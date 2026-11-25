import os
import secrets
from urllib.parse import urlencode
import requests
from dotenv import load_dotenv
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from google.oauth2 import id_token as google_id_token
from google.auth.transport.requests import Request as GoogleAuthRequest

from auth import SECRET_KEY, generate_auth_token, hash_user_password
from validators import ApiError
from .repositories import SecurityUserRepository, LoginLogRepository
from .two_factor import TwoFactorService, TWO_FACTOR_TTL_MINUTES, mask_email
from .email_templates import SecurityEmailService

GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"
GOOGLE_FALLBACK_CONFIG = {
    "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
    "token_endpoint": "https://oauth2.googleapis.com/token",
}
OIDC_STATE_COOKIE_NAME = "pnu_oidc_state"
OIDC_STATE_MAX_AGE = 600

_oidc_state_serializer = URLSafeTimedSerializer(SECRET_KEY, salt="pnu-google-oidc-state")
_cached_discovery: dict | None = None


def _get_google_credentials() -> tuple[str, str]:
    load_dotenv(override=True)
    client_id = os.getenv("GOOGLE_CLIENT_ID", "").strip()
    client_secret = os.getenv("GOOGLE_CLIENT_SECRET", "").strip()
    return client_id, client_secret


def is_google_oidc_configured() -> bool:
    client_id, client_secret = _get_google_credentials()
    return bool(client_id and client_secret)


def _get_discovery_config() -> dict:
    global _cached_discovery
    if _cached_discovery:
        return _cached_discovery
    try:
        res = requests.get(GOOGLE_DISCOVERY_URL, timeout=5)
        res.raise_for_status()
        data = res.json()
        if data.get("authorization_endpoint") and data.get("token_endpoint"):
            _cached_discovery = data
            return _cached_discovery
    except requests.RequestException:
        pass
    return GOOGLE_FALLBACK_CONFIG


class GoogleOidcService:
    @classmethod
    def _build_redirect_uri(cls, base_url: str) -> str:
        load_dotenv(override=True)
        custom_uri = os.getenv("GOOGLE_REDIRECT_URI", "").strip()
        if custom_uri:
            return custom_uri
        return f"{base_url.rstrip('/')}/auth/google/callback"

    @classmethod
    def create_authorization_request(cls, base_url: str) -> tuple[str, str]:
        client_id, client_secret = _get_google_credentials()
        if not client_id or not client_secret:
            raise ApiError(
                500,
                "Google OpenID Connect не налаштовано: задайте GOOGLE_CLIENT_ID та GOOGLE_CLIENT_SECRET у файлі .env."
            )

        csrf_token = secrets.token_urlsafe(24)
        nonce = secrets.token_urlsafe(24)
        signed_state = _oidc_state_serializer.dumps({"csrf": csrf_token, "nonce": nonce})

        discovery = _get_discovery_config()
        params = {
            "client_id": client_id,
            "redirect_uri": cls._build_redirect_uri(base_url),
            "response_type": "code",
            "scope": "openid email profile",
            "state": signed_state,
            "nonce": nonce,
            "prompt": "select_account",
        }
        auth_url = f"{discovery['authorization_endpoint']}?{urlencode(params)}"
        return auth_url, csrf_token

    @classmethod
    def _verify_state(cls, state_param: str, cookie_csrf: str) -> str:
        if not state_param or not cookie_csrf:
            raise ApiError(400, "Помилка перевірки стану OIDC (відсутній state або cookie). Спробуйте увійти ще раз.")

        try:
            payload = _oidc_state_serializer.loads(state_param, max_age=OIDC_STATE_MAX_AGE)
        except SignatureExpired:
            raise ApiError(400, "Сесія входу через Google застаріла. Повторіть спробу.")
        except BadSignature:
            raise ApiError(400, "Недійсний параметр state (підозра на CSRF).")

        if not secrets.compare_digest(str(payload.get("csrf", "")), str(cookie_csrf)):
            raise ApiError(400, "Незбіг CSRF-токена OIDC. Повторіть вхід.")

        return str(payload.get("nonce", ""))

    @classmethod
    def _exchange_code_for_tokens(cls, code: str, base_url: str) -> dict:
        client_id, client_secret = _get_google_credentials()
        discovery = _get_discovery_config()

        try:
            response = requests.post(
                discovery["token_endpoint"],
                data={
                    "code": code,
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "redirect_uri": cls._build_redirect_uri(base_url),
                    "grant_type": "authorization_code",
                },
                timeout=10,
            )
            token_data = response.json()
        except requests.RequestException:
            raise ApiError(503, "Не вдалося зв'язатися із сервером токенів Google.")
        except ValueError:
            raise ApiError(502, "Некоректна відповідь від сервера токенів Google.")

        if response.status_code != 200 or "id_token" not in token_data:
            desc = token_data.get("error_description") or token_data.get("error") or "Помилка обміну коду авторизації."
            raise ApiError(400, f"Google OIDC відхилив запит: {desc}")

        return token_data

    @classmethod
    def _verify_id_token(cls, raw_id_token: str, expected_nonce: str) -> dict:
        client_id, _ = _get_google_credentials()
        try:
            idinfo = google_id_token.verify_oauth2_token(
                raw_id_token,
                GoogleAuthRequest(),
                client_id,
                clock_skew_in_seconds=10,
            )
        except Exception as exc:
            raise ApiError(401, f"Не вдалося перевірити підпис Google ID Token: {exc}")

        if idinfo.get("iss") not in ("accounts.google.com", "https://accounts.google.com"):
            raise ApiError(401, "Недійсний видавець (iss) ID Token.")

        if expected_nonce and not secrets.compare_digest(str(idinfo.get("nonce", "")), expected_nonce):
            raise ApiError(401, "Незбіг параметра nonce у Google ID Token.")

        email = str(idinfo.get("email", "")).strip().lower()
        if not email:
            raise ApiError(400, "Google не повернув електронну адресу користувача.")
        if not idinfo.get("email_verified", False):
            raise ApiError(403, "Електронна адреса вашого Google-акаунта не підтверджена.")

        return idinfo

    @classmethod
    def handle_callback(
        cls,
        code: str,
        state_param: str,
        cookie_csrf: str,
        base_url: str,
        remote_ip: str = "127.0.0.1",
        user_agent: str = "",
    ) -> dict:
        if not code:
            raise ApiError(400, "Google не повернув код авторизації.")

        expected_nonce = cls._verify_state(state_param, cookie_csrf)
        token_data = cls._exchange_code_for_tokens(code, base_url)
        idinfo = cls._verify_id_token(token_data["id_token"], expected_nonce)

        google_sub = str(idinfo["sub"])
        email = str(idinfo["email"]).strip().lower()
        full_name = str(idinfo.get("name") or email.split("@")[0]).strip()[:100]

        is_new_user = False
        user = SecurityUserRepository.get_by_oauth("google", google_sub)

        if not user:
            existing_by_email = SecurityUserRepository.get_by_email(email)
            if existing_by_email:
                SecurityUserRepository.link_oauth_account(
                    user_id=existing_by_email.id,
                    oauth_provider="google",
                    oauth_sub=google_sub,
                    mark_verified=True,
                )
                user = SecurityUserRepository.get_by_id(existing_by_email.id)
            else:
                random_password_hash = hash_user_password(secrets.token_urlsafe(32))
                user = SecurityUserRepository.create_user(
                    full_name=full_name,
                    email=email,
                    password_hash=random_password_hash,
                    role="student",
                    is_verified=1,
                    oauth_provider="google",
                    oauth_sub=google_sub,
                )
                is_new_user = True

        if user.is_blocked:
            LoginLogRepository.create(
                email=user.email,
                ip_address=remote_ip,
                success=False,
                reason="Вхід через Google відхилено: обліковий запис заблоковано адміністратором",
                user_id=user.id,
                user_agent=user_agent,
            )
            raise ApiError(403, "Ваш обліковий запис заблоковано адміністратором.")

        if user.failed_login_attempts or user.locked_until:
            SecurityUserRepository.reset_login_failures(user.id)
            user = SecurityUserRepository.get_by_id(user.id)

        if user.two_factor_enabled:
            otp_code, challenge_token = TwoFactorService.create_email_otp(user.id)
            email_sent = SecurityEmailService.send_two_factor_code(
                user=user,
                code=otp_code,
                ttl_minutes=TWO_FACTOR_TTL_MINUTES,
            )
            if not email_sent:
                raise ApiError(500, "Не вдалося надіслати 2FA-код після входу через Google.")

            masked = mask_email(user.email)
            return {
                "requires_2fa": True,
                "challenge_token": challenge_token,
                "message": f"Google-вхід підтверджено. На {masked} надіслано 6-значний код 2FA.",
            }

        reason = (
            "Автоматична реєстрація та вхід через Google (OpenID Connect)"
            if is_new_user
            else "Успішний вхід через Google (OpenID Connect)"
        )
        LoginLogRepository.create(
            email=user.email,
            ip_address=remote_ip,
            success=True,
            reason=reason,
            user_id=user.id,
            user_agent=user_agent,
        )

        msg = (
            f"Акаунт «{user.full_name}» створено та активовано через Google!"
            if is_new_user
            else f"Вітаємо, {user.full_name}! Ви увійшли через Google (OpenID Connect)."
        )
        return {
            "requires_2fa": False,
            "token": generate_auth_token(user),
            "user": user.to_dict(),
            "message": msg,
        }
