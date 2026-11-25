import os
import math
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
from validators import ApiError, validate_email_format
from auth import generate_auth_token, verify_user_password, hash_user_password
from .password_policy import validate_password_policy
from .captcha import verify_recaptcha
from .repositories import SecurityUserRepository, SecurityTokenRepository, LoginLogRepository
from .tokens import (
    DEFAULT_ACTIVATION_TTL_MINUTES,
    DEFAULT_RESET_TTL_MINUTES,
    create_url_token,
    validate_url_token,
    verify_and_consume_url_token,
)
from .two_factor import TwoFactorService, TWO_FACTOR_TTL_MINUTES, mask_email
from .email_templates import SecurityEmailService


def _utc_now_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _get_max_login_attempts() -> int:
    load_dotenv(override=False)
    return max(1, int(os.getenv("MAX_LOGIN_ATTEMPTS", "5")))


def _get_lockout_minutes() -> int:
    load_dotenv(override=False)
    return max(1, int(os.getenv("LOCKOUT_MINUTES", "15")))


class SecurityAuthService:
    @classmethod
    def _build_base_url(cls, base_url: str | None) -> str:
        env_base = os.getenv("APP_BASE_URL", "").strip().rstrip("/")
        if env_base:
            return env_base
        return (base_url or "http://127.0.0.1:5000").rstrip("/")

    @classmethod
    def _send_activation_email(cls, user, base_url: str | None) -> bool:
        raw_token = create_url_token(
            user_id=user.id,
            token_type="activation",
            ttl_minutes=DEFAULT_ACTIVATION_TTL_MINUTES,
        )
        activation_url = f"{cls._build_base_url(base_url)}/auth/activate?token={raw_token}"
        return SecurityEmailService.send_account_activation(
            user=user,
            activation_url=activation_url,
            ttl_minutes=DEFAULT_ACTIVATION_TTL_MINUTES,
        )

    @classmethod
    def register_user(cls, data: dict, remote_ip: str | None = None, base_url: str | None = None) -> dict:
        full_name = str(data.get("full_name", "")).strip()
        email = str(data.get("email", "")).strip().lower()
        password = str(data.get("password", ""))
        role = str(data.get("role", "student")).strip()
        captcha_token = str(data.get("captcha_token", "")).strip()

        validate_email_format(email)
        if not (3 <= len(full_name) <= 100):
            raise ApiError(400, "ПІБ користувача повинно містити від 3 до 100 символів.")

        validate_password_policy(password, email=email)

        if role not in ("student", "teacher"):
            raise ApiError(400, "При самостійній реєстрації доступні лише ролі «Студент» або «Викладач».")

        verify_recaptcha(captcha_token, remote_ip=remote_ip)

        if SecurityUserRepository.get_by_email(email):
            raise ApiError(409, "Користувач із такою корпоративною поштою вже зареєстрований.")

        password_hash = hash_user_password(password)
        new_user = SecurityUserRepository.create_user(
            full_name=full_name,
            email=email,
            password_hash=password_hash,
            role=role,
            is_verified=0,
        )

        email_sent = cls._send_activation_email(new_user, base_url=base_url)

        msg = (
            f"Користувача «{new_user.full_name}» зареєстровано! На {new_user.email} надіслано лист із посиланням для активації."
            if email_sent
            else f"Користувача «{new_user.full_name}» зареєстровано, але не вдалося надіслати лист активації. Спробуйте повторно в профілі."
        )

        return {
            "status": 201,
            "success": True,
            "activation_email_sent": email_sent,
            "message": msg,
            "token": generate_auth_token(new_user),
            "user": new_user.to_dict(),
        }

    @classmethod
    def activate_account(cls, raw_token: str) -> dict:
        user_id = verify_and_consume_url_token(raw_token, token_type="activation")
        user = SecurityUserRepository.get_by_id(user_id)
        if not user:
            raise ApiError(404, "Користувача для активації не знайдено.")

        if not user.is_verified:
            SecurityUserRepository.mark_verified(user.id)
            user = SecurityUserRepository.get_by_id(user.id)

        return {
            "status": 200,
            "message": f"Обліковий запис {user.email} успішно активовано!",
            "user": user.to_dict(),
        }

    @classmethod
    def resend_activation(cls, current_user, base_url: str | None = None) -> dict:
        fresh_user = SecurityUserRepository.get_by_id(current_user.id)
        if not fresh_user:
            raise ApiError(404, "Користувача не знайдено.")
        if fresh_user.is_verified:
            raise ApiError(400, "Ваш обліковий запис уже активовано.")

        email_sent = cls._send_activation_email(fresh_user, base_url=base_url)
        if not email_sent:
            raise ApiError(500, "Не вдалося надіслати лист активації. Перевірте SMTP-налаштування у .env.")

        return {
            "status": 200,
            "message": f"Новий лист із посиланням активації надіслано на {fresh_user.email} (дійсний {DEFAULT_ACTIVATION_TTL_MINUTES} хв).",
        }

    @classmethod
    def request_password_reset(cls, data: dict, base_url: str | None = None) -> dict:
        email = str(data.get("email", "")).strip().lower()
        if not email or "@" not in email:
            raise ApiError(400, "Введіть коректну електронну адресу.")

        generic_message = (
            f"Якщо обліковий запис з адресою {email} існує в системі, "
            f"ми надіслали лист із одноразовим посиланням для відновлення пароля (дійсне {DEFAULT_RESET_TTL_MINUTES} хв)."
        )

        user = SecurityUserRepository.get_by_email(email)
        if not user or user.is_blocked:
            return {"status": 200, "message": generic_message}

        raw_token = create_url_token(
            user_id=user.id,
            token_type="password_reset",
            ttl_minutes=DEFAULT_RESET_TTL_MINUTES,
        )
        reset_url = f"{cls._build_base_url(base_url)}/auth/reset-password?token={raw_token}"
        email_sent = SecurityEmailService.send_password_reset(
            user=user,
            reset_url=reset_url,
            ttl_minutes=DEFAULT_RESET_TTL_MINUTES,
        )
        if not email_sent:
            raise ApiError(500, "Не вдалося надіслати лист відновлення пароля. Перевірте SMTP-налаштування у .env.")

        return {"status": 200, "message": generic_message}

    @classmethod
    def validate_password_reset_token(cls, raw_token: str) -> dict:
        record = validate_url_token(raw_token, token_type="password_reset")
        user = SecurityUserRepository.get_by_id(int(record["user_id"]))
        if not user:
            raise ApiError(404, "Користувача для відновлення пароля не знайдено.")
        if user.is_blocked:
            raise ApiError(403, "Ваш обліковий запис заблоковано адміністратором.")

        return {
            "status": 200,
            "email_masked": mask_email(user.email),
            "full_name": user.full_name,
        }

    @classmethod
    def confirm_password_reset(cls, data: dict) -> dict:
        raw_token = str(data.get("token", "")).strip()
        new_password = str(data.get("new_password", ""))
        confirm_password = data.get("confirm_password")

        record = validate_url_token(raw_token, token_type="password_reset")
        user = SecurityUserRepository.get_by_id(int(record["user_id"]))
        if not user:
            raise ApiError(404, "Користувача не знайдено.")
        if user.is_blocked:
            raise ApiError(403, "Ваш обліковий запис заблоковано адміністратором.")

        if confirm_password is not None and new_password != str(confirm_password):
            raise ApiError(400, "Пароль і його підтвердження не співпадають.")

        validate_password_policy(new_password, email=user.email)

        verify_and_consume_url_token(raw_token, token_type="password_reset")
        SecurityTokenRepository.invalidate_user_tokens(user.id, "2fa_email")

        new_hash = hash_user_password(new_password)
        SecurityUserRepository.update_password(user.id, new_hash)

        return {
            "status": 200,
            "message": "Пароль успішно оновлено! Тепер ви можете увійти з новим паролем.",
        }

    @classmethod
    def login_user(cls, data: dict, remote_ip: str = "127.0.0.1", user_agent: str = "") -> dict:
        email = str(data.get("email", "")).strip().lower()
        password = str(data.get("password", ""))

        if not email or "@" not in email:
            raise ApiError(400, "Введіть коректну електронну адресу.")
        if not password:
            raise ApiError(400, "Поле пароля є обов'язковим.")

        user = SecurityUserRepository.get_by_email(email)
        if not user:
            LoginLogRepository.create(
                email=email,
                ip_address=remote_ip,
                success=False,
                reason="Неіснуючий обліковий запис",
                user_id=None,
                user_agent=user_agent,
            )
            raise ApiError(401, "Невірна електронна пошта або пароль.")

        if user.is_blocked:
            LoginLogRepository.create(
                email=email,
                ip_address=remote_ip,
                success=False,
                reason="Обліковий запис заблоковано адміністратором",
                user_id=user.id,
                user_agent=user_agent,
            )
            raise ApiError(403, "Ваш обліковий запис заблоковано адміністратором. Зверніться до підтримки.")

        now = _utc_now_naive()
        if user.locked_until:
            try:
                lock_dt = datetime.strptime(user.locked_until, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                lock_dt = None

            if lock_dt and now < lock_dt:
                remaining_min = max(1, math.ceil((lock_dt - now).total_seconds() / 60))
                LoginLogRepository.create(
                    email=email,
                    ip_address=remote_ip,
                    success=False,
                    reason="Спроба входу під час тимчасового блокування (Brute Force)",
                    user_id=user.id,
                    user_agent=user_agent,
                )
                raise ApiError(
                    429,
                    f"Акаунт тимчасово заблоковано через перевищення ліміту спроб входу. Спробуйте через {remaining_min} хв або зверніться до адміністратора."
                )
            else:
                SecurityUserRepository.reset_login_failures(user.id)
                user.failed_login_attempts = 0
                user.locked_until = None

        max_attempts = _get_max_login_attempts()
        lockout_minutes = _get_lockout_minutes()

        if not verify_user_password(user.password_hash, password):
            new_attempts = (user.failed_login_attempts or 0) + 1
            if new_attempts >= max_attempts:
                locked_until_str = (now + timedelta(minutes=lockout_minutes)).strftime("%Y-%m-%d %H:%M:%S")
                SecurityUserRepository.record_failed_login(user.id, new_attempts, locked_until_str)
                LoginLogRepository.create(
                    email=email,
                    ip_address=remote_ip,
                    success=False,
                    reason=f"Перевищено ліміт ({new_attempts}/{max_attempts}) — тимчасове блокування на {lockout_minutes} хв",
                    user_id=user.id,
                    user_agent=user_agent,
                )
                raise ApiError(
                    429,
                    f"Занадто багато невдалих спроб входу ({new_attempts}/{max_attempts}). Акаунт тимчасово заблоковано на {lockout_minutes} хв."
                )

            SecurityUserRepository.record_failed_login(user.id, new_attempts, None)
            remaining = max_attempts - new_attempts
            LoginLogRepository.create(
                email=email,
                ip_address=remote_ip,
                success=False,
                reason=f"Невірний пароль (спроба {new_attempts}/{max_attempts})",
                user_id=user.id,
                user_agent=user_agent,
            )
            raise ApiError(
                401,
                f"Невірна електронна пошта або пароль. Залишилося спроб до тимчасового блокування: {remaining}."
            )

        if user.failed_login_attempts or user.locked_until:
            SecurityUserRepository.reset_login_failures(user.id)
            user = SecurityUserRepository.get_by_id(user.id)

        if user.two_factor_enabled:
            code, challenge_token = TwoFactorService.create_email_otp(user.id)
            email_sent = SecurityEmailService.send_two_factor_code(
                user=user,
                code=code,
                ttl_minutes=TWO_FACTOR_TTL_MINUTES,
            )
            if not email_sent:
                raise ApiError(500, "Не вдалося надіслати 2FA-код на пошту. Перевірте SMTP-налаштування у .env.")

            masked = mask_email(user.email)
            return {
                "status": 200,
                "requires_2fa": True,
                "challenge_token": challenge_token,
                "email_masked": masked,
                "message": f"На адресу {masked} надіслано 6-значний код підтвердження (дійсний {TWO_FACTOR_TTL_MINUTES} хв).",
            }

        LoginLogRepository.create(
            email=email,
            ip_address=remote_ip,
            success=True,
            reason="Успішний вхід",
            user_id=user.id,
            user_agent=user_agent,
        )

        return {
            "status": 200,
            "requires_2fa": False,
            "message": "Автентифікація успішна.",
            "token": generate_auth_token(user),
            "user": user.to_dict(),
        }

    @classmethod
    def verify_two_factor_login(cls, data: dict, remote_ip: str = "127.0.0.1", user_agent: str = "") -> dict:
        challenge_token = str(data.get("challenge_token", "")).strip()
        code = str(data.get("code", "")).strip()

        user_id = TwoFactorService.parse_challenge_token(challenge_token)
        user = SecurityUserRepository.get_by_id(user_id)
        if not user:
            raise ApiError(404, "Користувача не знайдено.")

        if user.is_blocked:
            LoginLogRepository.create(
                email=user.email,
                ip_address=remote_ip,
                success=False,
                reason="2FA відхилено: обліковий запис заблоковано адміністратором",
                user_id=user.id,
                user_agent=user_agent,
            )
            raise ApiError(403, "Ваш обліковий запис заблоковано адміністратором.")

        try:
            TwoFactorService.verify_and_consume_otp(user.id, code)
        except ApiError as err:
            LoginLogRepository.create(
                email=user.email,
                ip_address=remote_ip,
                success=False,
                reason=f"Помилка 2FA: {err.message}",
                user_id=user.id,
                user_agent=user_agent,
            )
            raise

        LoginLogRepository.create(
            email=user.email,
            ip_address=remote_ip,
            success=True,
            reason="Успішний вхід (підтверджено 2FA через Email)",
            user_id=user.id,
            user_agent=user_agent,
        )

        return {
            "status": 200,
            "message": "Двофакторну автентифікацію пройдено успішно!",
            "token": generate_auth_token(user),
            "user": user.to_dict(),
        }

    @classmethod
    def resend_two_factor_code(cls, data: dict) -> dict:
        challenge_token = str(data.get("challenge_token", "")).strip()
        user_id = TwoFactorService.parse_challenge_token(challenge_token)
        user = SecurityUserRepository.get_by_id(user_id)
        if not user:
            raise ApiError(404, "Користувача не знайдено.")
        if user.is_blocked:
            raise ApiError(403, "Ваш обліковий запис заблоковано адміністратором.")
        if not user.two_factor_enabled:
            raise ApiError(400, "Для цього облікового запису 2FA вимкнено.")

        code, new_challenge = TwoFactorService.create_email_otp(user.id)
        email_sent = SecurityEmailService.send_two_factor_code(
            user=user,
            code=code,
            ttl_minutes=TWO_FACTOR_TTL_MINUTES,
        )
        if not email_sent:
            raise ApiError(500, "Не вдалося надіслати новий 2FA-код. Перевірте SMTP-налаштування.")

        masked = mask_email(user.email)
        return {
            "status": 200,
            "challenge_token": new_challenge,
            "email_masked": masked,
            "message": f"Новий 6-значний код надіслано на {masked}.",
        }

    @classmethod
    def toggle_two_factor(cls, current_user, enabled: bool) -> dict:
        fresh_user = SecurityUserRepository.get_by_id(current_user.id)
        if not fresh_user:
            raise ApiError(404, "Користувача не знайдено.")

        if enabled and not fresh_user.is_verified:
            raise ApiError(
                400,
                "Для увімкнення 2FA через електронну пошту спочатку активуйте обліковий запис."
            )

        SecurityUserRepository.set_two_factor_enabled(fresh_user.id, 1 if enabled else 0)
        updated = SecurityUserRepository.get_by_id(fresh_user.id)

        msg = (
            "Двофакторну автентифікацію (Email OTP) увімкнено. При наступному вході знадобиться 6-значний код із пошти."
            if enabled
            else "Двофакторну автентифікацію (2FA) вимкнено."
        )
        return {
            "status": 200,
            "message": msg,
            "user": updated.to_dict(),
        }

    @classmethod
    def get_profile(cls, current_user) -> dict:
        fresh_user = SecurityUserRepository.get_by_id(current_user.id) or current_user
        return {
            "status": 200,
            "user": fresh_user.to_dict(),
        }
