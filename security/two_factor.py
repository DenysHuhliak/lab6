import os
import secrets
from datetime import datetime, timedelta, timezone
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from auth import SECRET_KEY
from validators import ApiError
from .repositories import SecurityTokenRepository
from .tokens import hash_token

TWO_FACTOR_TTL_MINUTES = int(os.getenv("TWO_FACTOR_TTL_MINUTES", "10"))
_CHALLENGE_SALT = "pnu-2fa-email-challenge"
_challenge_serializer = URLSafeTimedSerializer(SECRET_KEY, salt=_CHALLENGE_SALT)


def _utc_now_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def mask_email(email: str) -> str:
    if not email or "@" not in email:
        return "***"
    local, domain = email.split("@", 1)
    if len(local) <= 2:
        masked_local = local[0] + "*"
    else:
        masked_local = f"{local[:2]}{'*' * min(len(local) - 2, 5)}{local[-1]}"
    return f"{masked_local}@{domain}"


class TwoFactorService:
    @classmethod
    def _otp_hash(cls, user_id: int, code: str) -> str:
        return hash_token(f"2fa:{user_id}:{code.strip()}")

    @classmethod
    def create_email_otp(cls, user_id: int) -> tuple[str, str]:
        SecurityTokenRepository.invalidate_user_tokens(user_id, "2fa_email")

        code = f"{secrets.randbelow(1_000_000):06d}"
        token_hash = cls._otp_hash(user_id, code)
        expires_at = (_utc_now_naive() + timedelta(minutes=TWO_FACTOR_TTL_MINUTES)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        SecurityTokenRepository.create(
            user_id=user_id,
            token_hash=token_hash,
            token_type="2fa_email",
            expires_at=expires_at,
        )

        challenge_token = _challenge_serializer.dumps({"user_id": user_id, "purpose": "2fa_email"})
        return code, challenge_token

    @classmethod
    def parse_challenge_token(cls, challenge_token: str) -> int:
        clean = str(challenge_token or "").strip()
        if not clean:
            raise ApiError(400, "Сесію 2FA не знайдено. Виконайте вхід повторно.")

        try:
            payload = _challenge_serializer.loads(clean, max_age=TWO_FACTOR_TTL_MINUTES * 60)
            if payload.get("purpose") != "2fa_email" or not payload.get("user_id"):
                raise ApiError(400, "Недійсний токен підтвердження 2FA.")
            return int(payload["user_id"])
        except SignatureExpired:
            raise ApiError(401, "Термін дії сесії 2FA минув. Увійдіть заново.")
        except BadSignature:
            raise ApiError(401, "Недійсний токен сесії 2FA.")

    @classmethod
    def verify_and_consume_otp(cls, user_id: int, code: str) -> None:
        clean_code = str(code or "").strip().replace(" ", "")
        if not (len(clean_code) == 6 and clean_code.isdigit()):
            raise ApiError(400, "Код підтвердження повинен містити рівно 6 цифр.")

        record = SecurityTokenRepository.get_by_hash_and_type(
            cls._otp_hash(user_id, clean_code),
            "2fa_email",
        )
        if not record:
            raise ApiError(401, "Невірний 6-значний код підтвердження.")

        if record["used"]:
            raise ApiError(401, "Цей код підтвердження вже був використаний або замінений новим.")

        expires_at = datetime.strptime(record["expires_at"], "%Y-%m-%d %H:%M:%S")
        if _utc_now_naive() > expires_at:
            SecurityTokenRepository.mark_used(record["id"])
            raise ApiError(401, "Термін дії 6-значного коду минув. Надішліть новий код.")

        SecurityTokenRepository.mark_used(record["id"])
