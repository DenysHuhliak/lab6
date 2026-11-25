import os
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from validators import ApiError
from .repositories import SecurityTokenRepository

DEFAULT_ACTIVATION_TTL_MINUTES = int(os.getenv("ACTIVATION_TOKEN_TTL_MINUTES", "30"))
DEFAULT_RESET_TTL_MINUTES = int(os.getenv("PASSWORD_RESET_TTL_MINUTES", "15"))


def _utc_now_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def create_url_token(user_id: int, token_type: str, ttl_minutes: int = DEFAULT_ACTIVATION_TTL_MINUTES) -> str:
    SecurityTokenRepository.invalidate_user_tokens(user_id, token_type)

    raw_token = secrets.token_urlsafe(32)
    token_hash = hash_token(raw_token)
    expires_at = (_utc_now_naive() + timedelta(minutes=ttl_minutes)).strftime("%Y-%m-%d %H:%M:%S")

    SecurityTokenRepository.create(
        user_id=user_id,
        token_hash=token_hash,
        token_type=token_type,
        expires_at=expires_at,
    )
    return raw_token


def validate_url_token(raw_token: str, token_type: str) -> dict:
    clean_token = str(raw_token or "").strip()
    if not clean_token:
        raise ApiError(400, "Токен підтвердження відсутній або порожній.")

    record = SecurityTokenRepository.get_by_hash_and_type(hash_token(clean_token), token_type)
    if not record:
        raise ApiError(400, "Посилання недійсне або токен не знайдено.")

    if record["used"]:
        raise ApiError(400, "Це одноразове посилання вже було використане або замінене новим.")

    expires_at = datetime.strptime(record["expires_at"], "%Y-%m-%d %H:%M:%S")
    if _utc_now_naive() > expires_at:
        SecurityTokenRepository.mark_used(record["id"])
        raise ApiError(400, "Термін дії посилання минув. Запитайте новий лист.")

    return record


def verify_and_consume_url_token(raw_token: str, token_type: str) -> int:
    record = validate_url_token(raw_token, token_type)
    SecurityTokenRepository.mark_used(record["id"])
    return int(record["user_id"])
