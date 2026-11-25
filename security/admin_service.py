from datetime import datetime, timezone
from validators import ApiError
from .repositories import SecurityUserRepository, LoginLogRepository


def _utc_now_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _is_temporarily_locked(locked_until: str | None) -> bool:
    if not locked_until:
        return False
    try:
        dt = datetime.strptime(locked_until, "%Y-%m-%d %H:%M:%S")
        return _utc_now_naive() < dt
    except ValueError:
        return False


class SecurityAdminService:
    @classmethod
    def list_users(cls) -> list[dict]:
        users = SecurityUserRepository.get_all_users()
        stats_map = {
            row["email"].lower(): row
            for row in LoginLogRepository.get_summary_by_email(limit=500)
        }

        result = []
        for user in users:
            data = user.to_dict()
            is_temp_locked = _is_temporarily_locked(user.locked_until)
            email_stats = stats_map.get(user.email.lower(), {})

            data["is_temporarily_locked"] = is_temp_locked
            data["total_login_attempts"] = email_stats.get("total_attempts", 0)
            data["failed_login_total"] = email_stats.get("failed_attempts", 0)
            data["last_login_attempt"] = email_stats.get("last_attempt")
            result.append(data)

        return result

    @classmethod
    def set_user_blocked(cls, target_user_id: int, is_blocked: int, current_admin) -> dict:
        if is_blocked not in (0, 1):
            raise ApiError(400, "Поле is_blocked приймає лише значення 0 або 1.")

        target_user = SecurityUserRepository.get_by_id(target_user_id)
        if not target_user:
            raise ApiError(404, f"Користувача з id={target_user_id} не знайдено.")

        if target_user.id == current_admin.id and is_blocked == 1:
            raise ApiError(400, "Адміністратор не може заблокувати власний обліковий запис.")

        SecurityUserRepository.set_blocked_status(target_user_id, is_blocked)
        updated = SecurityUserRepository.get_by_id(target_user_id)

        msg = (
            f"Обліковий запис {updated.email} заблоковано адміністратором."
            if is_blocked == 1
            else f"Обліковий запис {updated.email} розблоковано, лічильник невдалих спроб скинуто."
        )
        return {
            "status": 200,
            "message": msg,
            "user": updated.to_dict(),
        }

    @classmethod
    def get_login_logs(cls, limit: int = 100, email_filter: str = "") -> dict:
        safe_limit = max(1, min(int(limit or 100), 500))
        logs = LoginLogRepository.get_recent(limit=safe_limit, email_filter=email_filter)
        summary = LoginLogRepository.get_summary_by_email(limit=100, email_filter=email_filter)
        return {
            "status": 200,
            "logs": logs,
            "summary": summary,
        }
