from dataclasses import fields
from typing import Optional
from models import User
import repositories


class SecurityUserRepository:
    _USER_FIELDS = {f.name for f in fields(User)}

    @classmethod
    def _map_user(cls, row) -> Optional[User]:
        if not row:
            return None
        data = {k: v for k, v in dict(row).items() if k in cls._USER_FIELDS}
        return User(**data)

    @classmethod
    def get_all_users(cls) -> list[User]:
        conn = repositories.get_db_connection()
        try:
            rows = conn.execute("SELECT * FROM users ORDER BY id ASC").fetchall()
            return [cls._map_user(r) for r in rows]
        finally:
            conn.close()

    @classmethod
    def get_by_id(cls, user_id: int) -> Optional[User]:
        conn = repositories.get_db_connection()
        try:
            row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            return cls._map_user(row)
        finally:
            conn.close()

    @classmethod
    def get_by_email(cls, email: str) -> Optional[User]:
        conn = repositories.get_db_connection()
        try:
            row = conn.execute(
                "SELECT * FROM users WHERE LOWER(email) = LOWER(?)",
                (email.strip(),)
            ).fetchone()
            return cls._map_user(row)
        finally:
            conn.close()

    @classmethod
    def get_by_oauth(cls, oauth_provider: str, oauth_sub: str) -> Optional[User]:
        conn = repositories.get_db_connection()
        try:
            row = conn.execute(
                """
                SELECT * FROM users
                WHERE oauth_provider = ? AND oauth_sub = ?
                """,
                (oauth_provider, oauth_sub)
            ).fetchone()
            return cls._map_user(row)
        finally:
            conn.close()

    @classmethod
    def link_oauth_account(
        cls,
        user_id: int,
        oauth_provider: str,
        oauth_sub: str,
        mark_verified: bool = True,
    ) -> bool:
        conn = repositories.get_db_connection()
        try:
            if mark_verified:
                cur = conn.execute(
                    """
                    UPDATE users
                    SET oauth_provider = ?, oauth_sub = ?, is_verified = 1
                    WHERE id = ?
                    """,
                    (oauth_provider, oauth_sub, user_id)
                )
            else:
                cur = conn.execute(
                    """
                    UPDATE users
                    SET oauth_provider = ?, oauth_sub = ?
                    WHERE id = ?
                    """,
                    (oauth_provider, oauth_sub, user_id)
                )
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    @classmethod
    def create_user(
        cls,
        full_name: str,
        email: str,
        password_hash: str,
        role: str,
        is_verified: int = 0,
        oauth_provider: Optional[str] = None,
        oauth_sub: Optional[str] = None,
    ) -> User:
        conn = repositories.get_db_connection()
        try:
            cur = conn.execute(
                """
                INSERT INTO users (
                    full_name, email, password_hash, role,
                    is_verified, oauth_provider, oauth_sub
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (full_name, email.strip().lower(), password_hash, role, is_verified, oauth_provider, oauth_sub)
            )
            conn.commit()
            return cls.get_by_id(cur.lastrowid)
        finally:
            conn.close()

    @classmethod
    def mark_verified(cls, user_id: int) -> bool:
        conn = repositories.get_db_connection()
        try:
            cur = conn.execute("UPDATE users SET is_verified = 1 WHERE id = ?", (user_id,))
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    @classmethod
    def set_two_factor_enabled(cls, user_id: int, enabled: int) -> bool:
        conn = repositories.get_db_connection()
        try:
            cur = conn.execute(
                "UPDATE users SET two_factor_enabled = ? WHERE id = ?",
                (1 if enabled else 0, user_id)
            )
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    @classmethod
    def update_password(cls, user_id: int, password_hash: str) -> bool:
        conn = repositories.get_db_connection()
        try:
            cur = conn.execute(
                """
                UPDATE users
                SET password_hash = ?, failed_login_attempts = 0, locked_until = NULL
                WHERE id = ?
                """,
                (password_hash, user_id)
            )
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    @classmethod
    def record_failed_login(cls, user_id: int, attempts: int, locked_until: Optional[str] = None) -> None:
        conn = repositories.get_db_connection()
        try:
            conn.execute(
                """
                UPDATE users
                SET failed_login_attempts = ?, locked_until = ?
                WHERE id = ?
                """,
                (attempts, locked_until, user_id)
            )
            conn.commit()
        finally:
            conn.close()

    @classmethod
    def reset_login_failures(cls, user_id: int) -> None:
        conn = repositories.get_db_connection()
        try:
            conn.execute(
                """
                UPDATE users
                SET failed_login_attempts = 0, locked_until = NULL
                WHERE id = ?
                """,
                (user_id,)
            )
            conn.commit()
        finally:
            conn.close()

    @classmethod
    def set_blocked_status(cls, user_id: int, is_blocked: int) -> bool:
        conn = repositories.get_db_connection()
        try:
            if is_blocked == 0:
                cur = conn.execute(
                    """
                    UPDATE users
                    SET is_blocked = 0, failed_login_attempts = 0, locked_until = NULL
                    WHERE id = ?
                    """,
                    (user_id,)
                )
            else:
                cur = conn.execute(
                    "UPDATE users SET is_blocked = 1 WHERE id = ?",
                    (user_id,)
                )
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()


class SecurityTokenRepository:
    @classmethod
    def create(cls, user_id: int, token_hash: str, token_type: str, expires_at: str) -> int:
        conn = repositories.get_db_connection()
        try:
            cur = conn.execute(
                """
                INSERT INTO security_tokens (user_id, token_hash, token_type, expires_at, used)
                VALUES (?, ?, ?, ?, 0)
                """,
                (user_id, token_hash, token_type, expires_at)
            )
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()

    @classmethod
    def get_by_hash_and_type(cls, token_hash: str, token_type: str) -> Optional[dict]:
        conn = repositories.get_db_connection()
        try:
            row = conn.execute(
                """
                SELECT id, user_id, token_hash, token_type, expires_at, used, created_at
                FROM security_tokens
                WHERE token_hash = ? AND token_type = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (token_hash, token_type)
            ).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    @classmethod
    def mark_used(cls, token_id: int) -> bool:
        conn = repositories.get_db_connection()
        try:
            cur = conn.execute(
                "UPDATE security_tokens SET used = 1 WHERE id = ?",
                (token_id,)
            )
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    @classmethod
    def invalidate_user_tokens(cls, user_id: int, token_type: str) -> None:
        conn = repositories.get_db_connection()
        try:
            conn.execute(
                """
                UPDATE security_tokens
                SET used = 1
                WHERE user_id = ? AND token_type = ? AND used = 0
                """,
                (user_id, token_type)
            )
            conn.commit()
        finally:
            conn.close()


class LoginLogRepository:
    @classmethod
    def create(
        cls,
        email: str,
        ip_address: str,
        success: bool,
        reason: Optional[str] = None,
        user_id: Optional[int] = None,
        user_agent: Optional[str] = None,
    ) -> int:
        conn = repositories.get_db_connection()
        try:
            cur = conn.execute(
                """
                INSERT INTO login_logs (user_id, email, ip_address, user_agent, success, reason)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (user_id, email.strip().lower(), ip_address, user_agent, 1 if success else 0, reason)
            )
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()

    @classmethod
    def get_recent(cls, limit: int = 100, email_filter: str = "") -> list[dict]:
        conn = repositories.get_db_connection()
        try:
            clean_filter = (email_filter or "").strip().lower()
            if clean_filter:
                rows = conn.execute(
                    """
                    SELECT l.id, l.user_id, l.email, l.ip_address, l.user_agent,
                           l.success, l.reason, l.created_at,
                           u.full_name, u.role
                    FROM login_logs l
                    LEFT JOIN users u ON l.user_id = u.id
                    WHERE LOWER(l.email) LIKE ?
                    ORDER BY l.created_at DESC, l.id DESC
                    LIMIT ?
                    """,
                    (f"%{clean_filter}%", limit)
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT l.id, l.user_id, l.email, l.ip_address, l.user_agent,
                           l.success, l.reason, l.created_at,
                           u.full_name, u.role
                    FROM login_logs l
                    LEFT JOIN users u ON l.user_id = u.id
                    ORDER BY l.created_at DESC, l.id DESC
                    LIMIT ?
                    """,
                    (limit,)
                ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    @classmethod
    def get_summary_by_email(cls, limit: int = 100, email_filter: str = "") -> list[dict]:
        conn = repositories.get_db_connection()
        try:
            clean_filter = (email_filter or "").strip().lower()
            if clean_filter:
                rows = conn.execute(
                    """
                    SELECT LOWER(email) AS email,
                           COUNT(*) AS total_attempts,
                           SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) AS success_attempts,
                           SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) AS failed_attempts,
                           MAX(created_at) AS last_attempt
                    FROM login_logs
                    WHERE LOWER(email) LIKE ?
                    GROUP BY LOWER(email)
                    ORDER BY last_attempt DESC
                    LIMIT ?
                    """,
                    (f"%{clean_filter}%", limit)
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT LOWER(email) AS email,
                           COUNT(*) AS total_attempts,
                           SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) AS success_attempts,
                           SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) AS failed_attempts,
                           MAX(created_at) AS last_attempt
                    FROM login_logs
                    GROUP BY LOWER(email)
                    ORDER BY last_attempt DESC
                    LIMIT ?
                    """,
                    (limit,)
                ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()
