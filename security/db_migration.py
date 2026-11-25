import os
import sys
import sqlite3

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

import repositories


USER_SECURITY_COLUMNS = [
    ("is_verified", "INTEGER NOT NULL DEFAULT 0"),
    ("is_blocked", "INTEGER NOT NULL DEFAULT 0"),
    ("failed_login_attempts", "INTEGER NOT NULL DEFAULT 0"),
    ("locked_until", "DATETIME DEFAULT NULL"),
    ("two_factor_enabled", "INTEGER NOT NULL DEFAULT 0"),
    ("oauth_provider", "VARCHAR(50) DEFAULT NULL"),
    ("oauth_sub", "VARCHAR(255) DEFAULT NULL"),
]


def run_migrations(db_path: str | None = None) -> None:
    target_db = db_path or repositories.DB_PATH
    conn = sqlite3.connect(target_db)
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        cur = conn.cursor()

        existing_columns = {
            row[1] for row in cur.execute("PRAGMA table_info(users)").fetchall()
        }

        added_is_verified = False
        for col_name, col_def in USER_SECURITY_COLUMNS:
            if col_name not in existing_columns:
                cur.execute(f"ALTER TABLE users ADD COLUMN {col_name} {col_def};")
                if col_name == "is_verified":
                    added_is_verified = True

        if added_is_verified:
            cur.execute("UPDATE users SET is_verified = 1;")

        cur.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_users_oauth
            ON users(oauth_provider, oauth_sub)
            WHERE oauth_provider IS NOT NULL AND oauth_sub IS NOT NULL;
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS security_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_hash VARCHAR(128) NOT NULL,
                token_type VARCHAR(30) NOT NULL CHECK (
                    token_type IN ('activation', 'password_reset', '2fa_email')
                ),
                expires_at DATETIME NOT NULL,
                used BOOLEAN NOT NULL DEFAULT 0,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
        """)

        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_security_tokens_hash
            ON security_tokens(token_hash);
        """)

        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_security_tokens_user_type
            ON security_tokens(user_id, token_type);
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS login_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER DEFAULT NULL,
                email VARCHAR(100) NOT NULL,
                ip_address VARCHAR(64) NOT NULL,
                user_agent VARCHAR(255) DEFAULT NULL,
                success BOOLEAN NOT NULL,
                reason VARCHAR(255) DEFAULT NULL,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            );
        """)

        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_login_logs_created_at
            ON login_logs(created_at DESC);
        """)

        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_login_logs_email
            ON login_logs(email);
        """)

        conn.commit()
        print(f"[MIGRATION OK] Схему безпеки застосовано до БД: {target_db}")
    finally:
        conn.close()


if __name__ == "__main__":
    run_migrations()