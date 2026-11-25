from models import User
from email_service import EmailNotificationService


class SecurityEmailService:
    @classmethod
    def send_account_activation(cls, user: User, activation_url: str, ttl_minutes: int = 30) -> bool:
        subject = "Активація облікового запису — Система бронювання КНУ"
        body = (
            f"Вітаємо, {user.full_name}!\n\n"
            f"Дякуємо за реєстрацію в системі бронювання навчальних аудиторій КНУ.\n"
            f"Щоб активувати ваш обліковий запис, перейдіть за одноразовим посиланням:\n\n"
            f"{activation_url}\n\n"
            f"Увага: посилання дійсне протягом {ttl_minutes} хвилин і може бути використане лише один раз.\n"
            f"Якщо ви не реєструвалися в системі, просто проігноруйте цей лист."
        )
        return EmailNotificationService._send_email(user.email, subject, body)

    @classmethod
    def send_two_factor_code(cls, user: User, code: str, ttl_minutes: int = 10) -> bool:
        subject = f"Код підтвердження входу (2FA): {code} — Система бронювання КНУ"
        body = (
            f"Вітаємо, {user.full_name}!\n\n"
            f"Виконується вхід у ваш обліковий запис із увімкненою двофакторною автентифікацією (2FA).\n"
            f"Ваш одноразовий 6-значний код підтвердження:\n\n"
            f"    {code}\n\n"
            f"Код дійсний протягом {ttl_minutes} хвилин і може бути використаний лише один раз.\n"
            f"Якщо це були не ви, негайно змініть пароль облікового запису."
        )
        return EmailNotificationService._send_email(user.email, subject, body)

    @classmethod
    def send_password_reset(cls, user: User, reset_url: str, ttl_minutes: int = 15) -> bool:
        subject = "Відновлення пароля — Система бронювання КНУ"
        body = (
            f"Вітаємо, {user.full_name}!\n\n"
            f"Отримано запит на відновлення пароля для вашого облікового запису ({user.email}).\n"
            f"Щоб встановити новий пароль, перейдіть за одноразовим посиланням:\n\n"
            f"{reset_url}\n\n"
            f"Увага: посилання дійсне протягом {ttl_minutes} хвилин і може бути використане лише один раз.\n"
            f"Якщо ви не надсилали цей запит, просто проігноруйте лист — ваш поточний пароль залишиться без змін."
        )
        return EmailNotificationService._send_email(user.email, subject, body)
