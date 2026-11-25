import os
import sys
import requests
from dotenv import load_dotenv
from validators import ApiError

RECAPTCHA_VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify"


def get_recaptcha_site_key() -> str:
    load_dotenv(override=True)
    return os.getenv("RECAPTCHA_SITE_KEY", "").strip()


def get_recaptcha_secret_key() -> str:
    load_dotenv(override=True)
    return os.getenv("RECAPTCHA_SECRET_KEY", "").strip()


def verify_recaptcha(token: str, remote_ip: str | None = None) -> None:
    is_testing = "pytest" in sys.modules or os.getenv("FLASK_TESTING") == "1"
    if is_testing and os.getenv("ENFORCE_RECAPTCHA_IN_TESTS") != "1":
        return

    secret_key = get_recaptcha_secret_key()
    if not secret_key:
        raise ApiError(
            500,
            "Сервіс reCAPTCHA не налаштовано: відсутній RECAPTCHA_SECRET_KEY у файлі .env."
        )

    clean_token = str(token or "").strip()
    if not clean_token:
        raise ApiError(400, "Будь ласка, підтвердіть, що ви не робот (пройдіть reCAPTCHA).")

    payload = {
        "secret": secret_key,
        "response": clean_token,
    }
    if remote_ip:
        payload["remoteip"] = remote_ip

    try:
        response = requests.post(RECAPTCHA_VERIFY_URL, data=payload, timeout=5)
        response.raise_for_status()
        result = response.json()
    except requests.RequestException:
        raise ApiError(503, "Не вдалося зв'язатися із сервісом Google reCAPTCHA. Спробуйте пізніше.")

    if not result.get("success"):
        raise ApiError(
            400,
            "Перевірку reCAPTCHA не пройдено або термін її дії минув. Повторіть спробу."
        )
