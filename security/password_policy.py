import re
from validators import ApiError

COMMON_WEAK_PASSWORDS = {
    "password", "password1", "password1!", "password123", "password123!",
    "qwerty123", "qwerty123!", "qwertyui", "12345678", "123456789",
    "1234567890", "admin123", "admin123!", "admin@123", "p@ssw0rd",
    "passw0rd", "welcome1!", "letmein1!", "iloveyou1!", "abc12345!",
    "pnu12345!", "student1!", "teacher1!", "ukraine1!", "test1234!",
}


def evaluate_password(password: str, email: str = "") -> dict:
    pwd = password or ""
    rules = {
        "min_length": len(pwd) >= 8,
        "has_upper": any(ch.isupper() for ch in pwd),
        "has_lower": any(ch.islower() for ch in pwd),
        "has_digit": any(ch.isdigit() for ch in pwd),
        "has_special": any(not ch.isalnum() and not ch.isspace() for ch in pwd),
        "no_spaces": not any(ch.isspace() for ch in pwd),
    }

    normalized = pwd.strip().lower()
    is_common = normalized in COMMON_WEAK_PASSWORDS

    email_local = (email or "").split("@")[0].strip().lower()
    contains_email = len(email_local) >= 4 and email_local in normalized

    score = sum([
        rules["min_length"],
        rules["has_upper"],
        rules["has_lower"],
        rules["has_digit"],
        rules["has_special"],
    ])
    if len(pwd) >= 12 and score == 5:
        score += 1
    if is_common or contains_email:
        score = min(score, 1)

    if score <= 2:
        strength = "weak"
        label = "Слабкий"
    elif score <= 4:
        strength = "medium"
        label = "Середній"
    elif score == 5:
        strength = "strong"
        label = "Надійний"
    else:
        strength = "very_strong"
        label = "Дуже надійний"

    return {
        "rules": rules,
        "is_common": is_common,
        "contains_email": contains_email,
        "score": score,
        "strength": strength,
        "label": label,
    }


def validate_password_policy(password: str, email: str = "") -> None:
    if not isinstance(password, str) or not password:
        raise ApiError(400, "Поле пароля є обов'язковим.")

    result = evaluate_password(password, email=email)
    rules = result["rules"]
    errors = []

    if not rules["min_length"]:
        errors.append("щонайменше 8 символів")
    if not rules["has_upper"]:
        errors.append("хоча б одну велику літеру")
    if not rules["has_lower"]:
        errors.append("хоча б одну малу літеру")
    if not rules["has_digit"]:
        errors.append("хоча б одну цифру")
    if not rules["has_special"]:
        errors.append("хоча б один спеціальний символ (наприклад, !@#$%^&*)")
    if not rules["no_spaces"]:
        errors.append("відсутність пробілів")

    if errors:
        raise ApiError(
            400,
            "Пароль не відповідає політиці безпеки. Потрібно: " + ", ".join(errors) + "."
        )

    if result["is_common"]:
        raise ApiError(
            400,
            "Цей пароль занадто поширений і ненадійний. Оберіть іншу комбінацію."
        )

    if result["contains_email"]:
        raise ApiError(
            400,
            "Пароль не повинен містити частину вашої електронної пошти."
        )