import os
import re
import sys
import json
import sqlite3
from urllib.parse import urlparse, parse_qs
import pytest

# Додаємо кореневу директорію проєкту до sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import repositories
from app import app
from validators import (
    ApiError,
    validate_email_format,
    validate_room_filters,
    validate_booking_payload,
)
from auth import hash_user_password, verify_user_password, generate_auth_token
from email_service import EmailNotificationService
from models import User
from repositories import UserRepository, RoomRepository, BookingRepository
from services import RoomService, BookingService
from security import run_migrations
from security.password_policy import validate_password_policy, evaluate_password
from security.repositories import SecurityUserRepository
import security.captcha as captcha_module
import security.auth_service as auth_service_module
import security.oidc_google as oidc_module


def print_api_result(title: str, response):
    """Допоміжна функція виведення результатів HTTP-запитів (видно при запуску з прапорцем -s)"""
    data = response.get_json()
    print(f"\n[ТЕСТ] {title}")
    print(f"HTTP Статус: {response.status_code}")
    print("Відповідь JSON:", json.dumps(data, ensure_ascii=False, indent=2))


def extract_token_from_last_email() -> str:
    """Витягує query-параметр token=... з останнього надісланого листа"""
    assert EmailNotificationService.sent_outbox, "Список надісланих листів порожній"
    body = EmailNotificationService.sent_outbox[-1]["body"]
    match = re.search(r"token=([A-Za-z0-9_\-]+)", body)
    assert match, f"Токен не знайдено в тілі листа: {body}"
    return match.group(1)


def extract_otp_from_last_email() -> str:
    """Витягує 6-значний OTP-код з останнього надісланого листа"""
    assert EmailNotificationService.sent_outbox, "Список надісланих листів порожній"
    body = EmailNotificationService.sent_outbox[-1]["body"]
    match = re.search(r"\b(\d{6})\b", body)
    assert match, f"6-значний код не знайдено в тілі листа: {body}"
    return match.group(1)


# =====================================================================
# ФІКСТУРИ PYTEST (ТЕСТОВА БАЗА ДАНИХ ТА КЛІЄНТ FLASK)
# =====================================================================

@pytest.fixture
def temp_test_db(tmp_path, monkeypatch):
    """Створює чисту тестову БД SQLite із початковими аудиторіями, користувачами та схемою безпеки"""
    db_file = tmp_path / "test_booking_system.db"
    monkeypatch.setattr(repositories, "DB_PATH", str(db_file))
    EmailNotificationService.sent_outbox.clear()

    conn = sqlite3.connect(str(db_file))
    conn.executescript("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL
        );
        CREATE TABLE floors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            floor_number INTEGER NOT NULL UNIQUE,
            svg_map_path TEXT
        );
        CREATE TABLE rooms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            floor_id INTEGER NOT NULL,
            room_number TEXT NOT NULL,
            capacity INTEGER NOT NULL,
            equipment_description TEXT,
            svg_polygon_id TEXT,
            is_active INTEGER DEFAULT 1,
            FOREIGN KEY (floor_id) REFERENCES floors(id)
        );
        CREATE TABLE bookings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            purpose TEXT NOT NULL,
            start_time TEXT NOT NULL,
            end_time TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT,
            reminder_sent INTEGER DEFAULT 0,
            FOREIGN KEY (room_id) REFERENCES rooms(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        INSERT INTO floors (id, floor_number, svg_map_path)
        VALUES (1, 3, 'static/maps/floor_3.svg');

        INSERT INTO rooms (id, floor_id, room_number, capacity, equipment_description, svg_polygon_id, is_active) VALUES
            (1, 1, '306', 30, 'Проєктор, ПК, Дошка', 'room-306', 1),
            (2, 1, '320', 25, 'Проєктор, Дошка', 'room-320', 1),
            (3, 1, '321', 20, 'ПК, Дошка', 'room-321', 1);

        INSERT INTO users (id, full_name, email, password_hash, role) VALUES
            (1, 'Адміністратор Системи', 'admin@pnu.edu.ua', 'hash_admin', 'admin'),
            (2, 'Петренко Іван Васильович', 'petrenko@pnu.edu.ua', 'hash_t1', 'teacher'),
            (3, 'Коваленко Олена Ігорівна', 'kovalenko@pnu.edu.ua', 'hash_t2', 'teacher'),
            (4, 'Студент ІПЗ-41', 'student@pnu.edu.ua', 'hash_st', 'student');
    """)
    conn.commit()
    conn.close()

    # Застосовуємо міграції модуля безпеки (додає колонки безпеки, security_tokens та login_logs)
    run_migrations(str(db_file))
    return db_file


@pytest.fixture
def client(temp_test_db):
    """Тестовий клієнт Flask, підключений до ізольованої тестової БД"""
    app.config["TESTING"] = True
    with app.test_client() as test_client:
        yield test_client


def get_auth_headers(user_id: int) -> dict:
    """Формує заголовки авторизації (Bearer-токен + X-User-Id) для заданого користувача"""
    user = UserRepository.get_by_id(user_id)
    token = generate_auth_token(user)
    return {
        "Authorization": f"Bearer {token}",
        "X-User-Id": str(user_id),
    }


# =====================================================================
# ЧАСТИНА 1. МОДУЛЬНЕ ТЕСТУВАННЯ (10 UNIT-ТЕСТІВ)
# =====================================================================

def test_unit_01_valid_corporate_emails():
    """Unit-тест 1: Перевірка коректних корпоративних пошт @pnu.edu.ua та @cnu.edu.ua"""
    assert validate_email_format("denys.huhliak@pnu.edu.ua") is None
    assert validate_email_format("teacher.ipz@cnu.edu.ua") is None


def test_unit_02_invalid_email_domain():
    """Unit-тест 2: Відхилення пошти зі стороннім доменом (@gmail.com)"""
    with pytest.raises(ApiError) as exc_info:
        validate_email_format("student@gmail.com")
    assert exc_info.value.status == 400


def test_unit_03_empty_email():
    """Unit-тест 3: Відхилення порожнього рядка електронної пошти"""
    with pytest.raises(ApiError) as exc_info:
        validate_email_format("")
    assert exc_info.value.status == 400


def test_unit_04_valid_room_capacity_boundaries():
    """Unit-тест 4: Граничні допустимі значення фільтра місткості (0 та 500 місць)"""
    assert validate_room_filters(0) is None
    assert validate_room_filters(500) is None


def test_unit_05_invalid_room_capacity_out_of_range():
    """Unit-тест 5: Відхилення від'ємної місткості та значення понад 500 місць"""
    with pytest.raises(ApiError) as exc_neg:
        validate_room_filters(-5)
    assert exc_neg.value.status == 400

    with pytest.raises(ApiError) as exc_over:
        validate_room_filters(501)
    assert exc_over.value.status == 400


def test_unit_06_valid_booking_payload():
    """Unit-тест 6: Валідація коректного словника даних для бронювання"""
    payload = {
        "room_id": 1,
        "user_id": 2,
        "purpose": "ІПЗ-41, Тестування ПЗ (лабораторна)",
        "start_time": "2026-11-10 09:00:00",
        "end_time": "2026-11-10 10:20:00",
    }
    assert validate_booking_payload(payload) is None


def test_unit_07_booking_payload_short_purpose():
    """Unit-тест 7: Відхилення бронювання із занадто коротким призначенням (< 5 символів)"""
    payload = {
        "room_id": 1,
        "user_id": 2,
        "purpose": "ІПЗ",
        "start_time": "2026-11-10 09:00:00",
        "end_time": "2026-11-10 10:20:00",
    }
    with pytest.raises(ApiError) as exc_info:
        validate_booking_payload(payload)
    assert exc_info.value.status == 400


def test_unit_08_booking_payload_invalid_time_order():
    """Unit-тест 8: Відхилення бронювання, де час завершення не пізніший за час початку"""
    payload = {
        "room_id": 1,
        "user_id": 2,
        "purpose": "ІПЗ-41, Лекція з програмування",
        "start_time": "2026-11-10 12:00:00",
        "end_time": "2026-11-10 10:00:00",
    }
    with pytest.raises(ApiError) as exc_info:
        validate_booking_payload(payload)
    assert exc_info.value.status == 400


def test_unit_09_password_hashing_and_verification():
    """Unit-тест 9: Перевірка PBKDF2-хешування та верифікації пароля"""
    raw_password = "SecurePassword2026"
    hashed = hash_user_password(raw_password)
    assert hashed.startswith("pbkdf2:sha256")
    assert verify_user_password(hashed, raw_password) is True
    assert verify_user_password(hashed, "WrongPassword") is False


def test_unit_10_generate_auth_token():
    """Unit-тест 10: Генерація підписаного токена сесії для моделі користувача"""
    dummy_user = User(id=5, full_name="Тестовий Викладач", email="test@pnu.edu.ua", role="teacher")
    token = generate_auth_token(dummy_user)
    assert isinstance(token, str) and len(token) > 20


# =====================================================================
# ЧАСТИНА 2. ІНТЕГРАЦІЙНЕ ТЕСТУВАННЯ БАЗИ ДАНИХ SQLite (IT-001 .. IT-003)
# =====================================================================

def test_it_001_add_and_retrieve_user_from_db(temp_test_db):
    """IT-001: Додавання нового викладача до бази даних та отримання за email"""
    created_user = UserRepository.create(
        full_name="Іван Франко",
        email="ivan.franko@pnu.edu.ua",
        password_hash=hash_user_password("TeacherPass123"),
        role="teacher",
    )
    fetched_user = UserRepository.get_by_email("ivan.franko@pnu.edu.ua")

    assert fetched_user is not None
    assert fetched_user.id == created_user.id
    assert fetched_user.full_name == "Іван Франко"
    assert fetched_user.role == "teacher"


def test_it_002_room_maintenance_status_db_integration(temp_test_db):
    """IT-002: Закриття та відкриття аудиторії на тех. обслуговування в БД"""
    updated = RoomService.set_room_active_state(room_id=1, is_active=0)
    assert updated["is_active"] == 0
    assert RoomRepository.get_by_id(1).is_active == 0

    RoomService.set_room_active_state(room_id=1, is_active=1)
    assert RoomRepository.get_by_id(1).is_active == 1


def test_it_003_booking_queue_and_auto_promotion_db_integration(temp_test_db):
    """IT-003: Створення бронювання, черги очікування та автопросування в БД"""
    t1 = UserRepository.get_by_id(2)
    t2 = UserRepository.get_by_id(3)

    slot_payload = {
        "room_id": 1,
        "purpose": "ІПЗ-41, Лабораторна робота №11",
        "start_time": "2026-11-12 09:00:00",
        "end_time": "2026-11-12 10:20:00",
    }

    res1 = BookingService.create_booking_or_queue({**slot_payload, "user_id": t1.id}, t1)
    status1 = res1.get("booking_status") or res1.get("status")
    b1_id = res1.get("booking_id") or (res1.get("booking") or {}).get("id")
    assert status1 == "confirmed"

    res2 = BookingService.create_booking_or_queue({**slot_payload, "user_id": t2.id}, t2)
    status2 = res2.get("booking_status") or res2.get("status")
    b2_id = res2.get("booking_id") or (res2.get("booking") or {}).get("id")
    assert status2 == "queued"

    BookingService.cancel_booking(b1_id, t1)
    promoted_booking = BookingRepository.get_by_id(b2_id)
    assert promoted_booking.status == "confirmed"


# =====================================================================
# ЧАСТИНА 3. ТЕСТУВАННЯ REST API (ПЕРЕВЕДЕНІ ТЕСТИ З BookingApiTestCase)
# =====================================================================

def test_api_01_get_rooms_success(client):
    """API-тест 1: Отримання списку аудиторій 3-го поверху"""
    res = client.get("/api/rooms?date=2026-10-28&slot=10:35-11:55")
    print_api_result("Отримання списку аудиторій 3-го поверху", res)

    assert res.status_code == 200
    assert len(res.get_json()) >= 3


def test_api_02_get_nonexistent_room(client):
    """API-тест 2: Запит неіснуючої аудиторії ID=999"""
    res = client.get("/api/rooms/999")
    print_api_result("2. Запит неіснуючої аудиторії ID=999", res)

    assert res.status_code == 404


def test_api_03_validation_short_purpose(client):
    """API-тест 3: Перевірка валідації — занадто коротке призначення"""
    payload = {
        "room_id": 1,
        "user_id": 2,
        "purpose": "ІПЗ",
        "start_time": "2026-11-20 10:35:00",
        "end_time": "2026-11-20 11:55:00",
    }
    res = client.post(
        "/api/bookings",
        json=payload,
        headers=get_auth_headers(2),
    )
    print_api_result("Перевірка валідації: занадто коротке призначення", res)

    assert res.status_code == 400


def test_api_04_rbac_student_forbidden(client):
    """API-тест 4: Перевірка авторизації RBAC — спроба бронювання студентом"""
    payload = {
        "room_id": 1,
        "user_id": 4,
        "purpose": "Самостійна робота студентів ІПЗ-41",
        "start_time": "2026-11-20 10:35:00",
        "end_time": "2026-11-20 11:55:00",
    }
    res = client.post(
        "/api/bookings",
        json=payload,
        headers=get_auth_headers(4),
    )
    print_api_result("Перевірка авторизації RBAC: спроба бронювання студентом", res)

    assert res.status_code == 403


def test_api_05_full_booking_and_queue_lifecycle(client):
    """API-тест 5: Повний життєвий цикл бронювання, черги, оновлення та автопросування"""
    # 1. Створення підтвердженого бронювання викладачем №1 (user_id=2)
    payload_teacher_1 = {
        "room_id": 1,
        "user_id": 2,
        "purpose": "Лекція з ІПЗ-41",
        "start_time": "2026-11-20 10:35:00",
        "end_time": "2026-11-20 11:55:00",
    }
    res_create = client.post(
        "/api/bookings",
        json=payload_teacher_1,
        headers=get_auth_headers(2),
    )
    print_api_result("Створення підтвердженого бронювання викладачем №1", res_create)
    assert res_create.status_code == 201

    create_data = res_create.get_json()
    booking_1_id = create_data.get("booking_id") or (create_data.get("booking") or {}).get("id")
    booking_1_status = create_data.get("booking_status") or create_data.get("status")
    assert booking_1_status == "confirmed"

    # 2. Блокування повторного запису в чергу тим самим викладачем
    res_duplicate = client.post(
        "/api/bookings",
        json=payload_teacher_1,
        headers=get_auth_headers(2),
    )
    print_api_result("Блокування повторного запису в чергу тим самим викладачем", res_duplicate)
    assert res_duplicate.status_code == 409

    # 3. Постановка другого викладача (user_id=3) в чергу очікування
    payload_teacher_2 = {
        "room_id": 1,
        "user_id": 3,
        "purpose": "Консультація з курсового проєктування",
        "start_time": "2026-11-20 10:35:00",
        "end_time": "2026-11-20 11:55:00",
    }
    res_queue = client.post(
        "/api/bookings",
        json=payload_teacher_2,
        headers=get_auth_headers(3),
    )
    print_api_result("Постановка другого викладача в чергу очікування", res_queue)
    assert res_queue.status_code == 201

    queue_data = res_queue.get_json()
    booking_2_id = queue_data.get("booking_id") or (queue_data.get("booking") or {}).get("id")
    booking_2_status = queue_data.get("booking_status") or queue_data.get("status")
    assert booking_2_status == "queued"

    # 4. Часткове оновлення призначення бронювання (PATCH)
    res_patch = client.patch(
        f"/api/bookings/{booking_1_id}",
        json={"purpose": "Лекція з ІПЗ-41 (оновлено)"},
        headers=get_auth_headers(2),
    )
    print_api_result("Часткове оновлення бронювання", res_patch)
    assert res_patch.status_code == 200

    # 5. Скасування основного бронювання та автоматичне просування черги (DELETE)
    res_delete = client.delete(
        f"/api/bookings/{booking_1_id}",
        headers=get_auth_headers(2),
    )
    print_api_result("Скасування бронювання та автопросування черги", res_delete)
    assert res_delete.status_code == 200

    delete_data = res_delete.get_json()
    if "promoted_booking_id" in delete_data:
        assert delete_data["promoted_booking_id"] == booking_2_id
    assert BookingRepository.get_by_id(booking_2_id).status == "confirmed"


# =====================================================================
# ЧАСТИНА 4. ТЕСТУВАННЯ БЕЗПЕЧНОЇ СИСТЕМИ ОБЛІКОВИХ ЗАПИСІВ (ЗАВДАННЯ 1–7)
# =====================================================================

def test_sec_01_password_policy_rules_and_strength():
    """Завдання 1: Перевірка політики складності, слабких паролів та оцінки сили"""
    invalid_passwords = [
        "Ab1!",               # коротший за 8 символів
        "alllower1!",         # немає великої літери
        "ALLUPPER1!",         # немає малої літери
        "NoDigitsHere!",      # немає цифри
        "NoSpecial123",       # немає спецсимволу
        "Password123!",       # поширений слабкий пароль
        "MyDenys#2026",       # містить частину email
    ]
    for pwd in invalid_passwords:
        with pytest.raises(ApiError) as exc:
            validate_password_policy(pwd, email="denys@pnu.edu.ua")
        assert exc.value.status == 400

    assert validate_password_policy("KnuSecure#2026", email="denys@pnu.edu.ua") is None
    evaluation = evaluate_password("KnuSecure#2026", email="denys@pnu.edu.ua")
    assert evaluation["strength"] == "very_strong"


def test_sec_02_register_weak_password_and_profile_access(client):
    """Завдання 1: Реєстрація відхиляє слабкий пароль, успішна реєстрація дає доступ до профілю та виходу"""
    res_weak = client.post("/api/auth/register", json={
        "full_name": "Тестовий Студент",
        "email": "new.student@pnu.edu.ua",
        "password": "weakpassword",
        "role": "student",
    })
    assert res_weak.status_code == 400

    res_ok = client.post("/api/auth/register", json={
        "full_name": "Тестовий Студент",
        "email": "new.student@pnu.edu.ua",
        "password": "KnuSecure#2026",
        "role": "student",
    })
    assert res_ok.status_code == 201
    data = res_ok.get_json()
    assert data["token"]
    assert data["user"]["is_verified"] == 0

    # Доступ до профілю за токеном
    res_me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {data['token']}"})
    assert res_me.status_code == 200
    assert res_me.get_json()["user"]["email"] == "new.student@pnu.edu.ua"

    # Вихід із системи
    res_logout = client.post("/api/auth/logout")
    assert res_logout.status_code == 200


def test_sec_03_recaptcha_verification_enforced(client, monkeypatch):
    """Завдання 2: Перевірка Google reCAPTCHA при реєстрації (відсутній, невалідний та валідний токен)"""
    monkeypatch.setenv("ENFORCE_RECAPTCHA_IN_TESTS", "1")
    monkeypatch.setattr(captcha_module, "get_recaptcha_secret_key", lambda: "test-secret-key")

    base_payload = {
        "full_name": "Перевірка Капчі",
        "email": "captcha.user@pnu.edu.ua",
        "password": "KnuSecure#2026",
        "role": "student",
    }

    # 1. Без токена reCAPTCHA
    res_missing = client.post("/api/auth/register", json=base_payload)
    assert res_missing.status_code == 400

    # 2. Невалідний токен (Google повертає success=False)
    class FakeResponse:
        def __init__(self, payload):
            self._payload = payload

        def raise_for_status(self):
            return None

        def json(self):
            return self._payload

    monkeypatch.setattr(captcha_module.requests, "post", lambda *a, **kw: FakeResponse({"success": False}))
    res_invalid = client.post("/api/auth/register", json={**base_payload, "captcha_token": "bad-token"})
    assert res_invalid.status_code == 400

    # 3. Валідний токен (Google повертає success=True)
    monkeypatch.setattr(captcha_module.requests, "post", lambda *a, **kw: FakeResponse({"success": True}))
    res_valid = client.post("/api/auth/register", json={**base_payload, "captcha_token": "good-token"})
    assert res_valid.status_code == 201


def test_sec_04_account_activation_one_time_and_expiry(client, temp_test_db):
    """Завдання 3: Активація акаунта за одноразовим токеном із листа та перевірка простроченого токена"""
    res_reg = client.post("/api/auth/register", json={
        "full_name": "Активація Тест",
        "email": "activate.me@pnu.edu.ua",
        "password": "KnuSecure#2026",
        "role": "student",
    })
    assert res_reg.status_code == 201
    token = extract_token_from_last_email()

    # Успішна активація за посиланням
    res_act = client.get(f"/auth/activate?token={token}")
    assert res_act.status_code == 302
    assert "activation=success" in res_act.headers["Location"]

    user = SecurityUserRepository.get_by_email("activate.me@pnu.edu.ua")
    assert user.is_verified == 1

    # Повторне використання того самого одноразового токена відхиляється
    res_reuse = client.post("/api/auth/activate", json={"token": token})
    assert res_reuse.status_code == 400

    # Перевірка простроченого токена на новому користувачі
    res_reg2 = client.post("/api/auth/register", json={
        "full_name": "Прострочений Токен",
        "email": "expired.act@pnu.edu.ua",
        "password": "KnuSecure#2026",
        "role": "student",
    })
    assert res_reg2.status_code == 201
    expired_token = extract_token_from_last_email()

    conn = sqlite3.connect(str(temp_test_db))
    conn.execute("UPDATE security_tokens SET expires_at = '2020-01-01 00:00:00' WHERE token_type = 'activation'")
    conn.commit()
    conn.close()

    res_expired = client.post("/api/auth/activate", json={"token": expired_token})
    assert res_expired.status_code == 400


def test_sec_05_brute_force_lockout_and_admin_panel(client, monkeypatch):
    """Завдання 4: Захист від Brute Force, журнал входів, RBAC адмінки та блокування/розблокування"""
    monkeypatch.setattr(auth_service_module, "_get_max_login_attempts", lambda: 3)
    monkeypatch.setattr(auth_service_module, "_get_lockout_minutes", lambda: 15)

    # 1. Три невдалі спроби входу -> тимчасове блокування (429)
    for attempt in range(2):
        res_fail = client.post("/api/auth/login", json={
            "email": "student@pnu.edu.ua",
            "password": f"WrongPass#{attempt}",
        })
        assert res_fail.status_code == 401

    res_lock = client.post("/api/auth/login", json={
        "email": "student@pnu.edu.ua",
        "password": "WrongPass#3",
    })
    assert res_lock.status_code == 429

    # 2. Навіть із правильним паролем під час блокування вхід заборонено
    res_still_locked = client.post("/api/auth/login", json={
        "email": "student@pnu.edu.ua",
        "password": "hash_st",
    })
    assert res_still_locked.status_code == 429

    # 3. Студент не має доступу до адмін-панелі (RBAC -> 403)
    res_forbidden = client.get("/api/admin/users", headers=get_auth_headers(4))
    assert res_forbidden.status_code == 403

    # 4. Адміністратор бачить користувачів і журнал усіх невдалих спроб
    admin_headers = get_auth_headers(1)
    res_logs = client.get("/api/admin/login-logs?email=student@pnu.edu.ua", headers=admin_headers)
    assert res_logs.status_code == 200
    logs_data = res_logs.get_json()
    assert len(logs_data["logs"]) >= 4
    assert logs_data["summary"][0]["failed_attempts"] >= 4

    # 5. Адміністратор блокує обліковий запис вручну -> доступ заблоковано (403)
    res_block = client.patch("/api/admin/users/4/block", json={"is_blocked": 1}, headers=admin_headers)
    assert res_block.status_code == 200

    res_blocked_login = client.post("/api/auth/login", json={
        "email": "student@pnu.edu.ua",
        "password": "hash_st",
    })
    assert res_blocked_login.status_code == 403

    res_blocked_me = client.get("/api/auth/me", headers=get_auth_headers(4))
    assert res_blocked_me.status_code == 403

    # 6. Адміністратор розблоковує користувача (скидає і Brute Force) -> успішний вхід
    res_unblock = client.patch("/api/admin/users/4/block", json={"is_blocked": 0}, headers=admin_headers)
    assert res_unblock.status_code == 200

    res_login_ok = client.post("/api/auth/login", json={
        "email": "student@pnu.edu.ua",
        "password": "hash_st",
    })
    assert res_login_ok.status_code == 200
    assert res_login_ok.get_json()["token"]


def test_sec_06_two_factor_email_otp_full_flow(client):
    """Завдання 5: Увімкнення 2FA у профілі, вхід із 6-значним кодом на email та вимкнення 2FA"""
    student_headers = get_auth_headers(4)

    # 1. Увімкнення 2FA у профілі
    res_on = client.post("/api/auth/2fa/toggle", json={"enabled": True}, headers=student_headers)
    assert res_on.status_code == 200
    assert res_on.get_json()["user"]["two_factor_enabled"] == 1

    # 2. Вхід повертає requires_2fa=True та надсилає 6-значний код
    res_step1 = client.post("/api/auth/login", json={
        "email": "student@pnu.edu.ua",
        "password": "hash_st",
    })
    assert res_step1.status_code == 200
    step1_data = res_step1.get_json()
    assert step1_data["requires_2fa"] is True
    assert "token" not in step1_data
    challenge_token = step1_data["challenge_token"]
    otp_code = extract_otp_from_last_email()

    # 3. Невірний код відхиляється (401)
    wrong_code = "000000" if otp_code != "000000" else "111111"
    res_wrong = client.post("/api/auth/2fa/verify", json={
        "challenge_token": challenge_token,
        "code": wrong_code,
    })
    assert res_wrong.status_code == 401

    # 4. Правильний 6-значний код завершує вхід і видає Bearer-токен
    res_step2 = client.post("/api/auth/2fa/verify", json={
        "challenge_token": challenge_token,
        "code": otp_code,
    })
    assert res_step2.status_code == 200
    assert res_step2.get_json()["token"]

    # 5. Повторне використання того самого коду неможливе
    res_replay = client.post("/api/auth/2fa/verify", json={
        "challenge_token": challenge_token,
        "code": otp_code,
    })
    assert res_replay.status_code == 401

    # 6. Вимкнення 2FA повертає звичайний вхід
    res_off = client.post("/api/auth/2fa/toggle", json={"enabled": False}, headers=student_headers)
    assert res_off.status_code == 200
    assert res_off.get_json()["user"]["two_factor_enabled"] == 0


def test_sec_07_google_oidc_login_and_csrf_protection(client, monkeypatch):
    """Завдання 6: Вхід/реєстрація через Google OpenID Connect (JWT id_token + перевірка state/nonce)"""
    monkeypatch.setattr(oidc_module, "_get_google_credentials", lambda: ("fake-google-id", "fake-google-secret"))
    monkeypatch.setattr(oidc_module, "_get_discovery_config", lambda: oidc_module.GOOGLE_FALLBACK_CONFIG)

    # 1. Старт авторизації -> редирект на Google зі state та nonce + встановлення HttpOnly cookie
    res_start = client.get("/auth/google/login")
    assert res_start.status_code == 302
    parsed_redirect = urlparse(res_start.headers["Location"])
    qs = parse_qs(parsed_redirect.query)
    state_val = qs["state"][0]
    nonce_val = qs["nonce"][0]

    # 2. Мокаємо обмін code -> id_token та криптографічну перевірку JWT
    class FakeTokenResponse:
        status_code = 200

        def json(self):
            return {"id_token": "fake.signed.jwt"}

    monkeypatch.setattr(oidc_module.requests, "post", lambda *a, **kw: FakeTokenResponse())
    monkeypatch.setattr(
        oidc_module.google_id_token,
        "verify_oauth2_token",
        lambda raw_token, req, aud, **kw: {
            "iss": "https://accounts.google.com",
            "aud": aud,
            "sub": "google-sub-999001",
            "email": "oidc.student@gmail.com",
            "email_verified": True,
            "name": "Олександр Гугл",
            "nonce": nonce_val,
        },
    )

    # 3. Успішний callback створює та активує користувача
    res_cb = client.get(f"/auth/google/callback?code=valid-auth-code&state={state_val}")
    assert res_cb.status_code == 302
    assert "#oidc_status=success" in res_cb.headers["Location"]

    created = SecurityUserRepository.get_by_email("oidc.student@gmail.com")
    assert created is not None
    assert created.oauth_provider == "google"
    assert created.oauth_sub == "google-sub-999001"
    assert created.is_verified == 1

    # 4. Захист від CSRF: підроблений state відхиляється
    res_csrf = client.get("/auth/google/callback?code=valid-auth-code&state=tampered-state")
    assert res_csrf.status_code == 302
    assert "#oidc_status=error" in res_csrf.headers["Location"]


def test_sec_08_password_reset_flow_and_token_limits(client, temp_test_db):
    """Завдання 7: Відновлення пароля через email, валідація нового пароля, одноразовість та термін дії токена"""
    # 1. Запит відновлення пароля
    res_req = client.post("/api/auth/password-reset/request", json={"email": "student@pnu.edu.ua"})
    assert res_req.status_code == 200
    reset_token = extract_token_from_last_email()

    # 2. Перехід за посиланням із листа -> валідний редирект на форму встановлення пароля
    res_page = client.get(f"/auth/reset-password?token={reset_token}")
    assert res_page.status_code == 302
    assert "#reset_status=valid" in res_page.headers["Location"]

    # 3. Слабкий новий пароль відхиляється, але токен залишається чинним
    res_weak = client.post("/api/auth/password-reset/confirm", json={
        "token": reset_token,
        "new_password": "123",
        "confirm_password": "123",
    })
    assert res_weak.status_code == 400

    # 4. Валідний новий пароль зберігається та погашає токен
    res_confirm = client.post("/api/auth/password-reset/confirm", json={
        "token": reset_token,
        "new_password": "NewStrong#2026",
        "confirm_password": "NewStrong#2026",
    })
    assert res_confirm.status_code == 200

    # 5. Повторне використання токена заборонено
    res_reuse = client.post("/api/auth/password-reset/confirm", json={
        "token": reset_token,
        "new_password": "AnotherStrong#2026",
        "confirm_password": "AnotherStrong#2026",
    })
    assert res_reuse.status_code == 400

    # 6. Старий пароль більше не працює, новий працює
    res_old_login = client.post("/api/auth/login", json={
        "email": "student@pnu.edu.ua",
        "password": "hash_st",
    })
    assert res_old_login.status_code == 401

    res_new_login = client.post("/api/auth/login", json={
        "email": "student@pnu.edu.ua",
        "password": "NewStrong#2026",
    })
    assert res_new_login.status_code == 200

    # 7. Перевірка простроченого токена відновлення пароля
    res_req2 = client.post("/api/auth/password-reset/request", json={"email": "student@pnu.edu.ua"})
    assert res_req2.status_code == 200
    expired_reset_token = extract_token_from_last_email()

    conn = sqlite3.connect(str(temp_test_db))
    conn.execute("UPDATE security_tokens SET expires_at = '2020-01-01 00:00:00' WHERE token_type = 'password_reset'")
    conn.commit()
    conn.close()

    res_expired = client.post("/api/auth/password-reset/confirm", json={
        "token": expired_reset_token,
        "new_password": "ValidAgain#2026",
        "confirm_password": "ValidAgain#2026",
    })
    assert res_expired.status_code == 400