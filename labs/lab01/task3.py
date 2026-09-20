"""Завдання 3: Хешування, CSV-база та JSON-логування (варіант 12)."""

import csv
import functools
import hashlib
import hmac
import json
import os
import sys
from datetime import datetime, timezone

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.append(ROOT_DIR)

from shared.student import (
    GROUP_NAME,
    STUDENT_NAME,
    VARIANT_NUMBER,
)

# Параметри варіанту 12: md5, мінімальна довжина пароля - 8
HASH_ALGORITHM = "md5"
MIN_PASSWORD_LENGTH = 8

# Персональна сіль: варіант, доповнений зліва нулями до 5 символів
PERSONAL_SALT = str(VARIANT_NUMBER).zfill(5)

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
USERS_FILE = os.path.join(DATA_DIR, "users.csv")
LOG_FILE = os.path.join(DATA_DIR, "log.json")

USERS_TO_REGISTER = (
    ("alice", "Alice@Secure1"),
    ("bob", "B0b#Strong2026"),
    ("charlie", "Ch@rlie_pass9"),
    ("diana", "D1ana!Cyber77"),
    ("eve", "Ev3@Analyst42"),
    ("frank", "Fr@nk_SIEM2026"),
    ("grace", "Gr4ce#Hunter8"),
    ("heidi", "He1di@Forensic"),
    ("ivan", "Iv@n_Defender5"),
    ("judy", "Ju6dy#Monitor3"),
)

# Спроби входу для демонстрації (правильні, неправильні, некоректні)
LOGIN_ATTEMPTS = (
    ("alice", "Alice@Secure1"),
    ("alice", "WrongPass123"),
    ("mallory", "Hack3r@Pass1"),
    ("bob", "abc"),
    ("bob", ""),
)

# Список записів (логін, хеш), який заповнюється з CSV-файлу
users_db = []


class ValidationError(Exception):
    """Помилка валідації (наприклад, занадто короткий пароль)."""


def generate_hash(password: str, salt: str = "00000") -> str:
    """Повертає hex-хеш від конкатенації пароля та солі."""
    if not password or not salt:
        raise ValueError("Пароль і сіль не можуть бути порожніми")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Пароль коротший за {MIN_PASSWORD_LENGTH} символів"
        )
    data = (password + salt).encode("utf-8")
    return hashlib.new(HASH_ALGORITHM, data).hexdigest()


def create_user(username, password):
    """Створює запис користувача (логін, хеш пароля)."""
    if not username:
        raise ValueError("Логін не може бути порожнім")
    return username, generate_hash(password, PERSONAL_SALT)


def create_users(users_list):
    """Створює базу користувачів і записує її у CSV-файл."""
    # Спочатку хешуємо всіх: при помилці файл не буде записано частково
    rows = [create_user(name, password) for name, password in users_list]
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(USERS_FILE, "w", newline="", encoding="utf-8") as file:
        csv.writer(file).writerows(rows)
    return rows


def load_users_db():
    """Зчитує CSV-файл у список users_db."""
    rows = []
    with open(USERS_FILE, newline="", encoding="utf-8") as file:
        for row in csv.reader(file):
            if len(row) == 2:
                rows.append((row[0], row[1]))
    users_db.clear()
    users_db.extend(rows)
    return users_db


def print_users_db(db):
    """Виводить базу користувачів у вигляді таблиці."""
    line = "-" * 52
    print(line)
    print(f"{'№':<4}{'Логін':<16}{'Хеш пароля (md5)':<32}")
    print(line)
    for number, (username, hash_value) in enumerate(db, start=1):
        print(f"{number:<4}{username:<16}{hash_value:<32}")
    print(line)


def write_log(entry):
    """Додає подію до JSON-журналу."""
    entries = []
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, encoding="utf-8") as file:
                entries = json.load(file)
        except json.JSONDecodeError:
            entries = []
    entries.append(entry)
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(LOG_FILE, "w", encoding="utf-8") as file:
        json.dump(entries, file, ensure_ascii=False, indent=4)


def log_event(func):
    """Декоратор: записує кожну спробу входу у log.json."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        username = args[0] if args else kwargs.get("username")
        result = "failure"
        try:
            success = func(*args, **kwargs)
            result = "success" if success else "failure"
            return success
        finally:
            # Аргументи (пароль!) навмисно не логуються
            entry = {
                "event": "login",
                "user": username,
                "result": result,
                "timestamp": datetime.now(timezone.utc).strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "args": [],
                "kwargs": {},
            }
            try:
                write_log(entry)
            except OSError as error:
                print(f"[!] Не вдалося записати лог: {error}")

    return wrapper


@log_event
def login(username: str, password: str) -> bool:
    """Перевіряє логін і пароль користувача за базою users_db."""
    if not username or not password:
        raise ValueError("Логін і пароль не можуть бути порожніми")
    try:
        hash_value = generate_hash(password, PERSONAL_SALT)
    except ValidationError:
        # Занадто короткий пароль не може збігатися зі збереженим
        return False
    for stored_login, stored_hash in users_db:
        if stored_login == username:
            return hmac.compare_digest(stored_hash, hash_value)
    return False


def run_login_demo():
    """Виконує демонстраційні спроби входу."""
    print("\nСпроби входу:")
    for username, password in LOGIN_ATTEMPTS:
        try:
            success = login(username, password)
        except ValueError as error:
            print(f"login={username!r} -> ERROR ({error})")
            continue
        status = "SUCCESS" if success else "FAILURE"
        print(f"login={username!r} -> {status}")


def main():
    """Головна функція запуску завдання 3."""
    print(f"Студент: {STUDENT_NAME}, група: {GROUP_NAME}")
    print(f"Варіант: {VARIANT_NUMBER}, алгоритм: {HASH_ALGORITHM}")
    print(f"Сіль: {PERSONAL_SALT}, мін. довжина пароля: {MIN_PASSWORD_LENGTH}")
    print()

    try:
        create_users(USERS_TO_REGISTER)
        print(f"Користувачів збережено у файл: {USERS_FILE}\n")
        print_users_db(load_users_db())
        run_login_demo()
    except FileNotFoundError as error:
        print(f"[!] Файл не знайдено: {error}")
    except PermissionError as error:
        print(f"[!] Немає прав доступу до файлу: {error}")
    except OSError as error:  # IOError є псевдонімом OSError
        print(f"[!] Помилка вводу/виводу: {error}")
    except ValidationError as error:
        print(f"[!] Помилка валідації: {error}")
    except ValueError as error:
        print(f"[!] Некоректне значення: {error}")


if __name__ == "__main__":
    main()