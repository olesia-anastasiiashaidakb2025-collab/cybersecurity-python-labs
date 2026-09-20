"""Завдання 2: Багаторівнева система контролю доступу (варіант 12)."""

import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.append(ROOT_DIR)

from shared.student import (
    GROUP_NAME,
    STUDENT_NAME,
    VARIANT_NUMBER,
)

# Вихідні дані варіанту 12
USERS = {
    "devsecops_lead": {
        "role": "devsecops",
        "clearance": 4,
        "department": "DevSecOps",
        "active": True,
    },
    "security_engineer": {
        "role": "security_engineer",
        "clearance": 3,
        "department": "Security Engineering",
        "active": True,
    },
    "automation_tech": {
        "role": "automation",
        "clearance": 2,
        "department": "Automation",
        "active": True,
    },
    "api_developer": {
        "role": "api_developer",
        "clearance": 2,
        "department": "API",
        "active": True,
    },
    "sandbox_env": {
        "role": "sandbox",
        "clearance": 1,
        "department": "Testing",
        "active": False,
    },
}
RESOURCES = [
    ("security_pipelines", 4),
    ("secure_coding_standards", 3),
    ("automation_scripts", 2),
    ("api_specifications", 2),
    ("threat_models", 4),
    ("testing_frameworks", 1),
    ("security_gates", 3),
    ("vulnerability_scans", 4),
    ("integration_tests", 2),
    ("mock_services", 1),
]
SECURITY_LEVELS = ("Sandbox", "Development", "Secure", "Production Critical")
BLOCKED_USERS = {"sandbox_env", "pipeline_breach", "automation_fail"}


def level_name(level):
    """Перетворює числовий рівень безпеки (1-4) на текстову назву."""
    return SECURITY_LEVELS[level - 1]


def print_resources(resources):
    """Виводить список ресурсів із текстовими назвами рівнів."""
    line = "-" * 46
    print(line)
    print(f"{'№':<4}{'Ресурс':<26}{'Рівень безпеки':<16}")
    print(line)
    for number, (name, level) in enumerate(resources, start=1):
        print(f"{number:<4}{name:<26}{level_name(level):<16}")
    print(line)


def check_access(username, resource_level, users, blocked_users):
    """Перевіряє доступ користувача до ресурсу.

    Повертає кортеж (дозволено: bool, причина відмови: str).
    """
    if username not in users:
        return False, "User not found"
    if username in blocked_users:
        return False, "User is blocked"

    user = users[username]
    if not user["active"]:
        return False, "Account inactive"
    if user["clearance"] >= resource_level:
        return True, ""
    return False, "Insufficient clearance"


def check_all(usernames, resources, users, blocked_users):
    """Перевіряє доступ кожного користувача до кожного ресурсу."""
    for username in usernames:
        for resource_name, resource_level in resources:
            allowed, reason = check_access(
                username, resource_level, users, blocked_users
            )
            if allowed:
                result = "ALLOW"
            else:
                result = f"DENY ({reason})"
            print(f"user={username} resource={resource_name} -> {result}")
        print()


def main():
    """Запуск завдання 2."""
    print(f"Студент: {STUDENT_NAME}, група: {GROUP_NAME}")
    print(f"Варіант: {VARIANT_NUMBER}\n")

    print("Ресурси системи:")
    print_resources(RESOURCES)

    # Додатковий неіснуючий користувач для демонстрації "User not found"
    usernames = list(USERS) + ["unknown_user"]

    print("\nРезультати перевірки доступу:\n")
    check_all(usernames, RESOURCES, USERS, BLOCKED_USERS)


if __name__ == "__main__":
    main()