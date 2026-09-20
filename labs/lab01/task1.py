"""Завдання 1: Комплексний аналізатор надійності паролів (варіант 12)."""

import os
import random
import string
import sys
from collections import Counter

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.append(ROOT_DIR)

from shared.student import (
    GROUP_NAME,
    STUDENT_NAME,
    VARIANT_NUMBER,
)

# Вихідні дані варіанту 12
PASSWORDS = [
    "SIEM@An4lysis",
    "easy123",
    "S0C@Analyst",
    "observer",
    "Threat@Hunt1ng",
    "viewer",
    "Incid3nt@Handle",
    "monitor",
    "Log@An4lysis",
    "watcher",
]
CRITERIA = {
    "min_length": 9,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}
FORBIDDEN_PASSWORDS = {
    "easy123",
    "observer",
    "viewer",
    "monitor",
    "watcher",
    "admin",
}

FORBIDDEN = "Заборонений"
WEAK = "Слабкий"
MEDIUM = "Середній"
STRONG = "Сильний"
VERY_STRONG = "Дуже сильний"


def add_random_duplicates(passwords, count=3):
    """Додає в кінець списку дублікати паролів з випадковими індексами."""
    indexes = random.sample(range(len(passwords)), count)
    result = list(passwords)
    for index in indexes:
        result.append(passwords[index])
    return result, indexes


def get_char_groups(password):
    """Визначає, які групи символів містить пароль."""
    return {
        "digit": any(ch.isdigit() for ch in password),
        "upper": any(ch.isupper() for ch in password),
        "lower": any(ch.islower() for ch in password),
        "special": any(ch in string.punctuation for ch in password),
    }


def evaluate_password(password, criteria, forbidden, counter):
    """Повертає рівень надійності пароля."""
    min_length = criteria["min_length"]

    if password in forbidden or len(password) < min_length:
        return FORBIDDEN

    groups = get_char_groups(password)
    meets_all = (
        (groups["digit"] or not criteria["require_digits"])
        and (groups["upper"] or not criteria["require_upper"])
        and (groups["special"] or not criteria["require_special"])
    )

    if meets_all:
        is_unique = counter[password] == 1
        if len(password) >= min_length + 4 and is_unique:
            return VERY_STRONG
        return STRONG

    if sum(groups.values()) >= 2:
        return MEDIUM
    return WEAK


def print_table(passwords, criteria, forbidden):
    """Виводить результат аналізу у вигляді таблиці."""
    counter = Counter(passwords)
    line = "-" * 70
    print(line)
    print(
        f"{'№':<4}{'Пароль':<20}{'Довжина':<10}"
        f"{'Унікальний':<13}{'Результат':<14}"
    )
    print(line)
    for number, password in enumerate(passwords, start=1):
        level = evaluate_password(password, criteria, forbidden, counter)
        unique = "Так" if counter[password] == 1 else "Ні"
        print(
            f"{number:<4}{password:<20}{len(password):<10}"
            f"{unique:<13}{level:<14}"
        )
    print(line)


def main():
    """Запуск завдання 1."""
    print(f"Студент: {STUDENT_NAME}, група: {GROUP_NAME}")
    print(f"Варіант: {VARIANT_NUMBER}\n")

    passwords, indexes = add_random_duplicates(PASSWORDS, count=3)
    print(f"Випадкові індекси для дублювання: {sorted(indexes)}")
    print(f"Критерії: {CRITERIA}\n")

    print_table(passwords, CRITERIA, FORBIDDEN_PASSWORDS)


if __name__ == "__main__":
    main()