import random
import string

from shared.student import VARIANT_NUMBER

PASSWORDS = [
    "Digital@F0r3nsics",
    "plain",
    "Encrypt10n@Key",
    "member",
    "Security@Audit2023",
    "regular",
    "Hack3r@D3fense",
    "ordinary",
    "Threat@Intel",
    "usual",
]
CRITERIA = {
    "min_length": 8,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}
FORBIDDEN_PASSWORDS = {"plain", "member", "regular", "ordinary", "usual", "user"}


def classify_password(password: str, all_passwords: list[str]) -> str:
    """Повертає категорію надійності пароля."""
    # Спочатку відсіюємо заборонені та занадто короткі паролі.
    if password in FORBIDDEN_PASSWORDS or len(password) < CRITERIA["min_length"]:
        return "Заборонений"

    # Окремо перевіряємо наявність цифр, великих літер і спецсимволів.
    checks = [
        not CRITERIA["require_digits"] or any(char.isdigit() for char in password),
        not CRITERIA["require_upper"] or any(char.isupper() for char in password),
        not CRITERIA["require_special"]
        or any(char in string.punctuation for char in password),
    ]
    passed_checks = sum(checks)

    if passed_checks == 0:
        return "Слабкий"
    if passed_checks < len(checks):
        return "Середній"
    if len(password) < CRITERIA["min_length"] + 4:
        return "Сильний"
    if all_passwords.count(password) == 1:
        return "Дуже сильний"
    return "Сильний"


def analyze_passwords() -> list[tuple[int, str, str]]:
    """Додає три випадкові дублікати та класифікує всі паролі."""
    passwords = PASSWORDS.copy()
    # Дублікати імітують повторне використання паролів користувачами.
    duplicate_indexes = random.sample(range(len(PASSWORDS)), 3)
    passwords.extend(PASSWORDS[index] for index in duplicate_indexes)
    return [
        (index, password, classify_password(password, passwords))
        for index, password in enumerate(passwords, start=1)
    ]


def print_password_report() -> None:
    """Виводить звіт аналізу паролів."""
    print(f"\nЗавдання 1 | Варіант {VARIANT_NUMBER}")
    print(f"{'№':<4}{'Пароль':<24}{'Категорія'}")
    print("-" * 52)
    for index, password, category in analyze_passwords():
        print(f"{index:<4}{password:<24}{category}")
