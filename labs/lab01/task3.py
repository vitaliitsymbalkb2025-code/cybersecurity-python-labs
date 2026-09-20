import csv
import hashlib
import json
from collections.abc import Callable
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from typing import Any

from shared.student import VARIANT_NUMBER

MIN_PASSWORD_LENGTH = 13
HASH_ALGORITHM = "sha224"
# Варіант записується як п'ять цифр, тому для 9 отримуємо 00009.
SALT = f"{VARIANT_NUMBER:05d}"
DATA_DIR = Path(__file__).parent / "data"
USERS_FILE = DATA_DIR / "users.csv"
LOG_FILE = DATA_DIR / "log.json"
USERS_TO_REGISTER = (
    ("cloud_admin", "CloudAdmin#2024x"),
    ("devops_lead", "DevOpsLead$2024"),
    ("qa_manager", "QAManager!2024"),
    ("partner_user", "PartnerUser@24"),
    ("security_architect", "SecurityArch#9"),
    ("audit_operator", "AuditOperator$9"),
    ("pipeline_owner", "PipelineOwner!9"),
    ("data_engineer", "DataEngineer@9"),
    ("release_manager", "ReleaseManager#9"),
    ("incident_lead", "IncidentLead$9"),
)


class ValidationError(Exception):
    """Помилка невідповідності пароля вимогам варіанта."""


def generate_hash(password: str, salt: str = "00000") -> str:
    """Повертає SHA-224 хеш пароля з сіллю."""
    if not password or not salt:
        raise ValueError("Пароль і сіль не можуть бути порожніми")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Пароль має містити щонайменше {MIN_PASSWORD_LENGTH} символів"
        )
    # Пароль не зберігаємо, у файл потрапляє тільки його хеш.
    value = f"{password}{salt}".encode()
    return hashlib.new(HASH_ALGORITHM, value).hexdigest()


def create_user(username: str, password: str) -> tuple[str, str]:
    """Створює запис користувача з хешем пароля."""
    if not username:
        raise ValueError("Логін не може бути порожнім")
    return username, generate_hash(password, SALT)


def create_users(users_list: tuple[tuple[str, str], ...]) -> list[tuple[str, str]]:
    """Створює каталог data та записує користувачів у CSV."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    users_db = [create_user(username, password) for username, password in users_list]
    try:
        # newline="" потрібен, щоб CSV не отримував зайві порожні рядки.
        with USERS_FILE.open("w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerows(users_db)
    except OSError as error:
        print(f"Помилка запису CSV: {error}")
        raise
    return users_db


def read_users() -> list[tuple[str, str]]:
    """Зчитує базу користувачів з CSV."""
    try:
        with USERS_FILE.open(newline="", encoding="utf-8") as file:
            return [tuple(row) for row in csv.reader(file) if len(row) == 2]
    except OSError as error:
        print(f"Помилка читання CSV: {error}")
        return []


def log_event(function: Callable[..., Any]) -> Callable[..., Any]:
    """Логує кожен виклик функції автентифікації."""

    @wraps(function)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        username = kwargs.get("username", args[0] if args else "")
        result = "failure"
        try:
            # Якщо login повернув False, спроба теж вважається невдалою.
            response = function(*args, **kwargs)
            result = "success" if response else "failure"
            return response
        finally:
            event = {
                "event": "login",
                "user": username,
                "result": result,
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                "args": [],
                "kwargs": {},
            }
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            try:
                # Журнал зберігаємо як список подій, щоб не затирати старі записи.
                events = []
                if LOG_FILE.exists():
                    with LOG_FILE.open(encoding="utf-8") as file:
                        events = json.load(file)
                events.append(event)
                with LOG_FILE.open("w", encoding="utf-8") as file:
                    json.dump(events, file, ensure_ascii=False, indent=2)
            except (OSError, json.JSONDecodeError) as error:
                print(f"Помилка запису журналу: {error}")

    return wrapper


@log_event
def login(username: str, password: str) -> bool:
    """Перевіряє логін і пароль користувача."""
    if not username or not password:
        raise ValueError("Логін і пароль не можуть бути порожніми")
    expected_hash = dict(read_users()).get(username)
    if expected_hash is None:
        return False
    return expected_hash == generate_hash(password, SALT)


def print_users(users_db: list[tuple[str, str]]) -> None:
    """Виводить CSV-базу у вигляді таблиці."""
    print(f"\nЗавдання 3 | Варіант {VARIANT_NUMBER}")
    print(f"{'Логін':<24}Хеш SHA-224")
    print("-" * 80)
    for username, password_hash in users_db:
        print(f"{username:<24}{password_hash}")


def run_task() -> None:
    """Виконує реєстрацію, читання бази та демонстрацію входу."""
    try:
        create_users(USERS_TO_REGISTER)
        users_db = read_users()
        print_users(users_db)
        print("\nРезультати входу:")
        print(
            f"cloud_admin / правильний пароль -> {login('cloud_admin', 'CloudAdmin#2024x')}"
        )
        print(
            f"cloud_admin / неправильний пароль -> {login('cloud_admin', 'wrong-password')}"
        )
        print(f"unknown / будь-який пароль -> {login('unknown', 'UnknownPassword#9')}")
    except (OSError, ValidationError, ValueError) as error:
        print(f"Помилка виконання завдання 3: {error}")
