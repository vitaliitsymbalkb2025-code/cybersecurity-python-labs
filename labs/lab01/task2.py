
from shared.student import VARIANT_NUMBER

USERS = {
    "cloud_architect": {
        "role": "cloud_security",
        "clearance": 4,
        "department": "Cloud",
        "active": True,
    },
    "devops_engineer": {
        "role": "devops",
        "clearance": 3,
        "department": "DevOps",
        "active": True,
    },
    "qa_tester": {
        "role": "quality_assurance",
        "clearance": 2,
        "department": "QA",
        "active": True,
    },
    "partner_access": {
        "role": "partner",
        "clearance": 2,
        "department": "Partnership",
        "active": True,
    },
    "migrated_user": {
        "role": "migrated",
        "clearance": 1,
        "department": "Migration",
        "active": False,
    },
}
RESOURCES = [
    ("cloud_configs", 4),
    ("deployment_pipelines", 3),
    ("test_environments", 2),
    ("partner_apis", 2),
    ("infrastructure_code", 4),
    ("shared_resources", 1),
    ("container_registry", 3),
    ("secrets_vault", 4),
    ("build_artifacts", 2),
    ("public_endpoints", 1),
]
SECURITY_LEVELS = ("Development", "Staging", "Production", "Critical Infrastructure")
BLOCKED_USERS = {"migrated_user", "container_breach", "pipeline_compromise"}


def check_access(username: str, resource_level: int) -> tuple[str, str]:
    """Перевіряє доступ користувача до ресурсу."""
    if username not in USERS:
        return "DENY", "User not found"
    if username in BLOCKED_USERS:
        return "DENY", "User is blocked"

    user = USERS[username]
    if not user["active"]:
        return "DENY", "Account inactive"
    if user["clearance"] >= resource_level:
        return "ALLOW", ""
    return "DENY", "Insufficient clearance"


def print_access_report() -> None:
    """Виводить ресурси та результати перевірок доступу."""
    print(f"\nЗавдання 2 | Варіант {VARIANT_NUMBER}")
    print("Ресурси:")
    for resource_name, level in RESOURCES:
        print(f"- {resource_name}: {SECURITY_LEVELS[level - 1]} ({level})")

    print("\nПеревірки доступу:")
    for username in [*USERS, "unknown_user"]:
        for resource_name, resource_level in RESOURCES:
            result, reason = check_access(username, resource_level)
            suffix = f" ({reason})" if reason else ""
            print(f"user={username} resource={resource_name} -> {result}{suffix}")
