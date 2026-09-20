from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

from .task1 import print_password_report
from .task2 import print_access_report
from .task3 import run_task


def main() -> None:
    """Запускає всі індивідуальні завдання."""
    # Усі три частини лабораторної запускаються одним головним модулем.
    print(f"Студент: {STUDENT_NAME}")
    print(f"Група: {GROUP_NAME}")
    print(f"Варіант: {VARIANT_NUMBER}")
    print_password_report()
    print_access_report()
    run_task()


if __name__ == "__main__":
    main()
