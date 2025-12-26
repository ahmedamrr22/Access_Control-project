import json
from models.user import User
import csv


def load_users(path):
    users = []
    try:
        with open(path, "r") as f:
            data = json.load(f)
            for u in data:
                user = User(u["username"], u["password"], u["role"])
                user.failed_attempts = u.get("failed_attempts", 0)
                user.locked = u.get("locked", False)
                users.append(user)
    except FileNotFoundError:
        pass
    return users


def save_users(path, users):
    data = []
    for u in users:
        data.append(
            {
                "username": u.username,
                "password": u.password,
                "role": u.role,
                "failed_attempts": u.failed_attempts,
                "locked": u.locked,
            }
        )
    with open(path, "w") as f:
        json.dump(data, f, indent=4)


def export_users_csv(csv_path, users):
    """Export users data to a CSV file at `csv_path`.

    Columns: username, role, locked, failed_attempts
    """
    with open(csv_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["username", "role", "locked", "failed_attempts"])
        for u in users:
            writer.writerow([u.username, u.role, u.locked, u.failed_attempts])
