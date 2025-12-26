from services.admin import add_user, remove_user
from services.auth import change_password
from utils.logger import log
from utils.storage import save_users, export_users_csv

LOG_PATH = "data/logs.txt"
USERS_PATH = "data/users.json"


def handle_command(cmd, current_user, users):
    cmd = cmd.lower()

    # Commands for all users
    if cmd == "logout":
        log(LOG_PATH, f"{current_user.username} logged out")
        return "logout"

    if cmd == "help":
        log(LOG_PATH, f"{current_user.username} used help")
        if current_user.role == "admin":
            return "Commands: logout, add_user, remove_user, view_logs, export_csv, change_password, status, help"
        else:
            return "Commands: logout, change_password, status, help"

    if cmd == "status":
        log(LOG_PATH, f"{current_user.username} checked status")
        return f"Username: {current_user.username}, Role: {current_user.role}, Locked: {current_user.locked}, Failed attempts: {current_user.failed_attempts}"

    # Change password (users for themselves; admins may change others)
    if cmd == "change_password":
        if current_user.role == "admin":
            target = input(
                "Enter username to change (leave blank for yourself): "
            ).strip()
            if not target:
                target = current_user.username
            # Admin doesn't need to provide old password when changing others
            old = None
            if target == current_user.username:
                old = input("Enter current password: ")
        else:
            target = current_user.username
            old = input("Enter current password: ")

        new = input("Enter new password: ")
        result = change_password(users, current_user, target, old, new, LOG_PATH)
        # Persist password change
        save_users(USERS_PATH, users)
        return result

    # Admin-only commands
    if current_user.role == "admin":
        if cmd == "add_user":
            username = input("Enter username: ")
            password = input("Enter password: ")
            role = input("Enter role (admin/user): ")
            result = add_user(current_user, users, username, password, role)
            log(LOG_PATH, f"{current_user.username} executed add_user: {username}")

            # Save users immediately
            save_users(USERS_PATH, users)

            return result

        if cmd == "remove_user":
            username = input("Enter username to remove: ")
            result = remove_user(current_user, users, username)
            log(LOG_PATH, f"{current_user.username} executed remove_user: {username}")

            # Save users immediately
            save_users(USERS_PATH, users)

            return result

        if cmd == "view_logs":
            try:
                with open(LOG_PATH, "r") as f:
                    logs = f.read()
                log(LOG_PATH, f"{current_user.username} viewed logs")
                return logs if logs else "No logs yet."
            except FileNotFoundError:
                return "No logs file found."

        if cmd == "export_csv":
            csv_path = input("Enter CSV path (default data/users.csv): ").strip()
            if not csv_path:
                csv_path = "data/users.csv"
            try:
                export_users_csv(csv_path, users)
                log(
                    LOG_PATH,
                    f"{current_user.username} exported users to CSV: {csv_path}",
                )
                return f"Exported users to {csv_path}"
            except Exception as e:
                return f"Failed to export CSV: {e}"

    # Normal users can't run admin commands
    if current_user.role == "user":
        log(LOG_PATH, f"{current_user.username} attempted forbidden command: {cmd}")
        return "Unknown command or permission denied"

    log(LOG_PATH, f"{current_user.username} entered unknown command: {cmd}")
    return "Unknown command"
