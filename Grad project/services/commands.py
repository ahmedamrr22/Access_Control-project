from services.admin import add_user, remove_user
from utils.logger import log
from utils.storage import save_users

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
            return "Commands: logout, add_user, remove_user, view_logs, status, help"
        else:
            return "Commands: logout, status, help"

    if cmd == "status":
        log(LOG_PATH, f"{current_user.username} checked status")
        return f"Username: {current_user.username}, Role: {current_user.role}, Locked: {current_user.locked}, Failed attempts: {current_user.failed_attempts}"

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

    # Normal users can't run admin commands
    if current_user.role == "user":
        log(LOG_PATH, f"{current_user.username} attempted forbidden command: {cmd}")
        return "Unknown command or permission denied"

    log(LOG_PATH, f"{current_user.username} entered unknown command: {cmd}")
    return "Unknown command"
