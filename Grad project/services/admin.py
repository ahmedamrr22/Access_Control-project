from models.user import User
from utils.logger import log
from utils.security import hash_password

LOG_PATH = "data/logs.txt"


def add_user(current_user, users, username, password, role):
    """
    Adds a new user to the system.
    """
    # Check if username already exists
    for u in users:
        if u.username == username:
            return "User already exists"
    # Enforce minimum password length
    if not isinstance(password, str) or len(password) < 8:
        return "Password must be at least 8 characters"

    # Create user with hashed password
    hashed = hash_password(password)
    new_user = User(username, hashed, role)
    users.append(new_user)

    # Log action
    log(LOG_PATH, f"{current_user.username} added user {username}")

    return "User added"


def remove_user(current_user, users, username):
    """
    Removes an existing user from the system.
    """
    for u in users:
        if u.username == username:
            users.remove(u)
            log(LOG_PATH, f"{current_user.username} removed user {username}")
            return "User removed"
    return "User not found"
