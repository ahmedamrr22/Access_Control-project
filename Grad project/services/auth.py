from utils.logger import log
from utils.security import verify_password, hash_password, is_hashed

MAX_FAILED = 3


def login(users, username, password, log_path):
    for user in users:
        if user.username == username:
            if user.locked:
                log(log_path, f"{username} login attempt while locked")
                return None, "User is locked"

            # Verify password: supports both legacy plain-text and PBKDF2-hashed
            if verify_password(password, user.password):
                # If stored password was plain-text, upgrade to hashed
                if not is_hashed(user.password):
                    try:
                        user.password = hash_password(password)
                        log(log_path, f"{username} password upgraded to hashed storage")
                    except Exception:
                        pass

                user.failed_attempts = 0
                log(log_path, f"{username} logged in")
                return user, "Login successful"
            else:
                user.failed_attempts += 1
                log(log_path, f"{username} failed login attempt")
                if user.failed_attempts >= MAX_FAILED:
                    user.locked = True
                    log(
                        log_path, f"{username} has been locked due to 3 failed attempts"
                    )
                return None, "Incorrect password"
    return None, "Username not found"


def change_password(
    users, current_user, username, old_password, new_password, log_path
):
    """Change password for `username`.

    - If `current_user` is admin, they may change another user's password without providing the old one.
    - Non-admins must provide the correct `old_password` for their own account.
    """
    for u in users:
        if u.username == username:
            # If not admin and trying to change any account, require old password
            if current_user.role != "admin":
                if not verify_password(old_password, u.password):
                    log(
                        log_path,
                        f"{current_user.username} failed password change for {username}",
                    )
                    return "Incorrect current password"

            if not isinstance(new_password, str) or len(new_password) < 8:
                return "New password must be at least 8 characters"

            try:
                u.password = hash_password(new_password)
                log(
                    log_path, f"{current_user.username} changed password for {username}"
                )
                return "Password changed"
            except Exception:
                return "Failed to change password"
    return "User not found"
