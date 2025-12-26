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
