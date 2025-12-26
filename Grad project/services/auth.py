from utils.logger import log

MAX_FAILED = 3

def login(users, username, password, log_path):
    for user in users:
        if user.username == username:
            if user.locked:
                log(log_path, f"{username} login attempt while locked")
                return None, "User is locked"
            if user.password == password:
                user.failed_attempts = 0
                log(log_path, f"{username} logged in")
                return user, "Login successful"
            else:
                user.failed_attempts += 1
                log(log_path, f"{username} failed login attempt")
                if user.failed_attempts >= MAX_FAILED:
                    user.locked = True
                    log(log_path, f"{username} has been locked due to 3 failed attempts")
                return None, "Incorrect password"
    return None, "Username not found"
