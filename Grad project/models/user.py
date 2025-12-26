class User:
    def __init__(self, username, password, role):
        self.username = username
        self.password = password
        self.role = role
        self.failed_attempts = 0
        self.locked = False
