import hashlib

def hash_password(password):
  return hashlib.sha256(password.encode()).hexdigest()


def verift_password(password, hashed):
  return hash_password(password) == hashed