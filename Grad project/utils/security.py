import hashlib
import os


# Use PBKDF2-HMAC-SHA256 with per-user salt
def hash_password(password: str, iterations: int = 100_000) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    if not stored or "$" not in stored:
        # stored value is likely plain-text fallback
        return password == stored
    try:
        algo, iters, salt_hex, hash_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        iterations = int(iters)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
        return dk == expected
    except Exception:
        return False


def is_hashed(stored: str) -> bool:
    return isinstance(stored, str) and stored.startswith("pbkdf2_sha256$")
