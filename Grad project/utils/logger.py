from datetime import datetime

def log(path, message):
    time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(path, "a") as f:
        f.write(f"[{time}] {message}\n")
