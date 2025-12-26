from utils.storage import load_users, save_users
from services.auth import login
from services.commands import handle_command
import speech_recognition as sr

USERS_PATH = "data/users.json"
LOG_PATH = "data/logs.txt"


# Voice input function


def listen_command():
    r = sr.Recognizer()
    with sr.Microphone() as source:
        print("Say a command:")
        audio = r.listen(source)
    try:
        cmd = r.recognize_google(audio)
        print(f"You said: {cmd}")
        return cmd.lower()
    except:
        print("Could not understand audio")
        return ""


# Normalize voice input


def normalize_command(cmd):
    cmd = cmd.lower().strip()
    if cmd in ["add user", "adduser", "add the user"]:
        return "add_user"
    if cmd in ["remove user", "removeuser", "delete user"]:
        return "remove_user"
    if cmd in ["view logs", "viewlogs", "show logs", "display logs", "view log"]:
        return "view_logs"
    if cmd in ["help", "show help", "what can i do"]:
        return "help"
    if cmd in ["status", "show status", "my status"]:
        return "status"
    if cmd in ["logout", "log out", "exit"]:
        return "logout"
    return cmd


# Load users

users = load_users(USERS_PATH)


# LOGIN LOOP

while True:
    username = input("Username: ")
    password = input("Password: ")
    current_user, msg = login(users, username, password, LOG_PATH)
    print(msg)
    if current_user:
        # Persist potential password upgrade (plain -> hashed)
        try:
            save_users(USERS_PATH, users)
        except Exception:
            pass
        break


# Choose input mode

mode = input("Choose input mode (type/voice): ").lower()
if mode not in ["type", "voice"]:
    mode = "type"


# COMMAND LOOP

while True:
    if mode == "voice":
        cmd = listen_command()
        cmd = normalize_command(cmd)  # Normalize voice input
        print(f"Interpreted command: {cmd}")  # Optional, helpful for demo
    else:
        cmd = input("Enter command: ")

    if cmd == "":
        continue

    result = handle_command(cmd, current_user, users)

    if result == "logout":
        save_users(USERS_PATH, users)
        print("Logged out")
        break

    print(result)
    save_users(USERS_PATH, users)
