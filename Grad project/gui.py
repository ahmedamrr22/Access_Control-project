import threading
import tkinter as tk
from tkinter import messagebox, simpledialog, scrolledtext
from tkinter import ttk
import tkinter.font as tkfont

from utils.storage import load_users, save_users
from services.auth import login
from services.admin import add_user, remove_user
from utils.logger import log

# Optional speech recognition
try:
    import speech_recognition as sr

    VOICE_AVAILABLE = True
except Exception:
    sr = None
    VOICE_AVAILABLE = False

USERS_PATH = "data/users.json"
LOG_PATH = "data/logs.txt"


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Access Control")
        self.geometry("700x520")

        # Modern ttk style and font
        self.style = ttk.Style(self)
        try:
            self.style.theme_use("vista")
        except Exception:
            try:
                self.style.theme_use("clam")
            except Exception:
                pass

        default_font = tkfont.nametofont("TkDefaultFont")
        default_font.configure(family="Segoe UI", size=10)

        self.option_add("*TCombobox*Listbox.font", default_font)

        self.users = load_users(USERS_PATH)
        self.current_user = None

        self.login_frame = None
        self.main_frame = None

        self.show_login()

    def show_login(self):
        if self.main_frame:
            self.main_frame.destroy()
        self.login_frame = ttk.Frame(self, padding=20)
        self.login_frame.pack(fill="both", expand=True)

        frm = ttk.Frame(self.login_frame)
        frm.place(relx=0.5, rely=0.4, anchor="center")

        ttk.Label(frm, text="Username:").grid(
            row=0, column=0, sticky="e", padx=6, pady=6
        )
        self.username_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.username_var, width=30).grid(
            row=0, column=1, pady=6
        )

        ttk.Label(frm, text="Password:").grid(
            row=1, column=0, sticky="e", padx=6, pady=6
        )
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(
            frm, textvariable=self.password_var, show="*", width=30
        )
        self.password_entry.grid(row=1, column=1, pady=6)

        self.show_pwd_var = tk.BooleanVar(value=False)

        def toggle_pwd():
            self.password_entry.config(show=("" if self.show_pwd_var.get() else "*"))

        ttk.Checkbutton(
            frm, text="Show password", variable=self.show_pwd_var, command=toggle_pwd
        ).grid(row=2, column=1, sticky="w")

        ttk.Button(frm, text="Sign in", command=self.attempt_login).grid(
            row=3, column=0, columnspan=2, pady=(12, 0), ipadx=10
        )

    def attempt_login(self):
        username = self.username_var.get().strip()
        password = self.password_var.get().strip()
        user, msg = login(self.users, username, password, LOG_PATH)
        messagebox.showinfo("Login", msg)
        if user:
            self.current_user = user
            # Persist possible password upgrade (plain -> hashed) or other changes
            try:
                save_users(USERS_PATH, self.users)
            except Exception:
                pass
            self.login_frame.destroy()
            self.show_main()

    def show_main(self):
        self.main_frame = ttk.Frame(self, padding=12)
        self.main_frame.pack(fill="both", expand=True)

        # Menu
        menubar = tk.Menu(self)
        filem = tk.Menu(menubar, tearoff=0)
        filem.add_command(label="Exit", command=self.destroy)
        menubar.add_cascade(label="File", menu=filem)
        helpm = tk.Menu(menubar, tearoff=0)
        helpm.add_command(
            label="About",
            command=lambda: messagebox.showinfo("About", "Access Control — GUI"),
        )
        menubar.add_cascade(label="Help", menu=helpm)
        self.config(menu=menubar)

        header = ttk.Frame(self.main_frame)
        header.pack(fill="x", pady=(0, 8))
        ttk.Label(
            header,
            text=f"Logged in as: {self.current_user.username}",
            font=(None, 11, "bold"),
        ).pack(side="left")
        ttk.Label(header, text=f"Role: {self.current_user.role}").pack(
            side="left", padx=12
        )

        # Voice & logout
        right_controls = ttk.Frame(header)
        right_controls.pack(side="right")
        self.voice_btn = ttk.Button(
            right_controls, text="🎤 Voice", command=self.start_listen
        )
        self.voice_btn.pack(side="left", padx=6)
        ttk.Button(right_controls, text="Logout", command=self.logout).pack(side="left")

        # Main content
        content = ttk.Frame(self.main_frame)
        content.pack(fill="both", expand=True)

        if self.current_user.role == "admin":
            self.show_admin_controls()
        else:
            self.show_user_controls()

    def show_admin_controls(self):
        frame = ttk.Frame(self.main_frame)
        frame.pack(fill="both", expand=True, pady=8)

        tree_frame = ttk.Frame(frame)
        tree_frame.pack(fill="both", expand=True)
        cols = ("username", "role", "locked")
        self.users_tree = ttk.Treeview(
            tree_frame, columns=cols, show="headings", selectmode="browse"
        )
        self.users_tree.heading("username", text="Username")
        self.users_tree.heading("role", text="Role")
        self.users_tree.heading("locked", text="Locked")
        self.users_tree.column("username", width=220)
        self.users_tree.column("role", width=100, anchor="center")
        self.users_tree.column("locked", width=80, anchor="center")
        self.users_tree.pack(fill="both", expand=True, side="left")

        scrollbar = ttk.Scrollbar(
            tree_frame, orient="vertical", command=self.users_tree.yview
        )
        scrollbar.pack(side="right", fill="y")
        self.users_tree.configure(yscrollcommand=scrollbar.set)

        self.refresh_user_list()

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill="x", pady=8)
        ttk.Button(btn_frame, text="Add User", command=self.add_user_dialog).pack(
            side="left", padx=6
        )
        ttk.Button(
            btn_frame, text="Remove Selected", command=self.remove_selected_user
        ).pack(side="left", padx=6)
        ttk.Button(btn_frame, text="View Logs", command=self.view_logs).pack(
            side="left", padx=6
        )

    def show_user_controls(self):
        frame = ttk.Frame(self.main_frame)
        frame.pack(fill="both", expand=True, pady=8)

        status = f"Username: {self.current_user.username}\nRole: {self.current_user.role}\nLocked: {self.current_user.locked}\nFailed attempts: {self.current_user.failed_attempts}"
        ttk.Label(frame, text="Status:").pack(anchor="w")
        ttk.Label(frame, text=status, justify="left").pack(anchor="w")

    def refresh_user_list(self):
        try:
            # clear
            for item in self.users_tree.get_children():
                self.users_tree.delete(item)
            for u in self.users:
                self.users_tree.insert(
                    "", tk.END, values=(u.username, u.role, str(u.locked))
                )
        except Exception:
            # fallback to previous listbox if not initialized
            try:
                self.users_listbox.delete(0, tk.END)
                for u in self.users:
                    self.users_listbox.insert(tk.END, f"{u.username} ({u.role})")
            except Exception:
                pass

    # --- Voice helpers ---
    def normalize_command(self, cmd):
        cmd = (cmd or "").lower().strip()
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

    def listen_command(self):
        if not VOICE_AVAILABLE:
            raise RuntimeError(
                "Speech recognition not available. Install SpeechRecognition."
            )
        r = sr.Recognizer()
        with sr.Microphone() as source:
            try:
                messagebox.showinfo("Voice", "Listening... Speak now.")
            except Exception:
                pass
            audio = r.listen(source)
        try:
            cmd = r.recognize_google(audio)
            return cmd.lower()
        except Exception:
            return ""

    def start_listen(self):
        if not VOICE_AVAILABLE:
            messagebox.showerror(
                "Voice",
                "SpeechRecognition not installed. Run: pip install SpeechRecognition\nOn Windows you may also need PyAudio.",
            )
            return
        # Disable button while listening
        try:
            self.voice_btn.config(state="disabled")
        except Exception:
            pass
        t = threading.Thread(target=self._bg_listen, daemon=True)
        t.start()

    def _bg_listen(self):
        cmd = self.listen_command()
        normalized = self.normalize_command(cmd)
        self.process_voice_command(normalized, raw=cmd)
        try:
            self.voice_btn.config(state="normal")
        except Exception:
            pass

    def process_voice_command(self, cmd, raw=None):
        if not cmd:
            messagebox.showinfo("Voice", f"Could not understand audio: {raw}")
            return

        if cmd == "logout":
            self.logout()
            return

        if cmd == "help":
            if self.current_user.role == "admin":
                messagebox.showinfo(
                    "Help",
                    "Commands: logout, add_user, remove_user, view_logs, status, help",
                )
            else:
                messagebox.showinfo("Help", "Commands: logout, status, help")
            return

        if cmd == "status":
            status = f"Username: {self.current_user.username}\nRole: {self.current_user.role}\nLocked: {self.current_user.locked}\nFailed attempts: {self.current_user.failed_attempts}"
            messagebox.showinfo("Status", status)
            return

        if cmd == "view_logs":
            if self.current_user.role == "admin":
                self.view_logs()
            else:
                messagebox.showerror("Permission", "Permission denied")
            return

        if cmd == "add_user":
            if self.current_user.role == "admin":
                # open same dialog used by admin add
                self.add_user_dialog()
            else:
                messagebox.showerror("Permission", "Permission denied")
            return

        if cmd == "remove_user":
            if self.current_user.role == "admin":
                username = simpledialog.askstring(
                    "Remove user (voice)", "Username to remove:", parent=self
                )
                if username:
                    result = remove_user(self.current_user, self.users, username)
                    save_users(USERS_PATH, self.users)
                    log(
                        LOG_PATH,
                        f"{self.current_user.username} executed remove_user via GUI/voice: {username}",
                    )
                    messagebox.showinfo("Remove user", result)
                    try:
                        self.refresh_user_list()
                    except Exception:
                        pass
            else:
                messagebox.showerror("Permission", "Permission denied")
            return

        messagebox.showinfo("Voice", f"Unknown command: {cmd}")

    def add_user_dialog(self):
        username = simpledialog.askstring("Add user", "Username:", parent=self)
        if not username:
            return
        password = simpledialog.askstring(
            "Add user", "Password:", parent=self, show="*"
        )
        if password is None:
            return
        if len(password) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters")
            return
        role = simpledialog.askstring("Add user", "Role (admin/user):", parent=self)
        if role not in ("admin", "user"):
            messagebox.showerror("Error", "Role must be 'admin' or 'user'")
            return

        result = add_user(self.current_user, self.users, username, password, role)
        save_users(USERS_PATH, self.users)
        log(
            LOG_PATH,
            f"{self.current_user.username} executed add_user via GUI: {username}",
        )
        messagebox.showinfo("Add user", result)
        self.refresh_user_list()

    def remove_selected_user(self):
        try:
            sel = self.users_tree.selection()
            if not sel:
                messagebox.showwarning("Remove user", "No user selected")
                return
            item = sel[0]
            vals = self.users_tree.item(item, "values")
            username = vals[0]
        except Exception:
            # fallback to listbox
            try:
                sel = self.users_listbox.curselection()
                if not sel:
                    messagebox.showwarning("Remove user", "No user selected")
                    return
                entry = self.users_listbox.get(sel[0])
                username = entry.split()[0]
            except Exception:
                messagebox.showwarning("Remove user", "No user selected")
                return

        if username == self.current_user.username:
            messagebox.showerror("Error", "Cannot remove the logged-in user.")
            return

        result = remove_user(self.current_user, self.users, username)
        save_users(USERS_PATH, self.users)
        log(
            LOG_PATH,
            f"{self.current_user.username} executed remove_user via GUI: {username}",
        )
        messagebox.showinfo("Remove user", result)
        self.refresh_user_list()

    def view_logs(self):
        try:
            with open(LOG_PATH, "r") as f:
                logs = f.read()
        except FileNotFoundError:
            logs = "No logs yet."

        win = tk.Toplevel(self)
        win.title("Logs")
        txt = scrolledtext.ScrolledText(win, wrap=tk.WORD, width=80, height=20)
        txt.pack(fill="both", expand=True)
        txt.insert(tk.END, logs)
        txt.configure(state="disabled")

    def logout(self):
        save_users(USERS_PATH, self.users)
        log(LOG_PATH, f"{self.current_user.username} logged out via GUI")
        self.current_user = None
        self.main_frame.destroy()
        self.show_login()


if __name__ == "__main__":
    app = App()
    app.mainloop()
