# secure_vault/main.py
import os
import sqlite3
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
import hashlib
import base64
from cryptography.fernet import Fernet
from pathlib import Path


BASE_DIR = Path(__file__).parent
DB_PATH = BASE_DIR / "database.db"
KEY_PATH = BASE_DIR / "key_store"

# Utility Functions

def derive_key(password):
    return base64.urlsafe_b64encode(hashlib.pbkdf2_hmac('sha256', password.encode(), b'somesalt', 100000, dklen=32))

def encrypt(data, key):
    f = Fernet(key)
    return f.encrypt(data.encode())

def decrypt(token, key):
    f = Fernet(key)
    return f.decrypt(token).decode()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def check_password(password):
    if not os.path.exists(KEY_PATH):
        return False
    with open(KEY_PATH, 'r') as f:
        stored = f.read()
    return hash_password(password) == stored

def save_password_hash(password):
    with open(KEY_PATH, 'w') as f:
        f.write(hash_password(password))

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS vault (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT NOT NULL,
                    password TEXT NOT NULL,
                    extra TEXT
                )''')
    conn.commit()
    conn.close()

# GUI Classes

class VaultApp:
    def __init__(self, master, key):
        self.master = master
        self.key = key
        master.title("Secure Vault")
        master.geometry("600x400")  # Increased width to accommodate Extra column

        self.tree = ttk.Treeview(master, columns=("UserID", "Password", "Extra"), show='headings')
        self.tree.heading("UserID", text="ID")
        self.tree.heading("Password", text="Password")
        self.tree.heading("Extra", text="Extra")
        self.tree.pack(pady=10, expand=True, fill=tk.BOTH)

        tk.Button(master, text="Add Credential", command=self.add_credential).pack(pady=5)
        tk.Button(master, text="Refresh", command=self.load_credentials).pack()

        self.load_credentials()

    def center_popup(self, popup):
        popup.update_idletasks()
        screen_width = popup.winfo_screenwidth()
        screen_height = popup.winfo_screenheight()
        size = tuple(int(_) for _ in popup.geometry().split('+')[0].split('x'))
        x = (screen_width - size[0]) // 2
        y = (screen_height - size[1]) // 2
        popup.geometry(f"{size[0]}x{size[1]}+{x}+{y}")

    def add_credential(self):
        popup = tk.Toplevel(self.master)
        popup.title("Add Credential")
        popup.geometry("300x200")
        popup.transient(self.master)
        popup.grab_set()
        self.center_popup(popup)

        tk.Label(popup, text="ID").pack()
        id_entry = tk.Entry(popup)
        id_entry.pack()

        tk.Label(popup, text="Password").pack()
        pwd_entry = tk.Entry(popup)  # Now visible while typing
        pwd_entry.pack()

        tk.Label(popup, text="Extra (optional)").pack()
        extra_entry = tk.Entry(popup)
        extra_entry.pack()

        def save():
            uid = id_entry.get()
            pwd = pwd_entry.get()
            extra = extra_entry.get() or ""
            if uid and pwd:
                enc_uid = encrypt(uid, self.key)
                enc_pwd = encrypt(pwd, self.key)
                enc_extra = encrypt(extra, self.key)

                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute("INSERT INTO vault (user_id, password, extra) VALUES (?, ?, ?)", (enc_uid, enc_pwd, enc_extra))
                conn.commit()
                conn.close()
                self.load_credentials()
                popup.destroy()
            else:
                messagebox.showerror("Error", "ID and Password are required.", parent=popup)

        tk.Button(popup, text="Save", command=save).pack(pady=10)

    def load_credentials(self):
        for i in self.tree.get_children():
            self.tree.delete(i)

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT user_id, password, extra FROM vault")
        rows = c.fetchall()
        conn.close()

        for r in rows:
            try:
                uid = decrypt(r[0], self.key)
                pwd = decrypt(r[1], self.key)
                extra = decrypt(r[2], self.key)
                self.tree.insert('', tk.END, values=(uid, pwd, extra))
            except:
                continue

# Entry Point

def main():
    init_db()
    root = tk.Tk()

    if not os.path.exists(KEY_PATH):
        pwd = simpledialog.askstring("Setup", "Set Master Password", show='*', parent=root)
        if not pwd:
            messagebox.showerror("Error", "Password required.", parent=root)
            root.destroy()
            return
        save_password_hash(pwd)
        key = derive_key(pwd)
        messagebox.showinfo("Success", "Password set. Restart app to login.", parent=root)
        root.destroy()
    else:
        pwd = simpledialog.askstring("Login", "Enter Master Password", show='*', parent=root)
        if not pwd or not check_password(pwd):
            messagebox.showerror("Error", "Invalid password.", parent=root)
            root.destroy()
        else:
            key = derive_key(pwd)
            VaultApp(root, key)
            root.mainloop()

if __name__ == "__main__":
    main()