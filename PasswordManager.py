import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import json
import os
import base64
import secrets
import string
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

USERS_FILE = "users.txt"

class CryptoManager:
    """Handles all hashing, key derivation, and AES encryption operations."""
    
    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        """Derives a secure AES key from a password using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    @staticmethod
    def hash_password(password: str, salt: bytes) -> str:
        """Hashes a password for secure storage using PBKDF2."""
        key = CryptoManager.derive_key(password, salt)
        return key.decode('utf-8')

    @staticmethod
    def encrypt_text(text: str, key: bytes) -> str:
        """Encrypts a single string using AES (Fernet)."""
        f = Fernet(key)
        return f.encrypt(text.encode()).decode('utf-8')

    @staticmethod
    def decrypt_text(encrypted_text: str, key: bytes) -> str:
        """Decrypts a single string using AES (Fernet)."""
        f = Fernet(key)
        return f.decrypt(encrypted_text.encode()).decode('utf-8')

    @staticmethod
    def encrypt_data_to_file(filepath: str, data: str, key: bytes):
        """Encrypts a string blob and writes it directly to disk."""
        f = Fernet(key)
        encrypted = f.encrypt(data.encode('utf-8'))
        with open(filepath, 'wb') as file:
            file.write(encrypted)

    @staticmethod
    def decrypt_data_from_file(filepath: str, key: bytes) -> str:
        """Reads encrypted bytes from disk and decrypts them in memory."""
        if not os.path.exists(filepath):
            return "[]"  # Return empty JSON array if file doesn't exist
        f = Fernet(key)
        with open(filepath, 'rb') as file:
            encrypted = file.read()
        return f.decrypt(encrypted).decode('utf-8')


class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Password Manager")
        self.root.geometry("700x500")
        
        self.current_user = None
        self.encryption_key = None
        self.data_filepath = None
        self.passwords = [] # List of dicts: Title, EncryptedPassword, URL, Notes

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.show_login_screen()

    # --- UI ROUTING ---
    def clear_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def show_login_screen(self):
        self.clear_screen()
        
        frame = tk.Frame(self.root, padx=20, pady=20)
        frame.pack(expand=True)

        tk.Label(frame, text="Login / Register", font=("Arial", 16, "bold")).grid(row=0, column=0, columnspan=2, pady=10)
        
        tk.Label(frame, text="Username:").grid(row=1, column=0, pady=5, sticky="e")
        self.entry_username = tk.Entry(frame)
        self.entry_username.grid(row=1, column=1, pady=5)

        tk.Label(frame, text="Master Password:").grid(row=2, column=0, pady=5, sticky="e")
        self.entry_password = tk.Entry(frame, show="*")
        self.entry_password.grid(row=2, column=1, pady=5)

        tk.Button(frame, text="Login", command=self.login, width=15).grid(row=3, column=0, pady=15)
        tk.Button(frame, text="Register", command=self.register, width=15).grid(row=3, column=1, pady=15)

    def show_main_screen(self):
        self.clear_screen()
        
        # Header
        header_frame = tk.Frame(self.root)
        header_frame.pack(fill="x", padx=10, pady=5)
        tk.Label(header_frame, text=f"Welcome, {self.current_user}", font=("Arial", 12, "bold")).pack(side="left")
        tk.Button(header_frame, text="Logout", command=self.logout).pack(side="right")

        # Table
        self.tree = ttk.Treeview(self.root, columns=("Title", "URL", "Notes"), show="headings", height=10)
        self.tree.heading("Title", text="Title")
        self.tree.heading("URL", text="URL")
        self.tree.heading("Notes", text="Notes")
        self.tree.pack(fill="both", expand=True, padx=10, pady=5)

        # Controls
        control_frame = tk.Frame(self.root)
        control_frame.pack(fill="x", padx=10, pady=10)

        tk.Button(control_frame, text="Add Entry", command=self.add_entry_dialog).grid(row=0, column=0, padx=5, pady=5)
        tk.Button(control_frame, text="Update Entry", command=self.update_entry_dialog).grid(row=0, column=1, padx=5, pady=5)
        tk.Button(control_frame, text="Delete Entry", command=self.delete_entry).grid(row=0, column=2, padx=5, pady=5)
        
        tk.Button(control_frame, text="Reveal Password", command=self.reveal_password).grid(row=1, column=0, padx=5, pady=5)
        tk.Button(control_frame, text="Copy to Clipboard", command=self.copy_password).grid(row=1, column=1, padx=5, pady=5)
        tk.Button(control_frame, text="Generate Random", command=self.generate_random_password).grid(row=1, column=2, padx=5, pady=5)

        # Search
        search_frame = tk.Frame(self.root)
        search_frame.pack(fill="x", padx=10, pady=5)
        tk.Label(search_frame, text="Search by Title:").pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", self.filter_treeview)
        tk.Entry(search_frame, textvariable=self.search_var).pack(side="left", padx=5)

        self.load_data()
        self.refresh_treeview()

    # --- AUTHENTICATION ---
    def register(self):
        username = self.entry_username.get().strip()
        password = self.entry_password.get().strip()

        if not username or not password:
            messagebox.showerror("Error", "Please fill in all fields.")
            return

        if os.path.exists(USERS_FILE):
            with open(USERS_FILE, 'r') as f:
                if any(line.split(',')[0] == username for line in f):
                    messagebox.showerror("Error", "Username already exists.")
                    return

        salt = os.urandom(16)
        hashed_pw = CryptoManager.hash_password(password, salt)

        with open(USERS_FILE, 'a') as f:
            f.write(f"{username},{salt.hex()},{hashed_pw}\n")
        
        # Initialize empty encrypted file for new user
        user_file = f"{username}_data.enc"
        key = CryptoManager.derive_key(password, salt)
        CryptoManager.encrypt_data_to_file(user_file, "[]", key) # Save empty JSON array

        messagebox.showinfo("Success", "Registration successful! You can now log in.")
        self.entry_password.delete(0, 'end')

    def login(self):
        username = self.entry_username.get().strip()
        password = self.entry_password.get().strip()

        if not os.path.exists(USERS_FILE):
            messagebox.showerror("Error", "No users registered yet.")
            return

        with open(USERS_FILE, 'r') as f:
            for line in f:
                stored_user, stored_salt_hex, stored_hash = line.strip().split(',')
                if stored_user == username:
                    salt = bytes.fromhex(stored_salt_hex)
                    if CryptoManager.hash_password(password, salt) == stored_hash:
                        self.current_user = username
                        self.encryption_key = CryptoManager.derive_key(password, salt)
                        self.data_filepath = f"{username}_data.enc"
                        
                        self.show_main_screen()
                        return
                    
        messagebox.showerror("Error", "Invalid username or password.")
        self.entry_password.delete(0, 'end')

    def logout(self):
        if self.current_user:
            self.save_data()
            self.current_user = None
            self.encryption_key = None
            self.data_filepath = None
            self.passwords = []
        self.show_login_screen()

    def on_closing(self):
        if self.current_user:
            self.save_data()
        self.root.destroy()

    # --- DATA MANAGEMENT (IN-MEMORY) ---
    def load_data(self):
        try:
            json_data = CryptoManager.decrypt_data_from_file(self.data_filepath, self.encryption_key)
            self.passwords = json.loads(json_data)
        except InvalidToken:
            messagebox.showerror("Critical Error", "Data decryption failed. File may be corrupted.")
            self.passwords = []
        except json.JSONDecodeError:
            self.passwords = []

    def save_data(self):
        if self.current_user and self.encryption_key:
            json_data = json.dumps(self.passwords)
            CryptoManager.encrypt_data_to_file(self.data_filepath, json_data, self.encryption_key)

    def refresh_treeview(self, filter_text=""):
        for row in self.tree.get_children():
            self.tree.delete(row)
        for entry in self.passwords:
            if filter_text.lower() in entry['Title'].lower():
                self.tree.insert("", "end", values=(entry['Title'], entry.get('URL', ''), entry.get('Notes', '')))

    def filter_treeview(self, *args):
        self.refresh_treeview(self.search_var.get())

    # --- FEATURES ---
    def add_entry_dialog(self):
        self._show_entry_form("Add Entry")

    def update_entry_dialog(self):
        selected = self.tree.focus()
        if not selected:
            messagebox.showwarning("Warning", "Select an entry to update.")
            return
        title = self.tree.item(selected)['values'][0]
        entry = next(e for e in self.passwords if e['Title'] == title)
        decrypted_pw = CryptoManager.decrypt_text(entry['EncryptedPassword'], self.encryption_key)
        self._show_entry_form("Update Entry", entry['Title'], decrypted_pw, entry.get('URL', ''), entry.get('Notes', ''), is_update=True)

    def _show_entry_form(self, action, t="", p="", u="", n="", is_update=False):
        top = tk.Toplevel(self.root)
        top.title(action)
        top.grab_set() # Prevent interacting with main window until closed
        
        tk.Label(top, text="Title:").grid(row=0, column=0, pady=5)
        title_entry = tk.Entry(top)
        title_entry.insert(0, t)
        title_entry.grid(row=0, column=1, pady=5)
        if is_update: title_entry.config(state='disabled')

        tk.Label(top, text="Password:").grid(row=1, column=0, pady=5)
        pass_entry = tk.Entry(top, show="*")
        pass_entry.insert(0, p)
        pass_entry.grid(row=1, column=1, pady=5)

        tk.Label(top, text="URL:").grid(row=2, column=0, pady=5)
        url_entry = tk.Entry(top)
        url_entry.insert(0, u)
        url_entry.grid(row=2, column=1, pady=5)

        tk.Label(top, text="Notes:").grid(row=3, column=0, pady=5)
        notes_entry = tk.Entry(top)
        notes_entry.insert(0, n)
        notes_entry.grid(row=3, column=1, pady=5)

        def save():
            title = title_entry.get().strip()
            password = pass_entry.get()
            if not title or not password:
                messagebox.showerror("Error", "Title and Password are required.", parent=top)
                return

            enc_pw = CryptoManager.encrypt_text(password, self.encryption_key)
            
            if is_update:
                for entry in self.passwords:
                    if entry['Title'] == title:
                        entry['EncryptedPassword'] = enc_pw
                        entry['URL'] = url_entry.get()
                        entry['Notes'] = notes_entry.get()
            else:
                if any(e['Title'].lower() == title.lower() for e in self.passwords):
                    messagebox.showerror("Error", "Title already exists.", parent=top)
                    return
                self.passwords.append({
                    "Title": title, "EncryptedPassword": enc_pw,
                    "URL": url_entry.get(), "Notes": notes_entry.get()
                })
            
            self.save_data()
            self.refresh_treeview()
            top.destroy()

        tk.Button(top, text="Save", command=save).grid(row=4, column=0, columnspan=2, pady=10)

    def delete_entry(self):
        selected = self.tree.focus()
        if not selected:
            messagebox.showwarning("Warning", "Select an entry to delete.")
            return
        title = self.tree.item(selected)['values'][0]
        if messagebox.askyesno("Confirm", f"Delete password for '{title}'?"):
            self.passwords = [e for e in self.passwords if e['Title'] != title]
            self.save_data()
            self.refresh_treeview()

    def reveal_password(self):
        selected = self.tree.focus()
        if not selected: return
        title = self.tree.item(selected)['values'][0]
        entry = next(e for e in self.passwords if e['Title'] == title)
        decrypted_pw = CryptoManager.decrypt_text(entry['EncryptedPassword'], self.encryption_key)
        messagebox.showinfo("Secure Reveal", f"Password for {title}:\n\n{decrypted_pw}")

    def clear_clipboard_timer(self):
        """Clears the clipboard after a delay."""
        self.root.clipboard_clear()
        # Optional: Show a subtle notification that clipboard was cleared.

    def copy_password(self):
        selected = self.tree.focus()
        if not selected: return
        title = self.tree.item(selected)['values'][0]
        entry = next(e for e in self.passwords if e['Title'] == title)
        decrypted_pw = CryptoManager.decrypt_text(entry['EncryptedPassword'], self.encryption_key)
        
        self.root.clipboard_clear()
        self.root.clipboard_append(decrypted_pw)
        messagebox.showinfo("Copied", "Password copied to clipboard!\n\nClipboard will clear in 10 seconds.")
        
        # Schedule clipboard clear after 10 seconds (10000 milliseconds)
        self.root.after(10000, self.clear_clipboard_timer)

    def generate_random_password(self):
        length = 16
        alphabet = string.ascii_letters + string.digits + string.punctuation
        pwd = ''.join(secrets.choice(alphabet) for _ in range(length))
        
        self.root.clipboard_clear()
        self.root.clipboard_append(pwd)
        messagebox.showinfo("Generated", f"Generated password:\n\n{pwd}\n\nCopied to clipboard. Will clear in 10s.")
        self.root.after(10000, self.clear_clipboard_timer)

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()