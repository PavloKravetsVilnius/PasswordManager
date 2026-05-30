import tkinter as tk
from tkinter import ttk, messagebox
import string
import secrets
from crypto_manager import CryptoManager
from password_vault import PasswordVault

class PasswordManagerApp:
    def __init__(self, root, user_service):
        self.root = root
        self.user_service = user_service
        self.root.title("Secure Password Manager")
        self.root.geometry("700x500")
        
        self.current_user = None
        self.vault = None  # Will hold a PasswordVault instance

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.show_login_screen()

    def clear_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    # --- UI: LOGIN SCREEN ---
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

    # --- UI: MAIN SCREEN ---
    def show_main_screen(self):
        self.clear_screen()
        
        header_frame = tk.Frame(self.root)
        header_frame.pack(fill="x", padx=10, pady=5)
        tk.Label(header_frame, text=f"Welcome, {self.current_user}", font=("Arial", 12, "bold")).pack(side="left")
        tk.Button(header_frame, text="Logout", command=self.logout).pack(side="right")

        self.tree = ttk.Treeview(self.root, columns=("Title", "URL", "Notes"), show="headings", height=10)
        self.tree.heading("Title", text="Title")
        self.tree.heading("URL", text="URL")
        self.tree.heading("Notes", text="Notes")
        self.tree.pack(fill="both", expand=True, padx=10, pady=5)

        control_frame = tk.Frame(self.root)
        control_frame.pack(fill="x", padx=10, pady=10)

        tk.Button(control_frame, text="Add Entry", command=self.add_entry_dialog).grid(row=0, column=0, padx=5, pady=5)
        tk.Button(control_frame, text="Update Entry", command=self.update_entry_dialog).grid(row=0, column=1, padx=5, pady=5)
        tk.Button(control_frame, text="Delete Entry", command=self.delete_entry).grid(row=0, column=2, padx=5, pady=5)
        
        tk.Button(control_frame, text="Reveal Password", command=self.reveal_password).grid(row=1, column=0, padx=5, pady=5)
        tk.Button(control_frame, text="Copy to Clipboard", command=self.copy_password).grid(row=1, column=1, padx=5, pady=5)
        tk.Button(control_frame, text="Generate Random", command=self.generate_random_password).grid(row=1, column=2, padx=5, pady=5)

        search_frame = tk.Frame(self.root)
        search_frame.pack(fill="x", padx=10, pady=5)
        tk.Label(search_frame, text="Search by Title:").pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", self.filter_treeview)
        tk.Entry(search_frame, textvariable=self.search_var).pack(side="left", padx=5)

        if not self.vault.load_data():
            messagebox.showerror("Critical Error", "Data decryption failed. File may be corrupted.")
        self.refresh_treeview()

    # --- ACTIONS ---
    def register(self):
        user = self.entry_username.get().strip()
        pwd = self.entry_password.get().strip()

        if not user or not pwd:
            messagebox.showerror("Error", "Please fill in all fields.")
            return

        if self.user_service.register(user, pwd):
            messagebox.showinfo("Success", "Registration successful! You can now log in.")
            self.entry_password.delete(0, 'end')
        else:
            messagebox.showerror("Error", "Username already exists.")

    def login(self):
        user = self.entry_username.get().strip()
        pwd = self.entry_password.get().strip()

        result = self.user_service.login(user, pwd)
        if result:
            self.current_user, key, filepath = result
            self.vault = PasswordVault(filepath, key)
            self.show_main_screen()
        else:
            messagebox.showerror("Error", "Invalid username or password.")
            self.entry_password.delete(0, 'end')

    def logout(self):
        self.current_user = None
        self.vault = None
        self.show_login_screen()

    def on_closing(self):
        self.root.destroy()

    def refresh_treeview(self, filter_text=""):
        for row in self.tree.get_children():
            self.tree.delete(row)
        for entry in self.vault.get_all():
            if filter_text.lower() in entry['Title'].lower():
                self.tree.insert("", "end", values=(entry['Title'], entry.get('URL', ''), entry.get('Notes', '')))

    def filter_treeview(self, *args):
        self.refresh_treeview(self.search_var.get())

    # --- CRUD ACTIONS ---
    def add_entry_dialog(self):
        self._show_entry_form("Add Entry")

    def update_entry_dialog(self):
        selected = self.tree.focus()
        if not selected:
            messagebox.showwarning("Warning", "Select an entry to update.")
            return
        title = self.tree.item(selected)['values'][0]
        entry = next(e for e in self.vault.get_all() if e['Title'] == title)
        decrypted_pw = CryptoManager.decrypt_text(entry['EncryptedPassword'], self.vault.key)
        self._show_entry_form("Update Entry", entry['Title'], decrypted_pw, entry.get('URL', ''), entry.get('Notes', ''), is_update=True)

    def _show_entry_form(self, action, t="", p="", u="", n="", is_update=False):
        top = tk.Toplevel(self.root)
        top.title(action)
        top.grab_set() 
        
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

            enc_pw = CryptoManager.encrypt_text(password, self.vault.key)
            new_data = {"Title": title, "EncryptedPassword": enc_pw, "URL": url_entry.get(), "Notes": notes_entry.get()}
            
            if is_update:
                self.vault.update_entry(title, new_data)
            else:
                if any(e['Title'].lower() == title.lower() for e in self.vault.get_all()):
                    messagebox.showerror("Error", "Title already exists.", parent=top)
                    return
                self.vault.add_entry(new_data)
            
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
            self.vault.delete_entry(title)
            self.refresh_treeview()

    # --- UTILITIES ---
    def get_selected_password(self):
        selected = self.tree.focus()
        if not selected: return None, None
        title = self.tree.item(selected)['values'][0]
        entry = next(e for e in self.vault.get_all() if e['Title'] == title)
        return title, CryptoManager.decrypt_text(entry['EncryptedPassword'], self.vault.key)

    def reveal_password(self):
        title, decrypted_pw = self.get_selected_password()
        if title:
            messagebox.showinfo("Secure Reveal", f"Password for {title}:\n\n{decrypted_pw}")

    def clear_clipboard_timer(self):
        self.root.clipboard_clear()

    def copy_password(self):
        title, decrypted_pw = self.get_selected_password()
        if title:
            self.root.clipboard_clear()
            self.root.clipboard_append(decrypted_pw)
            messagebox.showinfo("Copied", "Password copied to clipboard!\n\nClipboard will clear in 10 seconds.")
            self.root.after(10000, self.clear_clipboard_timer)

    def generate_random_password(self):
        alphabet = string.ascii_letters + string.digits + string.punctuation
        pwd = ''.join(secrets.choice(alphabet) for _ in range(16))
        self.root.clipboard_clear()
        self.root.clipboard_append(pwd)
        messagebox.showinfo("Generated", f"Generated password:\n\n{pwd}\n\nCopied to clipboard. Will clear in 10s.")
        self.root.after(10000, self.clear_clipboard_timer)