import tkinter as tk
from user_service import UserService
from app_ui import PasswordManagerApp

def main():
    # 1. Initialize core services
    user_service = UserService("users.txt")
    
    # 2. Initialize UI framework
    root = tk.Tk()
    
    # 3. Inject services into the application
    app = PasswordManagerApp(root, user_service)
    
    # 4. Start the application loop
    root.mainloop()

if __name__ == "__main__":
    main()