import os
from crypto_manager import CryptoManager

class UserService:
    """Handles User Registration and Authentication logic."""
    
    def __init__(self, users_file: str = "users.txt"):
        self.users_file = users_file

    def user_exists(self, username: str) -> bool:
        if not os.path.exists(self.users_file):
            return False
        with open(self.users_file, 'r') as f:
            return any(line.split(',')[0] == username for line in f)

    def register(self, username: str, password: str) -> bool:
        if self.user_exists(username):
            return False

        salt = os.urandom(16)
        hashed_pw = CryptoManager.hash_password(password, salt)

        with open(self.users_file, 'a') as f:
            f.write(f"{username},{salt.hex()},{hashed_pw}\n")
        
        # Initialize empty encrypted file for new user
        user_file = f"{username}_data.enc"
        key = CryptoManager.derive_key(password, salt)
        CryptoManager.encrypt_data_to_file(user_file, "[]", key)
        return True

    def login(self, username: str, password: str):
        """Returns (username, key, filepath) if successful, else None."""
        if not os.path.exists(self.users_file):
            return None

        with open(self.users_file, 'r') as f:
            for line in f:
                stored_user, stored_salt_hex, stored_hash = line.strip().split(',')
                if stored_user == username:
                    salt = bytes.fromhex(stored_salt_hex)
                    if CryptoManager.hash_password(password, salt) == stored_hash:
                        key = CryptoManager.derive_key(password, salt)
                        filepath = f"{username}_data.enc"
                        return username, key, filepath
        return None