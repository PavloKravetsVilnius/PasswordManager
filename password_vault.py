import json
from cryptography.fernet import InvalidToken
from crypto_manager import CryptoManager

class PasswordVault:
    """Handles persistence and retrieval of the user's encrypted passwords."""
    
    def __init__(self, filepath: str, key: bytes):
        self.filepath = filepath
        self.key = key
        self.passwords = []

    def load_data(self) -> bool:
        """Loads data from disk. Returns True if successful, False if corrupted."""
        try:
            json_data = CryptoManager.decrypt_data_from_file(self.filepath, self.key)
            self.passwords = json.loads(json_data)
            return True
        except InvalidToken:
            self.passwords = []
            return False
        except json.JSONDecodeError:
            self.passwords = []
            return True

    def save_data(self):
        """Saves current memory state to disk."""
        json_data = json.dumps(self.passwords)
        CryptoManager.encrypt_data_to_file(self.filepath, json_data, self.key)

    def add_entry(self, entry: dict):
        self.passwords.append(entry)
        self.save_data()

    def update_entry(self, title: str, new_entry: dict):
        for entry in self.passwords:
            if entry['Title'] == title:
                entry.update(new_entry)
                break
        self.save_data()

    def delete_entry(self, title: str):
        self.passwords = [e for e in self.passwords if e['Title'] != title]
        self.save_data()

    def get_all(self):
        return self.passwords