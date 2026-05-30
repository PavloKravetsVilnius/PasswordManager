import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class CryptoManager:
    """Handles all hashing, key derivation, and AES encryption operations."""
    
    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    @staticmethod
    def hash_password(password: str, salt: bytes) -> str:
        key = CryptoManager.derive_key(password, salt)
        return key.decode('utf-8')

    @staticmethod
    def encrypt_text(text: str, key: bytes) -> str:
        f = Fernet(key)
        return f.encrypt(text.encode()).decode('utf-8')

    @staticmethod
    def decrypt_text(encrypted_text: str, key: bytes) -> str:
        f = Fernet(key)
        return f.decrypt(encrypted_text.encode()).decode('utf-8')

    @staticmethod
    def encrypt_data_to_file(filepath: str, data: str, key: bytes):
        f = Fernet(key)
        encrypted = f.encrypt(data.encode('utf-8'))
        with open(filepath, 'wb') as file:
            file.write(encrypted)

    @staticmethod
    def decrypt_data_from_file(filepath: str, key: bytes) -> str:
        if not os.path.exists(filepath):
            return "[]"  
        f = Fernet(key)
        with open(filepath, 'rb') as file:
            encrypted = file.read()
        return f.decrypt(encrypted).decode('utf-8')