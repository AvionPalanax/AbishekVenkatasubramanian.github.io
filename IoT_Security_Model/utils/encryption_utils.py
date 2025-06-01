from cryptography.fernet import Fernet
import os

# Load or generate a key
key_path = "utils/secret.key"
if os.path.exists(key_path):
    with open(key_path, "rb") as key_file:
        key = key_file.read()
else:
    key = Fernet.generate_key()
    os.makedirs(os.path.dirname(key_path), exist_ok=True)
    with open(key_path, "wb") as key_file:
        key_file.write(key)

fernet = Fernet(key)

def encrypt_data(data: bytes) -> bytes:
    return fernet.encrypt(data)

def decrypt_data(encrypted_data: bytes) -> bytes:
    return fernet.decrypt(encrypted_data)
