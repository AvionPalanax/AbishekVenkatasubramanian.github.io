from cryptography.fernet import Fernet

# Generate and save the key
key = Fernet.generate_key()
with open("key.key", "wb") as key_file:
    key_file.write(key)

print("[KEY] Encryption key generated and saved to 'key.key'")
