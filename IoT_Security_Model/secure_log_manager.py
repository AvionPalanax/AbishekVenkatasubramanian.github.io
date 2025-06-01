from cryptography.fernet import Fernet

def load_key():
    with open("key.key", "rb") as key_file:
        return key_file.read()

def encrypt_log_file(input_path="logs/live_mqtt_log.csv", output_path="logs/live_mqtt_log.csv.enc"):
    key = load_key()
    fernet = Fernet(key)

    with open(input_path, "rb") as file:
        original_data = file.read()

    encrypted_data = fernet.encrypt(original_data)

    with open(output_path, "wb") as enc_file:
        enc_file.write(encrypted_data)

    print(f"[ENCRYPTED] Log file saved to {output_path}")

def decrypt_log_file(encrypted_path="logs/live_mqtt_log.csv.enc", output_path="logs/live_mqtt_log_decrypted.csv"):
    key = load_key()
    fernet = Fernet(key)

    with open(encrypted_path, "rb") as enc_file:
        encrypted_data = enc_file.read()

    decrypted_data = fernet.decrypt(encrypted_data)

    with open(output_path, "wb") as dec_file:
        dec_file.write(decrypted_data)

    print(f"[DECRYPTED] Log file restored to {output_path}")

# ✅ Add this to trigger encryption when script is run directly
if __name__ == "__main__":
    encrypt_log_file()
