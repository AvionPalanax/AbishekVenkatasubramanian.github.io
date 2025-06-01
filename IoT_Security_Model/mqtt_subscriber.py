
import paho.mqtt.client as mqtt
import json
import pandas as pd
import os
import ssl
from utils.predictor import predict_anomalies  # Make sure this is implemented and working
from secure_log_manager import encrypt_log_file  # Encryption utility
from utils.notification import send_email_alert
from datetime import datetime

# Configuration
BROKER = "broker.hivemq.com"
PORT = 8883  # Secure port for TLS
TOPIC = "iot/security/anomaly"
LOG_FILE = "logs/live_mqtt_log.csv"

# Ensure log folder exists
os.makedirs("logs", exist_ok=True)

# Create log file with headers if not present
if not os.path.exists(LOG_FILE) or os.path.getsize(LOG_FILE) == 0:
    pd.DataFrame(columns=["device_id", "anomaly_score", "mfa", "vpn", "firewall"]).to_csv(LOG_FILE, index=False)

# MQTT connection callback
def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print(f"[INFO] Connected to MQTT broker over TLS with result code {rc}")
        client.subscribe(TOPIC)
        print(f"[INFO] Subscribed to topic: {TOPIC}")
    else:
        print(f"[ERROR] Failed to connect. Result code: {rc}")

# MQTT message callback
def on_message(client, userdata, msg):
    try:
        payload = json.loads(msg.payload.decode())
        print(f"[RECEIVED] Payload: {payload}")

        # Convert to DataFrame
        input_df = pd.DataFrame([payload])

        # Predict anomaly score
        result = predict_anomalies(input_df, model_path="models/lstm_anomaly_model.pkl")

        print(f"[PREDICTED] Anomaly score: {result[0]}")

        # Log entry
        log_entry = {
            "device_id": payload.get("device_id", "Unknown"),
            "anomaly_score": round(result[0], 3),
            "mfa": payload.get("mfa", ""),
            "vpn": payload.get("vpn", ""),
            "firewall": payload.get("firewall", "")
        }

        # Append to CSV log
        df_log = pd.DataFrame([log_entry])
        df_log.to_csv(LOG_FILE, mode='a', header=False, index=False)
        print(f"[LOGGED] {log_entry}")

        # Quarantine logic
        device_id = log_entry["device_id"]
        blocked_path = "blocked_devices.json"
        if os.path.exists(blocked_path):
            with open(blocked_path, "r") as f:
                blocked_devices = set(json.load(f))
        else:
            blocked_devices = set()

        if device_id in blocked_devices:
            print(f"[BLOCKED] Skipping message from quarantined device: {device_id}")
            return

        policy_violations = sum([
            payload.get("vpn") == "no",
            payload.get("mfa") == "no",
            payload.get("firewall") == "no"
        ])

        if result[0] > 0.9 and policy_violations >= 2:
            print(f"[QUARANTINE] Device {device_id} quarantined.")
            blocked_devices.add(device_id)
            with open(blocked_path, "w") as f:
                json.dump(list(blocked_devices), f)

            send_email_alert(device_id, result[0], policy_violations)

            os.makedirs("logs", exist_ok=True)
            with open("logs/incident_actions.csv", "a") as logf:
                logf.write(f"{datetime.now()},{device_id},{result[0]:.2f},{policy_violations},Quarantined\n")

        # Encrypt the updated log file
        encrypt_log_file()
        print("[SECURE] Log file encrypted.")

    except Exception as e:
        print(f"[ERROR] Failed to process message: {e}")

def main():
    print("[INFO] Starting mqtt_subscriber.py script...")
    client = mqtt.Client()

    # Enable TLS with system-trusted CA certs
    client.tls_set(tls_version=ssl.PROTOCOL_TLSv1_2)
    client.tls_insecure_set(False)

    client.on_connect = on_connect
    client.on_message = on_message

    print("[INFO] Connecting securely to broker...")
    client.connect(BROKER, PORT, 60)

    client.loop_forever()

if __name__ == "__main__":
    main()
