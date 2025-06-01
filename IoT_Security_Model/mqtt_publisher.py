import paho.mqtt.client as mqtt
import json
import time
import ssl
import random

# MQTT configuration
BROKER = "broker.hivemq.com"
PORT = 8883
TOPIC = "iot/security/anomaly"

# Create secure MQTT client
def create_secure_client():
    client = mqtt.Client()
    client.tls_set(tls_version=ssl.PROTOCOL_TLSv1_2)
    client.tls_insecure_set(False)
    return client

# Function to generate a normal/randomized packet
def generate_packet(device_id):
    return {
        "device_id": device_id,
        "feature1": round(random.uniform(0.1, 1.0), 2),
        "feature2": round(random.uniform(0.1, 1.0), 2),
        "mfa": random.choice(["yes", "no"]),
        "vpn": random.choice(["yes", "no"]),
        "firewall": random.choice(["yes", "no"])
    }

def main():
    client = create_secure_client()
    client.connect(BROKER, PORT, 60)
    client.loop_start()

    print("[PUBLISHER] Sending normal packets every 5 seconds...")

    i = 0
    while True:
        device_id = f"device_{i}"
        packet = generate_packet(device_id)
        payload = json.dumps(packet)
        client.publish(TOPIC, payload)
        print(f"[PUBLISHED] {payload}")
        time.sleep(5)
        i += 1

if __name__ == "__main__":
    main()
