
# IoT Security Dashboard 🚨🔐

This project provides a real-time IoT Security Dashboard for monitoring MQTT traffic, detecting anomalies using an LSTM model, enforcing security policies, and generating password-protected PDF reports.

---

## 📁 Project Structure

```
IoT_Security_Model/
│
├── app.py                         # Streamlit dashboard
├── mqtt_publisher.py              # Sends encrypted MQTT packets
├── mqtt_subscriber.py             # Subscribes to MQTT, logs & predicts anomalies
├── secure_log_manager.py          # Handles encryption of logs
├── pdf_generator_secure.py        # Generates encrypted PDF reports
├── generate_key.py                # Generates AES encryption key
│
├── key.key                        # AES encryption key (DO NOT share)
├── requirements.txt               # Required Python packages
│
├── certs/                         # TLS certificates for MQTT encryption
│
├── models/
│   └── lstm_anomaly_model.h5      # Trained LSTM model
│
├── logs/
│   ├── live_mqtt_log.csv          # Decrypted log (temporary)
│   └── live_mqtt_log.csv.enc      # Encrypted log file
│
└── utils/
    ├── predictor.py               # Anomaly prediction with LSTM
    └── encryption_utils.py        # Extra utilities (if used)
```

---

## 🛠️ Setup Instructions

1. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Generate encryption key (once)**
   ```bash
   python generate_key.py
   ```

3. **Run the MQTT Subscriber**
   ```bash
   python mqtt_subscriber.py
   ```

4. **Run the MQTT Publisher (in another terminal)**
   ```bash
   python mqtt_publisher.py
   ```

5. **Launch the Streamlit Dashboard**
   ```bash
   streamlit run app.py
   ```

---

## 🔐 Security Features

- TLS-secured MQTT connection (using `certs/`)
- Encrypted logs with AES (Fernet)
- PDF report generation with password protection (`iot@123`)
- Policy violation detection (VPN, MFA, Firewall)
- Threat auto-response (e.g., quarantine action)

---

## 📄 Offline Analysis

You can upload any CSV file via the dashboard for:
- Anomaly detection
- Policy violation checks
- Encrypted PDF report download

---

## 📌 Default Passwords

| Item          | Value      |
|---------------|------------|
| PDF Report    | `iot@123`  |

---

## 📬 Contact

For questions or contributions, feel free to reach out.

