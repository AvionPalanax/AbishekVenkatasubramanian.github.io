import streamlit as st
import pandas as pd
import numpy as np
import time
import os
from cryptography.fernet import Fernet
from utils.predictor import predict_anomalies
from pdf_generator import generate_pdf  # Updated import

st.set_page_config(layout="wide")
st.sidebar.title("IoT Security Dashboard Navigation")
page = st.sidebar.radio("Go to", ["Live Monitoring", "Offline Analysis"])

# --- Encryption Utilities ---
def load_key():
    with open("key.key", "rb") as key_file:
        return key_file.read()

def decrypt_log_file(enc_path="logs/live_mqtt_log.csv.enc", temp_path="logs/live_mqtt_temp.csv"):
    key = load_key()
    fernet = Fernet(key)
    with open(enc_path, "rb") as enc_file:
        decrypted = fernet.decrypt(enc_file.read())
    with open(temp_path, "wb") as dec_file:
        dec_file.write(decrypted)
    return temp_path

# --- Threat Response Logic ---
def apply_threat_response(df):
    df['policy_violations'] = ((df['vpn'] == 0).astype(int) +
                               (df['mfa'] == 0).astype(int) +
                               (df['firewall'] == 0).astype(int))

    df['threat_level'] = np.where(
        (df['anomaly_score'] > 0.9) & (df['policy_violations'] >= 2),
        'High', 'Normal'
    )

    df['auto_action'] = np.where(
        df['threat_level'] == 'High', 'Device Quarantined', 'None'
    )
    return df

# --- Page 1: Live Monitoring ---
if page == "Live Monitoring":
    st.title("\U0001F4E1 Live MQTT Monitoring")
    refresh_rate = st.sidebar.slider("Refresh interval (seconds)", 5, 60, 10)

    try:
        decrypted_path = decrypt_log_file()
        live_data = pd.read_csv(decrypted_path).copy()  # force detach from file
        time.sleep(0.5)  # give OS a moment to release the lock
        os.remove(decrypted_path)


        live_data["device_id"] = [f"Device_{i}" for i in range(len(live_data))]

        st.subheader("\U0001F4CA Anomalies in Recent MQTT Packets")
        window_sizes = [10, 20, 50, 100]
        cols = st.columns(len(window_sizes))
        for i, w in enumerate(window_sizes):
            recent = live_data.tail(w)
            count = (recent["anomaly_score"] > 0.5).sum()
            cols[i].metric(f"Last {w} Packets", f"{count}")

        if 'timestamp' not in live_data.columns:
            live_data['timestamp'] = pd.date_range(end=pd.Timestamp.now(), periods=len(live_data), freq='s')
        live_data['timestamp'] = pd.to_datetime(live_data['timestamp'], errors='coerce')
        live_data = live_data.dropna(subset=['timestamp'])

        if not live_data.empty:
            st.line_chart(live_data.tail(100).set_index('timestamp')['anomaly_score'])

        st.dataframe(live_data.tail(10), use_container_width=True)

        st.subheader("\U0001F6A8 Policy Violations in MQTT")
        for col in ['vpn', 'mfa', 'firewall']:
            live_data[col] = live_data.get(col, 1)

        last_20 = live_data.tail(20)
        total_violations = ((last_20['vpn'] == 0) | (last_20['mfa'] == 0) | (last_20['firewall'] == 0)).sum()
        vpn_violations = (last_20['vpn'] == 0).sum()
        mfa_violations = (last_20['mfa'] == 0).sum()
        fw_violations = (last_20['firewall'] == 0).sum()

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Policy Violations (Last 20)", total_violations)
        col2.metric("VPN Violations", vpn_violations)
        col3.metric("MFA Violations", mfa_violations)
        col4.metric("Firewall Violations", fw_violations)

        live_data = apply_threat_response(live_data)
        st.subheader("\U0001F9E0 Threat Response Actions")
        st.dataframe(live_data[['device_id', 'anomaly_score', 'policy_violations', 'threat_level', 'auto_action']].tail(10))

        time.sleep(refresh_rate)
        st.rerun()

    except FileNotFoundError:
        st.warning("Encrypted MQTT log not found. Please ensure 'live_mqtt_log.csv.enc' exists.")

# --- Page 2: Offline Analysis ---
elif page == "Offline Analysis":
    st.title("\U0001F4C1 Offline Analysis from CSV")

    offline_file = st.file_uploader("Upload CSV", type="csv")
    if offline_file:
        df = pd.read_csv(offline_file)
        df["device_id"] = [f"Device_{i}" for i in range(len(df))]

        st.subheader("\U0001F50D Anomaly Detection")
        preds = predict_anomalies(df, "models/lstm_anomaly_model.h5")
        df['anomaly_score'] = preds
        anomalies = df[df['anomaly_score'] > 0.5]
        st.dataframe(anomalies[['device_id', 'anomaly_score']])

        total_packets = len(df)
        total_anomalies = len(anomalies)

        col_a, col_b = st.columns(2)
        col_a.metric("Total Packets Received", total_packets)
        col_b.metric("Total Anomalies Detected", total_anomalies)

        if 'timestamp' not in df.columns:
            df['timestamp'] = pd.date_range(end=pd.Timestamp.now(), periods=len(df), freq='s')

        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        df = df.dropna(subset=['timestamp'])

        if not df.empty:
            st.line_chart(df.tail(100).set_index('timestamp')['anomaly_score'])

        st.subheader("\U0001F6A8 Policy Violations")
        for col in ['vpn', 'mfa', 'firewall']:
            df[col] = df.get(col, 1)

        total_violations = ((df['vpn'] == 0) | (df['mfa'] == 0) | (df['firewall'] == 0)).sum()
        vpn_violations = (df['vpn'] == 0).sum()
        mfa_violations = (df['mfa'] == 0).sum()
        fw_violations = (df['firewall'] == 0).sum()

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Policy Violations", total_violations)
        col2.metric("VPN Violations", vpn_violations)
        col3.metric("MFA Violations", mfa_violations)
        col4.metric("Firewall Violations", fw_violations)

        violations = df[(df['vpn'] == 0) | (df['mfa'] == 0) | (df['firewall'] == 0)]
        st.dataframe(violations[['device_id', 'vpn', 'mfa', 'firewall']])

        df = apply_threat_response(df)
        st.subheader("\U0001F9E0 Threat Response Actions")
        st.dataframe(df[['device_id', 'anomaly_score', 'policy_violations', 'threat_level', 'auto_action']])

        st.subheader("\U0001F4C4 Download Report")
        pdf_bytes = generate_pdf(anomalies, violations, df)  # Returns encrypted PDF as bytes
        st.download_button("Download Encrypted PDF", data=pdf_bytes, file_name="report_protected.pdf")
