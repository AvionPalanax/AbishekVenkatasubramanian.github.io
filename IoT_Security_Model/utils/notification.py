import os
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv

load_dotenv()

def send_email_alert(device_id, score, violations):
    sender = os.getenv("GMAIL_USER")
    password = os.getenv("GMAIL_PASSWORD")
    recipient = os.getenv("ALERT_TO")

    subject = f"[ALERT] Device Quarantined - {device_id}"
    body = f"""
    ⚠️ A device has been automatically quarantined.
    
    Device ID: {device_id}
    Anomaly Score: {score:.2f}
    Policy Violations: {violations}
    Action: Device Quarantined
    """

    msg = MIMEText(body)
    msg["From"] = sender
    msg["To"] = recipient
    msg["Subject"] = subject

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender, password)
            server.sendmail(sender, recipient, msg.as_string())
        print(f"[EMAIL SENT] Alert sent for {device_id}")
    except Exception as e:
        print(f"[EMAIL ERROR] Failed to send alert: {e}")
