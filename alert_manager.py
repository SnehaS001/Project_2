from config import EMAIL_CONFIG
import smtplib
from email.mime.text import MIMEText
from datetime import datetime

def send_email_alert(subject, body):
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = EMAIL_CONFIG["sender"]
    msg["To"] = EMAIL_CONFIG["receiver"]

    with smtplib.SMTP(EMAIL_CONFIG["smtp_server"], EMAIL_CONFIG["smtp_port"]) as server:
        server.starttls()
        server.login(EMAIL_CONFIG["sender"], EMAIL_CONFIG["password"])
        server.sendmail(EMAIL_CONFIG["sender"], EMAIL_CONFIG["receiver"], msg.as_string())

def log_alert_to_file(message):
    with open("alerts.log", "a") as f:
        f.write(f"{datetime.now()}: {message}\n")