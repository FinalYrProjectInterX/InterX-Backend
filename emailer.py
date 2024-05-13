from email.message import EmailMessage
import smtplib
import ssl
from dotenv import load_dotenv
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

class EMAILER():
    def __init__(self) -> None:
        load_dotenv()
        self.EMAIL_ADDRESS = os.environ.get("EMAIL_ADD")
        self.EMAIL_PASSWORD = os.environ.get("EMAIL_PASS")
        self.MAIL_SERVER = "smtp.gmail.com"
        self.PORT = 465

    def send(self, subject, email, html_content) -> None:
        # Construct Secure Email
        ssl_context = ssl.create_default_context()
        msg = MIMEMultipart()
        msg["From"] = self.EMAIL_ADDRESS
        msg["To"] = email
        msg["Subject"] = subject

        # Attach HTML content
        html_part = MIMEText(html_content, "html")
        msg.attach(html_part)

        # Send Email
        with smtplib.SMTP_SSL(self.MAIL_SERVER, self.PORT, context=ssl_context) as smtp:
            smtp.login(self.EMAIL_ADDRESS, self.EMAIL_PASSWORD)
            smtp.send_message(msg)