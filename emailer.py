from email.message import EmailMessage
import smtplib
import ssl
from dotenv import load_dotenv
import os




class EMAILER():

    def __init__(self) -> None:

        # Load Email Server with Credentials
        load_dotenv()
        self.EMAIL_ADDRESS = os.environ.get("EMAIL_ADD")
        self.EMAIL_PASSWORD = os.environ.get("EMAIL_PASS")
        self.MAIL_SERVER = "smtp.gmail.com"
        self.PORT = 465

    def send(self, subject, email, content) -> None:

        # Construct Secure Email
        ssl_context = ssl.create_default_context()
        msg = EmailMessage()
        msg["From"] = self.EMAIL_ADDRESS
        msg["To"] = email
        msg["Subject"] = subject
        msg.add_alternative(content, subtype="html")

        # Send Email
        with smtplib.SMTP_SSL(self.MAIL_SERVER, self.PORT, context=ssl_context) as smtp:
            smtp.login(self.EMAIL_ADDRESS, self.EMAIL_PASSWORD)
            smtp.send_message(msg)

