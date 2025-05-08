from email.message import EmailMessage
import smtplib

def compose_email(sender: str, recipient: str, subject: str, encrypted_message: str, signature: str) -> EmailMessage:
    email = EmailMessage()
    email['From'] = sender
    email['To'] = recipient
    email['Subject'] = subject
    email.set_content(f"""Encrypted Message (base64):
{encrypted_message}

Signature (base64):
{signature}
""")
    return email

def parse_email(email: EmailMessage):
    lines = email.get_content().splitlines()
    encrypted_message = ""
    signature = ""
    in_encrypted = False
    in_signature = False
    for line in lines:
        if line.strip().startswith("Encrypted Message"):
            in_encrypted = True
            in_signature = False
            continue
        if line.strip().startswith("Signature"):
            in_signature = True
            in_encrypted = False
            continue
        if in_encrypted and line.strip():
            encrypted_message += line.strip()
        if in_signature and line.strip():
            signature += line.strip()
    return encrypted_message, signature

def send_email_via_smtp(email_message, smtp_server, smtp_port, smtp_user, smtp_pass):
    with smtplib.SMTP_SSL(smtp_server, smtp_port) as smtp:
        smtp.login(smtp_user, smtp_pass)
        smtp.send_message(email_message)
    print("Email sent successfully!")
