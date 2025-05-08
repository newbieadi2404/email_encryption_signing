from key_utils import load_private_key, load_public_key
from crypto_utils import encrypt_message, sign_message
from email_utils import compose_email, send_email_via_smtp

# User inputs
msg = input("Enter the message to encrypt and send: ")
sender_email = input("Enter sender's email address (your Gmail): ")
receiver_email = input("Enter receiver's email address: ")
smtp_user = sender_email
smtp_pass = input("Enter your Gmail App Password (not your Gmail password!): ")

# Load keys
sender_private = load_private_key('sender')
receiver_public = load_public_key('receiver')

# Encrypt message
encrypted_msg = encrypt_message(msg, receiver_public)

# Sign the ORIGINAL message (plaintext)
signature = sign_message(msg, sender_private)

# Compose email with encrypted message and signature
email = compose_email(sender_email, receiver_email, 'Encrypted and Signed Email', encrypted_msg, signature)

# Send email via SMTP
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 465
send_email_via_smtp(email, SMTP_SERVER, SMTP_PORT, smtp_user, smtp_pass)

print("Encrypted and signed email sent!")
