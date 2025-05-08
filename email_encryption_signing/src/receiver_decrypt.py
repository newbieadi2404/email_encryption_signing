from key_utils import load_private_key, load_public_key
from crypto_utils import decrypt_message, verify_signature

# Load keys
receiver_private = load_private_key('receiver')
sender_public = load_public_key('sender')

# Input encrypted message and signature
base64_encrypted = input("Paste the Encrypted Message (base64):\n").strip()
signature_b64 = input("Paste the Signature (base64):\n").strip()

# Fix padding for signature if needed
missing_padding = len(signature_b64) % 4
if missing_padding:
    signature_b64 += '=' * (4 - missing_padding)

# Decrypt message
try:
    decrypted_msg = decrypt_message(base64_encrypted, receiver_private)
    print("\nDecrypted message:", decrypted_msg)
except Exception as e:
    print("Error decrypting message:", e)
    exit(1)

# Verify signature on decrypted message
try:
    is_valid = verify_signature(decrypted_msg, signature_b64, sender_public)
    print("Signature valid:", is_valid)
except Exception as e:
    print("Error verifying signature:", e)
 
 #to run this command : python src/receiver_decrypt.py