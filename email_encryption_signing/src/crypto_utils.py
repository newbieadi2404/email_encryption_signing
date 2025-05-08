import rsa
import base64

def encrypt_message(message: str, public_key) -> str:
    encrypted = rsa.encrypt(message.encode('utf-8'), public_key)
    return base64.b64encode(encrypted).decode('utf-8')

def decrypt_message(encrypted_b64: str, private_key) -> str:
    encrypted = base64.b64decode(encrypted_b64.encode('utf-8'))
    decrypted = rsa.decrypt(encrypted, private_key)
    return decrypted.decode('utf-8')

def sign_message(message: str, private_key) -> str:
    signature = rsa.sign(message.encode('utf-8'), private_key, 'SHA-256')
    return base64.b64encode(signature).decode('utf-8')

def verify_signature(message: str, signature_b64: str, public_key) -> bool:
    signature = base64.b64decode(signature_b64.encode('utf-8'))
    try:
        rsa.verify(message.encode('utf-8'), signature, public_key)
        return True
    except rsa.VerificationError:
        return False
