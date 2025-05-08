import rsa
import os

KEYS_DIR = os.path.join(os.path.dirname(__file__), '..', 'keys')

def generate_and_save_keys(name: str):
    public_key, private_key = rsa.newkeys(2048)
    with open(os.path.join(KEYS_DIR, f'{name}_private.pem'), 'wb') as f:
        f.write(private_key.save_pkcs1('PEM'))
    with open(os.path.join(KEYS_DIR, f'{name}_public.pem'), 'wb') as f:
        f.write(public_key.save_pkcs1('PEM'))
    print(f"Keys for {name} generated and saved in {KEYS_DIR}")

def load_private_key(name: str):
    with open(os.path.join(KEYS_DIR, f'{name}_private.pem'), 'rb') as f:
        return rsa.PrivateKey.load_pkcs1(f.read())

def load_public_key(name: str):
    with open(os.path.join(KEYS_DIR, f'{name}_public.pem'), 'rb') as f:
        return rsa.PublicKey.load_pkcs1(f.read())

if __name__ == '__main__':
    os.makedirs(KEYS_DIR, exist_ok=True)
    generate_and_save_keys('sender')
    generate_and_save_keys('receiver')
