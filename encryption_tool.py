from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64

backend = default_backend()

def derive_key(password, salt):
    """Derive AES key from password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits
        salt=salt,
        iterations=100000,
        backend=backend
    )
    return kdf.derive(password.encode())

def encrypt_file(file_path, password):
    with open(file_path, 'rb') as f:
        data = f.read()

    salt = os.urandom(16)
    iv = os.urandom(16)
    key = derive_key(password, salt)

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    with open(file_path + ".enc", 'wb') as f:
        f.write(salt + iv + ciphertext)

    print("[+] File encrypted successfully!")

def decrypt_file(file_path, password):
    with open(file_path, 'rb') as f:
        content = f.read()

    salt = content[:16]
    iv = content[16:32]
    ciphertext = content[32:]
    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_plaintext) + unpadder.finalize()

    decrypted_path = file_path.replace(".enc", ".decrypted")
    with open(decrypted_path, 'wb') as f:
        f.write(data)

    print("[+] File decrypted successfully!")

# CLI Interface
if __name__ == "__main__":
    print("--- Advanced Encryption Tool (AES-256) ---")
    choice = input("1. Encrypt File\n2. Decrypt File\nEnter choice: ")

    if choice == "1":
        path = input("Enter file path to encrypt: ")
        password = input("Enter password: ")
        encrypt_file(path, password)

    elif choice == "2":
        path = input("Enter encrypted file path: ")
        password = input("Enter password: ")
        decrypt_file(path, password)

    else:
        print("Invalid option.")
