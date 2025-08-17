#!/usr/bin/env python3
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import getpass

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive encryption key from password using PBKDF2"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_file(file_path: str, password: str):
    """Encrypt a file with AES-256"""
    # Generate random salt
    salt = os.urandom(16)
    
    # Derive key
    key = derive_key(password, salt)
    fernet = Fernet(key)
    
    # Read file data
    with open(file_path, 'rb') as f:
        file_data = f.read()
    
    # Encrypt and package with salt
    encrypted_data = salt + fernet.encrypt(file_data)
    
    # Save with .encrypted extension
    output_path = file_path + '.encrypted'
    with open(output_path, 'wb') as f:
        f.write(encrypted_data)
    
    print(f"🔒 Encrypted: {output_path}")

def decrypt_file(encrypted_path: str, password: str):
    """Decrypt a file"""
    # Read encrypted file
    with open(encrypted_path, 'rb') as f:
        encrypted_data = f.read()
    
    # Extract salt (first 16 bytes) and ciphertext
    salt, ciphertext = encrypted_data[:16], encrypted_data[16:]
    
    # Derive key
    key = derive_key(password, salt)
    fernet = Fernet(key)
    
    # Decrypt
    try:
        decrypted_data = fernet.decrypt(ciphertext)
        
        # Save decrypted file
        output_path = encrypted_path.replace('.encrypted', '.decrypted')
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)
        print(f"🔓 Decrypted: {output_path}")
    except:
        print("❌ Decryption failed! Wrong password or corrupted file.")

def main():
    print("🔐 File Vault - AES-256 Encryption")
    print("1. Encrypt file\n2. Decrypt file")
    choice = input("Choose (1/2): ")
    
    file_path = input("Enter file path: ")
    password = getpass.getpass("Enter password: ")
    
    if choice == '1':
        encrypt_file(file_path, password)
    elif choice == '2':
        decrypt_file(file_path, password)
    else:
        print("Invalid choice")

if __name__ == "__main__":
    main()
