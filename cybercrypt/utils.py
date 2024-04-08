import os
import getpass
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def secure_store_key(key, filename, passphrase=None):
    if passphrase:
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(passphrase.encode())
    with open(filename, 'wb') as file:
        file.write(key)

def secure_load_key(filename, passphrase=None):
    with open(filename, 'rb') as file:
        key = file.read()
    if passphrase:
        salt = key[:16]
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(passphrase.encode())
    return key

def get_passphrase(prompt='Enter passphrase: '):
    return getpass.getpass(prompt)

def prompt_passphrase(prompt='Enter passphrase: '):
    passphrase = get_passphrase(prompt)
    confirm_passphrase = getpass.getpass('Confirm passphrase: ')
    if passphrase != confirm_passphrase:
        raise ValueError('Passphrases do not match.')
    return passphrase

def aes_encrypt(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    return iv + encrypted_data

def aes_decrypt(encrypted_data, key):
    iv = encrypted_data[:16]
    encrypted_data = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    return decrypted_data

