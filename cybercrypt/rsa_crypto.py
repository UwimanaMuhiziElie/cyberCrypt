import os
import getpass
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

def generate_rsa_keypair(passphrase=None):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    if passphrase:
        encryption_algorithm = serialization.BestAvailableEncryption(passphrase.encode())
    else:
        encryption_algorithm = serialization.NoEncryption()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm
    )
    
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    with open("rsa_private.pem", "wb") as private_file:
        private_file.write(private_pem)
    print("[+] Private Key saved to 'rsa_private.pem'")

    with open("rsa_public.pem", "wb") as public_file:
        public_file.write(public_pem)
    print("[+] Public Key saved to 'rsa_public.pem'")
    
    return private_pem, public_pem

def rsa_encrypt(data, public_key_pem):
    public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
    encrypted_data = public_key.encrypt(
        data.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=padding.algorithms.SHA256()),
            algorithm=padding.algorithms.SHA256(),
            label=None
        )
    )
    return encrypted_data

def rsa_decrypt(encrypted_data, private_key_pem, passphrase=None):
    if passphrase:
        decryption_algorithm = serialization.BestAvailableEncryption(passphrase.encode())
    else:
        decryption_algorithm = serialization.NoEncryption()

    private_key = serialization.load_pem_private_key(private_key_pem, password=passphrase, backend=default_backend())
    decrypted_data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=padding.algorithms.SHA256()),
            algorithm=padding.algorithms.SHA256(),
            label=None
        )
    )
    return decrypted_data.decode()
