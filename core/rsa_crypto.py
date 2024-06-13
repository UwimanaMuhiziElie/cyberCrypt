import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

def generate_rsa_keypair(key_size=2048, passphrase=None):
    """
    Generate an RSA key pair with the specified key size.
    Optionally encrypt the private key with a passphrase.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )

    encryption_algorithm = serialization.BestAvailableEncryption(passphrase.encode()) if passphrase else serialization.NoEncryption()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm
    )

    public_pem = private_key.public_key().public_bytes(
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

def rsa_encrypt(data, public_key_pem, padding_scheme='OAEP'):
    """
    Encrypt data using the RSA public key and specified padding scheme.
    """
    public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())

    if padding_scheme == 'OAEP':
        chosen_padding = padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    elif padding_scheme == 'PKCS1v15':
        chosen_padding = padding.PKCS1v15()
    else:
        raise ValueError(f"Unsupported padding scheme: {padding_scheme}")

    encrypted_data = public_key.encrypt(
        data.encode(),
        chosen_padding
    )
    return encrypted_data

def rsa_decrypt(encrypted_data, private_key_pem, passphrase=None, padding_scheme='OAEP'):
    """
    Decrypt data using the RSA private key and specified padding scheme.
    """
    if isinstance(passphrase, str):
        passphrase = passphrase.encode() 

    private_key = serialization.load_pem_private_key(private_key_pem, password=passphrase, backend=default_backend())

    if padding_scheme == 'OAEP':
        chosen_padding = padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    elif padding_scheme == 'PKCS1v15':
        chosen_padding = padding.PKCS1v15()
    else:
        raise ValueError(f"Unsupported padding scheme: {padding_scheme}")

    decrypted_data = private_key.decrypt(
        encrypted_data,
        chosen_padding
    )
    return decrypted_data.decode()
