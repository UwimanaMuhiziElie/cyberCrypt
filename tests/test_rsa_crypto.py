import pytest
from core.rsa_crypto import generate_rsa_keypair, rsa_encrypt, rsa_decrypt

@pytest.fixture(scope="module")
def rsa_keys():
    private_key, public_key = generate_rsa_keypair(passphrase="we are hackers!")
    return private_key, public_key

def test_generate_rsa_keypair(rsa_keys):
    private_key, public_key = rsa_keys
    assert private_key is not None
    assert public_key is not None

def test_rsa_encryption_decryption(rsa_keys):
    private_key, public_key = rsa_keys
    message = "Hello, hackers!"

    encrypted_message = rsa_encrypt(message, public_key)
    decrypted_message = rsa_decrypt(encrypted_message, private_key, passphrase="we are hackers!")

    assert decrypted_message == message
