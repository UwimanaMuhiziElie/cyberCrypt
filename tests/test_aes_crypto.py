import pytest
from core.utils import aes_encrypt, aes_decrypt, secure_store_key, secure_load_key

@pytest.mark.asyncio
async def test_aes_encryption_decryption():
    key = b'thisistestaeskey'  # AES key must be either 16, 24, or 32 bytes long
    message = b"Hello, AES!"

    encrypted_message = aes_encrypt(message, key)
    decrypted_message = aes_decrypt(encrypted_message, key)

    assert decrypted_message == message

@pytest.mark.asyncio
async def test_secure_store_load_key(tmp_path):
    key = b'thisistestaeskey'  # AES key must be either 16, 24, or 32 bytes long
    passphrase = "securepass"
    key_file = tmp_path / "aes_key.bin"

    await secure_store_key(key, str(key_file), passphrase)
    loaded_key = await secure_load_key(str(key_file), passphrase)

    assert loaded_key == key
