import subprocess
import pytest
from core.utils import secure_store_key, secure_load_key

def run_command(command):
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout, result.stderr

def test_cli_help():
    stdout, stderr = run_command("python cybercrypt.py --help")
    assert "usage: cyberCrypt.py" in stdout

def test_cli_base64_encode():
    stdout, stderr = run_command('python cybercrypt.py "Hello, World!" --encode base64')
    assert "SGVsbG8sIFdvcmxkIQ==" in stdout

def test_cli_base64_decode():
    stdout, stderr = run_command('python cybercrypt.py "SGVsbG8sIFdvcmxkIQ==" --decode base64')
    assert "Hello, World!" in stdout

def test_cli_hash_md5():
    stdout, stderr = run_command('python cybercrypt.py "Hello, World!" --hash md5')
    assert "65a8e27d8879283831b664bd8b7f0ad4" in stdout

def test_cli_rsa_generate_keypair():
    stdout, stderr = run_command("python cybercrypt.py --generate-rsa-keypair --passphrase 'we are hackers!'")
    assert "rsa_private.pem" in stdout
    assert "rsa_public.pem" in stdout

def test_cli_rsa_encrypt_decrypt():
    run_command("python cybercrypt.py --generate-rsa-keypair --passphrase 'we are hackers!'")
    message = "Hello, hackers!"
    stdout, stderr = run_command(f'python cybercrypt.py "{message}" --rsa-encrypt --public-key rsa_public.pem')
    encrypted_message = stdout.split("[+] RSA Encrypted Data: ")[-1].strip()
    stdout, stderr = run_command(f'python cybercrypt.py "{encrypted_message}" --rsa-decrypt --private-key rsa_private.pem --passphrase "we are hackers!"')
    decrypted_message = stdout.split("[+] RSA Decrypted Data: ")[-1].strip()
    assert message == decrypted_message

@pytest.mark.asyncio
async def test_cli_aes_encrypt_decrypt(tmp_path):
    key = b'thisistestaeskey'
    message = b"Hello, AES!"
    key_file = tmp_path / "aes_key.bin"

    await secure_store_key(key, str(key_file), "securepass")
    stdout, stderr = run_command(f'python cybercrypt.py "{message.decode()}" --aes-encrypt --key-file {str(key_file)}')
    encrypted_message = stdout.split("[+] AES Encrypted Data: ")[-1].strip()
    stdout, stderr = run_command(f'python cybercrypt.py "{encrypted_message}" --aes-decrypt --key-file {str(key_file)}')

    # Extract the decrypted message
    decrypted_message = stdout.split("[+] AES Decrypted Data: ")[-1].strip()
    assert message.decode() == decrypted_message