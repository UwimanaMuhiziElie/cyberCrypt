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

