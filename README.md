# CyberCrypt

It is a command‑line cybersecurity tool designed for ethical hackers and penetration testers. It aims to deliver secure data transformation, robust hashing operations, and encryption algorithms (AES and RSA). CyberCrypt supports a comprehensive range of operations, including encoding,decoding, hashing, and unhashing. It supports all operating systems (Linux, Windows, and MacOs)

## Installation

### Prerequisites
- Python 3.6 or higher

### Installation Steps
1. Clone the repository: `git clone https://github.com/UwimanaMuhiziElie/cybercrypt.git`
2. Navigate to the project directory: `cd cybercrypt`
3. Install CyberCrypt: `python setup.py install`

## Usage
- For usage instructions, run `python main.py --help`

## Examples
- **Encrypt data using base64**: 
  - Demonstration: This command will encode the string "hello world" using the base64 algorithm.
  - Example: `python main.py "hello world" --encode base64`

- **Decrypt data using base64**: 
  - Demonstration: This command will decode the base64-encoded string "aGVsbG8gd29ybGQ=".
  - Example: `python main.py "aGVsbG8gd29ybGQ=" --decode base64`

- **Hash data using sha256**:
  - Demonstration: This command will hash the string "password123" using the SHA-256 algorithm.
  - Example: `python main.py "password123" --hash sha256`

- **Unhash data with wordlist using md5**:
  - Demonstration: This command will attempt to unhash the MD5 hash <hashed_data> using words from the wordlist file.
  - Example: `python main.py "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8" --unhash md5 --wordlist wordlist.txt`

- **Generating RSA-key-pair**:
  - Demonstration: This command will generate a RSA key pair (public and private keys).
  - Example: `python main.py --generate-rsa-keypair`

- **RSA encryption**:
  - Demonstration: This command will encrypt the string "secret message" using RSA encryption and the specified public key.
  - Example: `python main.py --rsa-encrypt "secret message" --public-key public_key.pem`

- **RSA decryption**:
  - Demonstration: This command will decrypt the RSA-encrypted data using the specified private key.
  - Example: `python main.py --rsa-decrypt <encrypted_data> --private-key private_key.pem`

## Troubleshooting
- If you encounter any issues, please [open an issue](https://github.com/UwimanaMuhiziElie/cybercrypt/issues) on GitHub.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
