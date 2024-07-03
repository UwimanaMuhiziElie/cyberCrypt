# CyberCrypt

CyberCrypt is a command‑line cybersecurity tool designed for ethical hackers and penetration testers. It aims to deliver secure data transformation, robust hashing operations, and encryption algorithms (AES and RSA). it supports a comprehensive range of operations, including encoding, decoding, hashing, and unhashing. It supports all operating systems (Linux, Windows, and MacOs)

## Installation

### Prerequisites
- Python 3.6 or higher

### Installation Steps

#### Option 1: Install On Windows Os:
1. Clone the repository: `git clone https://github.com/UwimanaMuhiziElie/cybercrypt.git`
2. Navigate to the project directory: `cd cybercrypt`
3. Install CyberCrypt: `python setup.py install`

#### Option 2: Install on Linux (Kali Linux, Ubuntu tested):
1. Clone the repository: `git clone https://github.com/UwimanaMuhiziElie/cybercrypt.git`
2. Navigate to the project directory: `cd cybercrypt`
3. - Install all Requirements and dependencies:`pip install --user .`
   - Or with `sudo` for system-wide installation: `sudo pip install .` 
4. Test the tool: `python cybercrypt.py --help` 

#### Option 3: Install on MacOs:
1. Install Homebrew (if not already installed):`/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"`
2. Install python 3 and pip: `brew install python`
3. Clone the repository: `git clone https://github.com/UwimanaMuhiziElie/cybercrypt.git`
4. Navigate to the project directory: `cd cybercrypt`
5. Install Dependencies Using pip:`pip3 install --user .`
6. Test the tool: `python cybercrypt.py --help`
## Usage
- For usage instructions, run `python cybercrypt.py --help`

#### Using a Virtual Environment(linux or macos):
1. Create a virtual Environment: `python3 -m venv venv`
2. Activate the Virtual Environment: `source venv/bin/activate`
3. Install the package in the Virtual Environment: `pip install .`, `pip install --user .`, or `sudo pip install .`

## Examples
- **Encrypt data using base64**: 
  - Demonstration: This command will encode the string "hello world" using the base64 algorithm.
  - Example: `python cybercrypt.py "hello world" --encode base64`

- **Decrypt data using base64**: 
  - Demonstration: This command will decode the base64-encoded string "aGVsbG8gd29ybGQ=".
  - Example: `python cybercrypt.py "aGVsbG8gd29ybGQ=" --decode base64`

- **Hash data using sha256**:
  - Demonstration: This command will hash the string "password123" using the SHA-256 algorithm.
  - Example: `python cybercrypt.py "password123" --hash sha256`

- **Unhash data with wordlist using md5**:
  - Demonstration: This command will attempt to unhash the MD5 hash <hashed_data> using words from the wordlist file.
  - Example: `python cybercrypt.py "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8" --unhash md5 --wordlist wordlist.txt`

- **Generating RSA-key-pair**:
  - Demonstration: This command will generate a RSA key pair (public and private keys).
  - Example: `python cybercrypt.py --generate-rsa-keypair --key-size 2048 --passphrase "we are hackers!"`

- **RSA encryption**:
  - Demonstration: This command will encrypt the string "secret message" using RSA encryption and the specified public key.
  - Example: `python cybercrypt.py "secret message" --rsa-encrypt --public-key rsa_public.pem`

- **RSA decryption**:
  - Demonstration: This command will decrypt the RSA-encrypted data using the specified private key.
  - Example: `python cybercrypt.py <encrypted_data> --rsa-decrypt --private-key rsa_private.pem --passphrase "we are hackers!"`

- **AES encryption**:
  - Demonstration: This command will encrypt the string "secret message" using AES encryption and the specified key file.
  - Example: `python cybercrypt.py "secret message" --aes-encrypt --key-file aes_key.bin`

- **AES decryption**:
  - Demonstration: This command will decrypt the AES-encrypted data using the specified key file.
  - Example: `python cybercrypt.py <encrypted_data> --aes-decrypt --key-file aes_key.bin`

## Troubleshooting
- If you encounter any issues, please [open an issue](https://github.com/UwimanaMuhiziElie/cybercrypt/issues) on GitHub.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
