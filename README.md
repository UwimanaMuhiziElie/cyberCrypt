
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
- For usage instructions, run `main.py --help`

## Examples
- **Encrypt data using base64**: 
This command will encode the string "hello world" using the base64 algorithm.
python main.py "hello world" --encode base64

- **Decrypt data using base64**: 
This command will decode the base64-encoded string "aGVsbG8gd29ybGQ=".
python main.py "aGVsbG8gd29ybGQ=" --decode base64


## Troubleshooting
- If you encounter any issues, please [open an issue](https://github.com/UwimanaMuhiziElie/cybercrypt/issues) on GitHub.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

