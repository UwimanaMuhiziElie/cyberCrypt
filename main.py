import argparse
import pyfiglet
from colorama import Fore,init
from cybercrypt.input_validator import determine_input_type, validate_input
from cybercrypt.encoder import encode
from cybercrypt.decoder import decode
from cybercrypt.hasher import hash_data, bcrypt_hash
from cybercrypt.rsa_crypto import generate_rsa_keypair, rsa_encrypt, rsa_decrypt
from cybercrypt.unhasher import unhash
from cybercrypt.utils import aes_encrypt, aes_decrypt

init(autoreset=True)

def print_banner():
    banner_text = "cyberCrypt__"

    font_style = "slant"
    banner = pyfiglet.figlet_format(banner_text, font=font_style)
    print(Fore.YELLOW + banner)
    print(f"{Fore.YELLOW}***************************************************************")
    print()

def print_author_info():
    author_info = 'Author: El-scorpio | Contact: umuhizielie@gmail.com | Description: Red Teamer, Penetration tester, and bug bounty hunter with a passion for security research.'
    print(Fore.GREEN + author_info)
    print()

VERSION = "1.0.0"

def main():
    print_banner()
    print_author_info()                          
    parser = argparse.ArgumentParser(prog='cyberCrypt.py', usage='%(prog)s <data> [OPTIONS] <Arguments>', description="CyberCrypt is a versatile command-line tool designed for secure data transformation, encryption, and hashing operations.",
                                     epilog="For more information, visit https://github.com/uwimanaMuhiziElie/cyberCrypt")
    parser.add_argument("data", help="Input data to process")
    parser.add_argument("-enc", "--encode", choices=['base64', 'hex', 'url', 'html'], help="Encode the input data using specified algorithm (default: base64)")
    parser.add_argument("-dec", "--decode", choices=['base64', 'hex', 'url', 'html'], help="Decode the input data using specified algorithm (default: base64)")
    parser.add_argument("-hash", "--hash", choices=['md5', 'sha1', 'sha256', 'sha512', 'sha3_256', 'bcrypt'], help="Hash the input data using specified algorithm (default: sha256)")
    parser.add_argument("-uh", "--unhash", choices=['md5', 'sha1', 'sha256', 'sha512', 'sha3_256'],help="Unhash a hashed string using specified algorithm")
    parser.add_argument("-w", "--wordlist", help="Path to a wordlist for unhashing")
    parser.add_argument("--generate-rsa-keypair", action="store_true", help="Generate RSA key pair (public and private key)")
    parser.add_argument("--rsa-encrypt", action="store_true", help="Encrypt data using RSA (requires --public-key)")
    parser.add_argument("--rsa-decrypt", action="store_true", help="Decrypt data using RSA (requires --private-key)")
    parser.add_argument("--public-key", help="Path to RSA public key (for encryption)")
    parser.add_argument("--private-key", help="Path to RSA private key (for decryption)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode, providing detailed output")
    parser.add_argument('--version', action='version', version='%(prog)s ' + VERSION)
    args = parser.parse_args()

    input_type = determine_input_type(args.data)
    print("[+] Input type is >> " + input_type)

    try:
        if args.encode:
            encoded_data = encode(args.data.encode(), args.encode)
            print(f"{Fore.YELLOW}[+]{args.encode} encoding: {encoded_data}")

        if args.decode:
            decoded_data = decode(args.data, args.decode)
            print(f"{Fore.YELLOW}[+] {args.decode} decoding: {decoded_data}")

        if args.hash:
            hashed_data = hash_data(args.data, args.hash)
            print(f"{Fore.YELLOW}[+] {args.hash} algorithm string: {hashed_data}")

        if args.unhash:
            if not args.wordlist:
                raise ValueError("{Fore.YELLOW}[!] Please provide a wordlist path for unhashing.")
            original_data = unhash(args.data, args.unhash, args.wordlist)
            print(f"{Fore.YELLOW}[+] {args.unhash} unhash: {original_data}")


        if args.generate_rsa_keypair:
            private_key_pem, public_key_pem = generate_rsa_keypair()
            print("{Fore.YELLOW}[+]RSA Key Pair Generated.")
            # Save private_key_pem and public_key_pem securely for future use.

        if args.rsa_encrypt:
            if not args.public_key:
                raise ValueError("{Fore.YELLOW}[!] Please provide a public key for RSA encryption.")
            encrypted_data = rsa_encrypt(args.data, args.public_key)
            print(f"{Fore.YELLOW}[+] RSA Encrypted Data: {encrypted_data.hex()}")

        if args.rsa_decrypt:
            if not args.private_key:
                raise ValueError("{Fore.YELLOW}[!] Please provide a private key for RSA decryption.")
            decrypted_data = rsa_decrypt(bytes.fromhex(args.data), args.private_key)
            print(f"{Fore.YELLOW}[+] RSA Decrypted Data: {decrypted_data}")

    except ValueError as e:
        print(Fore.RED + str(e))

if __name__ == "__main__":
    main()
