import argparse
import pyfiglet
from colorama import Fore, init
import asyncio
from core.input_validator import determine_input_type, validate_input
from core.encoder import encode
from core.decoder import decode
from core.hasher import hash_data, hash_data_concurrently
from core.rsa_crypto import generate_rsa_keypair, rsa_encrypt, rsa_decrypt
from core.utils import aes_encrypt, aes_decrypt, wrap_key, unwrap_key, secure_store_key, secure_load_key
from core.unhasher import unhash_data

init(autoreset=True)

def print_banner():
    banner_text = "cyberCrypt__"
    font_style = "slant"
    banner = pyfiglet.figlet_format(banner_text, font=font_style)
    print(Fore.GREEN + banner)
    print(f"{Fore.GREEN}***************************************************************")
    print()

def print_author_info():
    author_info = 'Author: El13 | ping me at: www.linkedin.com/in/elie-uwimana'
    print(Fore.GREEN + author_info)
    print()

VERSION = "1.0.0"

async def main():
    print_banner()
    print_author_info()                          

    parser = argparse.ArgumentParser(prog='cyberCrypt.py', usage='%(prog)s <data> [OPTIONS] <Arguments>', description="CyberCrypt is a versatile command-line tool designed for secure data transformation, encryption, and hashing operations.",
                                     epilog="For more information, visit https://github.com/uwimanaMuhiziElie/cyberCrypt")
    parser.add_argument("--generate-rsa-keypair", action="store_true", help="Generate RSA key pair (public and private key)")
    parser.add_argument("--key-size", type=int, choices=[2048, 3072, 4096], default=2048, help="Specify RSA key size (default: 2048)")
    parser.add_argument("--passphrase", help="Passphrase for RSA key pair encryption")
    parser.add_argument("data", nargs='?', help="Input data to process")
    parser.add_argument("-enc", "--encode", choices=['base64', 'hex', 'url', 'html'], help="Encode the input data using specified algorithm (default: base64)")
    parser.add_argument("-dec", "--decode", choices=['base64', 'hex', 'url', 'html'], help="Decode the input data using specified algorithm (default: base64)")
    parser.add_argument("-hash", "--hash", choices=['md5', 'sha1', 'sha256', 'sha512', 'sha3_256', 'bcrypt'], help="Hash the input data using specified algorithm (default: sha256)")
    parser.add_argument("--concurrent-hash", action="store_true", help="Enable concurrent hashing")
    parser.add_argument("-w", "--wordlist", help="Path to a wordlist for unhashing")
    parser.add_argument("--rsa-encrypt", action="store_true", help="Encrypt data using RSA (requires --public-key)")
    parser.add_argument("--rsa-decrypt", action="store_true", help="Decrypt data using RSA (requires --private-key)")
    parser.add_argument("--public-key", help="Path to RSA public key (for encryption)")
    parser.add_argument("--private-key", help="Path to RSA private key (for decryption)")
    parser.add_argument("--padding", choices=['OAEP', 'PKCS1v15'], default='OAEP', help="Specify padding scheme for RSA operations (default: OAEP)")
    parser.add_argument("--wrap-key", action="store_true", help="Wrap a symmetric key")
    parser.add_argument("--unwrap-key", action="store_true", help="Unwrap a symmetric key")
    parser.add_argument("--wrapping-key", help="Path to the key used for wrapping/unwrapping")
    parser.add_argument("--key-to-wrap", help="The key to be wrapped (in hex format)")
    parser.add_argument("--wrapped-key", help="The wrapped key (in hex format)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode, providing detailed output")
    parser.add_argument('--version', action='version', version='%(prog)s ' + VERSION)
    args = parser.parse_args()

    if args.generate_rsa_keypair:
        generate_rsa_keypair(key_size=args.key_size, passphrase=args.passphrase)
        return

    if not args.data and not (args.wrap_key or args.unwrap_key):
        print(Fore.RED + "Error: No data provided.")
        return

    if args.data:
        input_type = determine_input_type(args.data)
        print("[+] Input type is >> " + input_type)

        try:
            if args.encode:
                encoded_data = encode(args.data.encode(), args.encode)
                print(f"{Fore.YELLOW}[+] {args.encode} encoding: {encoded_data}")

            if args.decode:
                decoded_data = decode(args.data, args.decode)
                print(f"{Fore.YELLOW}[+] {args.decode} decoding: {decoded_data}")

            if args.hash:
                if args.concurrent_hash:
                    hashed_data = hash_data_concurrently([args.data], args.hash)[0]
                else:
                    hashed_data = hash_data(args.data, args.hash)
                print(f"{Fore.YELLOW}[+] {args.hash} algorithm string: {hashed_data}")

            if args.wordlist:
                original_data = await unhash_data(args.data, args.hash, args.wordlist)
                print(f"{Fore.YELLOW}[+] {args.hash} unhash: {original_data}")

            if args.rsa_encrypt:
                if not args.public_key:
                    raise ValueError("{Fore.YELLOW}[!] Please provide a public key for RSA encryption.")
                with open(args.public_key, 'rb') as key_file:
                    public_key_pem = key_file.read()
                encrypted_data = rsa_encrypt(args.data, public_key_pem, args.padding)
                print(f"{Fore.YELLOW}[+] RSA Encrypted Data: {encrypted_data.hex()}")

            if args.rsa_decrypt:
                if not args.private_key:
                    raise ValueError("{Fore.YELLOW}[!] Please provide a private key for RSA decryption.")
                with open(args.private_key, 'rb') as key_file:
                    private_key_pem = key_file.read()
                passphrase = args.passphrase.encode() if args.passphrase else None
                decrypted_data = rsa_decrypt(bytes.fromhex(args.data), private_key_pem, passphrase=passphrase, padding_scheme=args.padding)
                print(f"{Fore.YELLOW}[+] RSA Decrypted Data: {decrypted_data}")

        except ValueError as e:
            print(Fore.RED + str(e))

    if args.wrap_key:
        if not args.wrapping_key or not args.key_to_wrap:
            raise ValueError("Please provide both --wrapping-key and --key-to-wrap.")
        with open(args.wrapping_key, 'rb') as key_file:
            wrapping_key = key_file.read()
        key_to_wrap = bytes.fromhex(args.key_to_wrap)
        wrapped_key = wrap_key(key_to_wrap, wrapping_key)
        print(f"{Fore.YELLOW}[+] Wrapped Key: {wrapped_key.hex()}")

    if args.unwrap_key:
        if not args.wrapping_key or not args.wrapped_key:
            raise ValueError("Please provide both --wrapping-key and --wrapped-key.")
        with open(args.wrapping_key, 'rb') as key_file:
            unwrapping_key = key_file.read()
        wrapped_key = bytes.fromhex(args.wrapped_key)
        unwrapped_key = unwrap_key(wrapped_key, unwrapping_key)
        print(f"{Fore.YELLOW}[+] Unwrapped Key: {unwrapped_key.hex()}")

if __name__ == "__main__":
    asyncio.run(main())
