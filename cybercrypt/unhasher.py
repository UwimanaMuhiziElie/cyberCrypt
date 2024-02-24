
# import hashlib

# def unhash(hash_type, hashed_value, wordlist_path):
#     with open(wordlist_path, 'r') as wordlist_file:
#         for word in wordlist_file:
#             word = word.strip()
#             if hash_type == 'md5':
#                 hash_object = hashlib.md5(word.encode()).hexdigest()
#             elif hash_type == 'sha1':
#                 hash_object = hashlib.sha1(word.encode()).hexdigest()
#             elif hash_type == 'sha256':
#                 hash_object = hashlib.sha256(word.encode()).hexdigest()
#             elif hash_type == 'sha512':
#                 hash_object = hashlib.sha512(word.encode()).hexdigest()
#             elif hash_type == 'sha3_256':
#                 hash_object = hashlib.sha3_256(word.encode()).hexdigest()
#             else:
#                 raise ValueError("[!] Unsupported hash type.")

#             if hash_object == hashed_value:
#                 return word
#     raise ValueError("[!] Unable to find the original value in the wordlist.")


# import hashlib
# from .hasher import hash_data

# def unhash(hash_type, hashed_value, wordlist_path):
#     with open(wordlist_path, 'r') as wordlist_file:
#         for word in wordlist_file:
#             word = word.strip()
#             hashed_word = hash_data(word, hash_type)
#             if hashed_word == hashed_value:
#                 return word
#     raise ValueError("[!] Unable to find the original value in the wordlist.")



import hashlib

def unhash(hash_type, hashed_value, wordlist_path):
    with open(wordlist_path, 'r') as wordlist_file:
        for word in wordlist_file:
            word = word.strip()
            if hash_type == 'md5':
                hashed_word = hashlib.md5(word.encode()).hexdigest()
            elif hash_type == 'sha1':
                hashed_word = hashlib.sha1(word.encode()).hexdigest()
            elif hash_type == 'sha256':
                hashed_word = hashlib.sha256(word.encode()).hexdigest()
            elif hash_type == 'sha512':
                hashed_word = hashlib.sha512(word.encode()).hexdigest()
            elif hash_type == 'sha3_256':
                hashed_word = hashlib.sha3_256(word.encode()).hexdigest()
            else:
                raise ValueError("[!] Unsupported hash type.")

            if hashed_word == hashed_value:
                return word
    raise ValueError("[!] Unable to find the original value in the wordlist.")
