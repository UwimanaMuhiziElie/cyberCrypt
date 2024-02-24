# import hashlib
# import bcrypt


# HASH_ALGORITHMS = set(hashlib.algorithms_guaranteed) | {'sha3_256', 'sha512', 'bcrypt'}

# def hash_data(data, hash_algorithm):
#     if hash_algorithm == 'bcrypt':
#         return bcrypt_hash(data)
#     hasher = hashlib.new(hash_algorithm)
#     hasher.update(data.encode())
#     return hasher.hexdigest()

# def bcrypt_hash(data):
#     salt = bcrypt.gensalt()
#     hashed_data = bcrypt.hashpw(data.encode(), salt)
#     return hashed_data.decode()


import hashlib
import bcrypt

HASH_ALGORITHMS = set(hashlib.algorithms_guaranteed) | {'sha3_256', 'sha512', 'bcrypt'}

def hash_data(data, hash_algorithm):
    if hash_algorithm == 'bcrypt':
        return bcrypt_hash(data)
    elif hash_algorithm in HASH_ALGORITHMS:
        hasher = hashlib.new(hash_algorithm)
        hasher.update(data.encode())
        return hasher.hexdigest()
    else:
        raise ValueError("[!] Unsupported hash type.")

def bcrypt_hash(data):
    salt = bcrypt.gensalt()
    hashed_data = bcrypt.hashpw(data.encode(), salt)
    return hashed_data.decode()
