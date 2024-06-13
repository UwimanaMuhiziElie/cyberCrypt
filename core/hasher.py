import hashlib
import bcrypt
from concurrent.futures import ThreadPoolExecutor

HASH_ALGORITHMS = set(hashlib.algorithms_guaranteed) | {'sha3_256', 'sha512', 'bcrypt'}

def hash_data(data, hash_algorithm):
    if hash_algorithm == 'bcrypt':
        return bcrypt_hash(data)
    hasher = hashlib.new(hash_algorithm)
    hasher.update(data.encode())
    return hasher.hexdigest()

def bcrypt_hash(data):
    salt = bcrypt.gensalt()
    hashed_data = bcrypt.hashpw(data.encode(), salt)
    return hashed_data.decode()

def hash_data_concurrently(data_list, hash_algorithm):
    with ThreadPoolExecutor() as executor:
        results = list(executor.map(lambda data: hash_data(data, hash_algorithm), data_list))
    return results
