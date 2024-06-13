import hashlib
import asyncio
from concurrent.futures import ProcessPoolExecutor

def hash_word(word, hash_algorithm, hashed_data):
    hashed_word = hashlib.new(hash_algorithm, word.encode()).hexdigest()
    if hashed_word == hashed_data:
        return word
    return None

async def unhash_data(hashed_data, hash_algorithm, wordlist_path):
    supported_algorithms = ['md5', 'sha1', 'sha256', 'sha512', 'sha3_256']
    if hash_algorithm not in supported_algorithms:
        raise ValueError("Unhashing is not supported for the specified algorithm.")
    
    # Read the wordlist asynchronously
    loop = asyncio.get_event_loop()
    with open(wordlist_path, 'r') as file:
        wordlist = await loop.run_in_executor(None, file.readlines)
    wordlist = [word.strip() for word in wordlist]

    # Use ProcessPoolExecutor for CPU-bound hashing operations
    with ProcessPoolExecutor() as executor:
        tasks = [loop.run_in_executor(executor, hash_word, word, hash_algorithm, hashed_data) for word in wordlist]
        results = await asyncio.gather(*tasks)
    
    matched_words = [result for result in results if result is not None]

    if matched_words:
        return matched_words[0]
    else:
        raise ValueError("Unable to unhash the provided data with the given wordlist.")
