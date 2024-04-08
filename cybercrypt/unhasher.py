import hashlib
from multiprocessing import Pool

def unhash_data(hashed_data, hash_algorithm, wordlist):
    if hash_algorithm not in ['md5', 'sha1']:
        raise ValueError("Unhashing is not supported for the specified algorithm.")

    def hash_word(word):
        hashed_word = hashlib.new(hash_algorithm, word.encode()).hexdigest()
        if hashed_word == hashed_data:
            return word
        return None

    with open(wordlist, 'r') as file:
        wordlist = [word.strip() for word in file]

    with Pool() as pool:
        matched_word = pool.map(hash_word, wordlist)
    
    matched_word = [word for word in matched_word if word is not None]

    if matched_word:
        return matched_word[0]
    else:
        raise ValueError("Unable to unhash the provided data with the given wordlist.")



