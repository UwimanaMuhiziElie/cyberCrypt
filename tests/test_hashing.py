import pytest
from core.hasher import hash_data

def test_md5_hashing():
    assert hash_data("Hello everyone !", "md5") == '256bfbf03761493e03893cd9909f4170'

def test_sha1_hashing():
    assert hash_data("we are cybersecurity community!!", "sha1") == 'c7c33ef65400f640e504bbd463d342e2c06ef66e'

def test_sha256_hashing():
    assert hash_data("we offensive security Engineers", "sha256") == 'fb7bced8fb91342996fde322f01ef1bebb68f7c0e4a98026e62d96d292189cc8'

def test_sha512_hashing():
    assert hash_data("HelloHackers From India", "sha512") == 'c816cbbdf29ab20a952668689ba594e20e06de7d1842cdc90f4a6d9dddd02172e98c3cf64144087fc59c6a025107f8cc47248df64e9fac4774d3324de6f786de'

def test_sha3_256_hashing():
    assert hash_data("I love offensive security!", "sha3_256") == '18bcec6b573cd40ee1b522016d76fc8c7d987de96d545045e403825f88607e66'

def test_bcrypt_hashing():
    hashed_data = hash_data("we are hackers!", "bcrypt")
    assert hashed_data.startswith('$2b$12$')  # bcrypt hashes include a version, cost factor, and 22-character salt
