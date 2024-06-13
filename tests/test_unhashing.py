import pytest
from core.unhasher import unhash_data

# Path to the sample wordlist for testing
wordlist_path = 'C:\\Users\\muhiz\\OneDrive\\Documents\\wordlist_sample.txt'

@pytest.mark.asyncio
async def test_md5_unhashing():
    assert await unhash_data("8b1a9953c4611296a827abf8c47804d7", "md5", wordlist_path) == "Hello"

@pytest.mark.asyncio
async def test_sha1_unhashing():
    assert await unhash_data("78fd5cac8c025babdb453751f04931a0ec865610", "sha1", wordlist_path) == "cybersecurity"

@pytest.mark.asyncio
async def test_sha256_unhashing():
    assert await unhash_data("91df9a8e8982259cef0f3ebadee8152037efcfbd479e551b35bf9e2f30b3646e", "sha256", wordlist_path) == "engineers"

@pytest.mark.asyncio
async def test_sha512_unhashing():
    assert await unhash_data("1bdb85ee866d676af25692cc6a8994ed092c53014165d7d52de4d4fd2e470a8f89e49abfff31e0056dbcb68de006faa95a3aa0ed211ea06a0cc812c6ac078eab", "sha512", wordlist_path) == "from"

@pytest.mark.asyncio
async def test_sha3_256_unhashing():
    assert await unhash_data("51f2c023d695d219b6a10ad156616b631e7fbee9dd7c6ec431075fbbfe09ed76", "sha3_256", wordlist_path) == "india"
