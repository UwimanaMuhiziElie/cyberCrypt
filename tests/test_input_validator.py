import pytest
from core.input_validator import determine_input_type, validate_input

def test_determine_input_type():
    assert determine_input_type("https://www.example.com") == "URL"
    assert determine_input_type("0101010101") == "Binary"
    assert determine_input_type("4a6f686e") == "Hex"
    assert determine_input_type("SGVsbG9Gcm9tVWdhbmRh") == "Base64"
    assert determine_input_type("617f04a6a52573928a9a4c94f4bf13a1") == "Hash"
    assert determine_input_type("Hello From Uganda") == "Text"
    assert determine_input_type("<title>Base64 Encoder/Decoder</title>") == "HTML"
    assert determine_input_type("hellofromhackers") == "Text"
    assert determine_input_type("HelloHackers") == "Text"
    assert determine_input_type("HelloHackersIndians") == "Text"

def test_validate_input():
    assert validate_input("https://www.example.com") == "https://www.example.com"
    assert validate_input("0101010101") == "0101010101"
    assert validate_input("4a6f686e") == "4a6f686e"
    assert validate_input("SGVsbG9Gcm9tVWdhbmRh") == "SGVsbG9Gcm9tVWdhbmRh"
    assert validate_input("617f04a6a52573928a9a4c94f4bf13a1") == "617f04a6a52573928a9a4c94f4bf13a1"
    assert validate_input("Hello From Uganda") == "Hello From Uganda"
    assert validate_input("<title>Base64 Encoder/Decoder</title>") == "<title>Base64 Encoder/Decoder</title>"
    assert validate_input("hellofromhackers") == "hellofromhackers"
    assert validate_input("HelloHackers") == "HelloHackers"
    assert validate_input("HelloHackersIndians") == "HelloHackersIndians"

    with pytest.raises(ValueError):
        validate_input("")

    with pytest.raises(ValueError):
        validate_input("a" * 10001)
