import pytest
from core.encoder import encode
from core.decoder import decode
from core.input_validator import determine_input_type

def test_base64_encoding():
    assert encode("HelloHackers", "base64") == b'SGVsbG9IYWNrZXJz'
    assert decode("SGVsbG9IYWNrZXJz", "base64") == 'HelloHackers'

def test_hex_encoding():
    assert encode("Hello Pentesters!", "hex") == '48656c6c6f2050656e7465737465727321'
    assert decode("48656c6c6f2050656e7465737465727321", "hex") == 'Hello Pentesters!'

def test_url_encoding():
    assert encode("https://www.iana.org/help/example-domains", "url") == 'https%3A%2F%2Fwww.iana.org%2Fhelp%2Fexample-domains'
    assert decode("https%3A%2F%2Fwww.iana.org%2Fhelp%2Fexample-domains", "url") == 'https://www.iana.org/help/example-domains'

def test_html_encoding():
    assert encode("<title>Base64 Encoder/Decoder</title>", "html") == '&lt;title&gt;Base64 Encoder/Decoder&lt;/title&gt;'
    assert decode("&lt;title&gt;Base64 Encoder/Decoder&lt;/title&gt;", "html") == '<title>Base64 Encoder/Decoder</title>'

def test_input_type():
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
