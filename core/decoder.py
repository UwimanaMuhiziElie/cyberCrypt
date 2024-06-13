

import base64
import urllib.parse
import html

DECODERS = {
    "base64": lambda data: base64.b64decode(data).decode() if isinstance(data, str) else base64.b64decode(data).decode(),
    "hex": lambda data: bytes.fromhex(data).decode(),
    "url": lambda data: urllib.parse.unquote(data),
    "html": html.unescape
}

def decode(data, decoding_type):
    return DECODERS[decoding_type](data)
