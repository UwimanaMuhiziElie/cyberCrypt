

import base64
import urllib.parse
import html


ENCODERS = {
    "base64": lambda data: base64.b64encode(data.encode() if isinstance(data, str) else data),
    "hex": lambda data: data.encode().hex() if isinstance(data, str) else data.hex(),
    "url": lambda data: urllib.parse.quote(data),
    # "html": html.escape
     "html": lambda data: html.escape(data.encode('utf-8').decode('utf-8')) if isinstance(data, str) else html.escape(data.decode('utf-8'))
}

def encode(data, encoding_type):
    return ENCODERS[encoding_type](data)
