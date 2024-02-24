import re

def determine_input_type(data):
    if re.match(r'^https?://(?:www\.)?[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$', data):
        return "URL"
    if all(c in "01" for c in data):
        return "Binary"
    if all(c in "0123456789ABCDEFabcdef" for c in data):
        return "Hex"
    if all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in data):
        return "Base64"
    if all(c in "0123456789abcdefABCDEF" for c in data) and len(data) % 2 == 0:
        return "Hash"
    return "Text"

def validate_input(data):
    data = data.strip()
    if re.match(r'^https?://(?:www\.)?[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$', data):
        return data
    if re.match(r'^[01]+$', data):
        return data
    if re.match(r'^[0-9A-Fa-f]+$', data):
        return data
    if re.match(r'^[A-Za-z0-9+/=]+$', data):
        return data
    if re.match(r'^[0-9A-Fa-f]+$', data) and len(data) % 2 == 0:
        return data
    if re.match(r'^[\w\s!@#$%^&*()_+{}\[\]:;<>,.?~\/\-]+$', data):
        return data
    raise ValueError(f"[!] Invalid Input: '{data}' is not a valid input")

# import re

# def determine_input_type(data):
#     if re.match(r'^https?://(?:www\.)?[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$', data):
#         return "URL"
#     if all(c in "01" for c in data):
#         return "Binary"
#     if all(c in "0123456789ABCDEFabcdef" for c in data):
#         return "Hex"
#     if all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in data):
#         return "Base64"
#     if all(c in "0123456789abcdefABCDEF" for c in data) and len(data) % 2 == 0:
#         return "Hash"
#     return "Text"

# def validate_input(data):
#     data = data.strip()
#     if re.match(r'^https?://(?:www\.)?[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$', data):
#         return data
#     if re.match(r'^[01]+$', data):
#         return data
#     if re.match(r'^[0-9A-Fa-f]+$', data):
#         return data
#     if re.match(r'^[A-Za-z0-9+/=]+$', data):
#         return data
#     if re.match(r'^[0-9A-Fa-f]+$', data) and len(data) % 2 == 0:
#         return data
#     if re.match(r'^[\w\s!@#$%^&*()_+{}\[\]:;<>,.?~\/\-]+$', data):
#         return data
#     raise ValueError(f"[!] Invalid Input: '{data}' is not a valid input")




