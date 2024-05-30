import re

def determine_input_type(data):
    """
    Determine the type of the input based on patterns.
    Uses regex and specific character checks to classify data accurately.
    """
    if re.match(r'^https?://(?:www\.)?[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$', data):
        return "URL"
    if all(c in "01" for c in data):
        return "Binary"
    if all(c in "0123456789ABCDEFabcdef" for c in data):
        return "Hex"

    base64_pattern = r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$'
    if re.match(base64_pattern, data) and len(data) % 4 == 0:
        return "Base64"
    if all(c in "0123456789abcdefABCDEF" for c in data) and len(data) % 2 == 0:
        return "Hash"
    return "Text"

def validate_input(data):
    """
    Validate input to ensure it conforms to expected formats and types.
    Adds checks for empty input, excessive length, and ensures that the input
    does not contain unexpected characters.
    """
    data = data.strip()

    if not data:
        raise ValueError("[!] Input cannot be empty.")

    if len(data) > 10000: 
        raise ValueError("[!] Input is too long. Please limit input to 10,000 characters.")

    patterns = {
        "URL": r'^https?://(?:www\.)?[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$',
        "Binary": r'^[01]+$',
        "Hex": r'^[0-9A-Fa-f]+$',
        "Base64": base64_pattern,
        "Hash": r'^[0-9A-Fa-f]+$',
        "Text": r'^[\w\s!@#$%^&*()_+{}\[\]:;<>,.?~\/\-]+$'
    }

    input_type = determine_input_type(data)

    if re.match(patterns[input_type], data):
        return data
    else:
        raise ValueError(f"[!] Invalid Input: '{data}' does not conform to expected format for {input_type}.")

