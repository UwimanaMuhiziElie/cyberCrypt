import re

def determine_input_type(data):
    """
    Determine the type of the input based on patterns.
    Uses regex and specific character checks to classify data accurately.
    """
    # Regex for checking if the input is a valid URL
    if re.match(r'^(https?|ftp)://[^\s/$.?#].[^\s]*$', data):
        return "URL"

    # Check if all characters are either 0 or 1 for Binary data
    if all(c in "01" for c in data):
        return "Binary"

    # Check if all characters are valid hexadecimal characters
    if all(c in "0123456789ABCDEFabcdef" for c in data):
        # Check for common hash lengths to differentiate between Hex and Hash
        if len(data) in [32, 40, 64, 128]:  # MD5, SHA-1, SHA-256, SHA-512
            return "Hash"
        else:
            return "Hex"

    # Enhanced Base64 check that includes length divisibility by 4 and optional '=' padding
    base64_pattern = r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$'
    if re.match(base64_pattern, data) and len(data) % 4 == 0 and ('=' in data or len(data) > 16):
        return "Base64"

    # Heuristic check for HTML input
    if re.search(r'<[^>]+>', data):
        return "HTML"

    # Default to text for any other input
    return "Text"

def validate_input(data):
    """
    Validate input to ensure it conforms to expected formats and types.
    Adds checks for empty input, excessive length, and ensures that the input
    does not contain unexpected characters.
    """
    data = data.strip()

    # Check for empty input
    if not data:
        raise ValueError("[!] Input cannot be empty.")

    # Check for excessive input length
    if len(data) > 10000:  # Adjust the length based on your context
        raise ValueError("[!] Input is too long. Please limit input to 10,000 characters.")

    # Patterns to validate various input types securely
    patterns = {
        "URL": r'^(https?|ftp)://[^\s/$.?#].[^\s]*$',
        "Binary": r'^[01]+$',
        "Hex": r'^[0-9A-Fa-f]+$',
        "Base64": r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$',
        "Hash": r'^[0-9A-Fa-f]+$',
        "HTML": r'<[^>]+>',
        "Text": r'^[\w\s!@#$%^&*()_+{}\[\]:;<>,.?~\/\-]+$'
    }

    input_type = determine_input_type(data)

    # Validate based on detected type
    if re.match(patterns[input_type], data):
        return data
    else:
        raise ValueError(f"[!] Invalid Input: '{data}' does not conform to expected format for {input_type}.")
