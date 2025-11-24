import re
import unicodedata

# COMMON BAD PASSWORD BASE LIST
COMMON_PASSWORDS = {
    "123456", "password", "admin", "qwerty", "letmein", "iloveyou",
    "welcome", "abc123", "111111", "123123", "monkey", "dragon",
    "passw0rd", "p@ssword", "p@ssw0rd"
}

KEYBOARD_PATTERNS = [
    "qwerty", "asdfgh", "zxcvbn", "qazwsx", "1q2w3e", "azerty"
]

# Helper → Remove Unicode tricks
def normalize(password):
    # Remove zero-width spaces and normalize unicode
    cleaned = ''.join(c for c in password if unicodedata.category(c) != 'Cf')
    return unicodedata.normalize("NFKC", cleaned)

# MAIN CHECKER
def check_password_strength(password: str, username: str = None) -> dict:
    password = normalize(password)
    errors = []

    # Basic Check
    if not password:
        errors.append("Password cannot be empty.")
        return {"is_strong": False, "errors": errors}

    # Length 
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long.")

    # Categories
    categories = {
        "upper": bool(re.search(r"[A-Z]", password)),
        "lower": bool(re.search(r"[a-z]", password)),
        "digit": bool(re.search(r"[0-9]", password)),
        "symbol": bool(re.search(r"[!@#$%^&*()_\-+=<>?/{}~\[\]|\\]", password)),
    }

    if sum(categories.values()) < 4:
        errors.append("Password must include: uppercase, lowercase, numbers, symbols.")

    # Username similarity
    if username:
        uname = username.lower()
        pwd = password.lower()

        if uname == pwd:
            errors.append("Password cannot be the same as your username.")

        if uname[::-1] in pwd:
            errors.append("Password cannot contain reversed username.")

    # Common Password Check
    if password.lower() in COMMON_PASSWORDS:
        errors.append("Password is too common.")

    # --- Leet speak check ---
    leet_map = str.maketrans(
    "430@$!17+5",
    "aeoasilt ts"[0:10]  # Safe way to ensure length = 10
    )

    decoded = password.lower().translate(leet_map)
    if decoded in COMMON_PASSWORDS:
        errors.append("Password is a leet version of a common password.")


    # Repeating characters
    if re.search(r"(.)\1{3,}", password):
        errors.append("Password contains too many repeating characters in a row.")

    # Sequence numeric
    if re.search(r"1234|2345|3456|4567|5678|6789", password):
        errors.append("Password contains numeric sequences (1234, 5678…).")

    # Alphabet sequence
    if re.search(r"abcd|bcde|cdef|defg|efgh|fghi", password.lower()):
        errors.append("Password contains alphabetical sequences (abcd, cdef…).")

    # Keyboard patterns
    for pattern in KEYBOARD_PATTERNS:
        if pattern in password.lower():
            errors.append("Password cannot contain simple keyboard patterns.")

    # Repeated pattern (abcabcabc)
    if re.fullmatch(r"(.+)\1{1,}", password):
        errors.append("Password cannot be a repeated pattern.")

    # Date patterns
    if re.search(r"\b(19|20)\d{2}\b", password):
        errors.append("Password should not contain years (e.g., 1999, 2024).")

    # Spaces
    if re.search(r" ", password):
        errors.append("Password cannot have spaces.")

    # Final Verdict
    return {
        "is_strong": len(errors) == 0,
        "errors": errors
    }