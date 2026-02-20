"""
generator.py — Cryptographically secure password generation.

Uses Python's `secrets` module (backed by os.urandom) for all
random operations to ensure cryptographic security.

Supports three generation modes:
    1. Standard Password — configurable character classes
    2. PIN — numeric digits only (4–6 digits)
    3. Passphrase — random words joined by hyphens
"""

import secrets
import string

# Common ambiguous characters that can be confused visually
AMBIGUOUS_CHARS = "il1Lo0O"

# Embedded word list for passphrase generation (common, easy-to-type words)
WORD_LIST = [
    "apple", "brave", "cloud", "dance", "eagle", "flame", "grace", "heart",
    "ivory", "jewel", "knack", "lunar", "maple", "night", "ocean", "pearl",
    "quest", "river", "stone", "tiger", "umbra", "vivid", "whale", "xenon",
    "yacht", "zebra", "amber", "blaze", "cedar", "drift", "ember", "frost",
    "globe", "haven", "inlet", "joker", "karma", "lemon", "mirth", "noble",
    "oasis", "prism", "quilt", "raven", "solar", "thorn", "ultra", "vigor",
    "wired", "pixel", "arrow", "brisk", "candy", "delta", "elbow", "fiery",
    "ghost", "humor", "index", "jolly", "kneel", "logic", "metal", "nerve",
    "orbit", "pulse", "quiet", "roast", "shark", "trail", "unity", "vault",
    "wagon", "yield", "bliss", "charm", "dwarf", "ethos", "fable", "glyph",
    "haste", "irony", "jazzy", "kiosk", "lyric", "mocha", "nexus", "olive",
    "piano", "reign", "spice", "tulip", "usher", "viper", "widow", "zesty",
    "acorn", "basin", "cliff", "dodge", "epoch", "flint", "grain", "hydra",
    "image", "joint", "kayak", "libra", "marsh", "north", "omega", "plume",
    "quota", "ridge", "swirl", "torch", "urban", "verge", "whisk", "axiom"
]


def generate_standard(
    length: int = 16,
    uppercase: bool = True,
    lowercase: bool = True,
    numbers: bool = True,
    symbols: bool = True,
    exclude_ambiguous: bool = False
) -> str:
    """
    Generate a standard password with configurable character classes.
    
    Args:
        length: Password length (8–128, default 16).
        uppercase: Include uppercase letters.
        lowercase: Include lowercase letters.
        numbers: Include digits.
        symbols: Include special characters.
        exclude_ambiguous: Exclude visually ambiguous characters.
    
    Returns:
        Generated password string.
    
    Raises:
        ValueError: If no character classes selected or length out of range.
    """
    # Clamp length to safe range
    length = max(8, min(128, length))

    # Build character pool
    pool = ""
    required = []  # Ensure at least one char from each selected class

    if lowercase:
        chars = string.ascii_lowercase
        if exclude_ambiguous:
            chars = "".join(c for c in chars if c not in AMBIGUOUS_CHARS)
        pool += chars
        required.append(secrets.choice(chars))

    if uppercase:
        chars = string.ascii_uppercase
        if exclude_ambiguous:
            chars = "".join(c for c in chars if c not in AMBIGUOUS_CHARS)
        pool += chars
        required.append(secrets.choice(chars))

    if numbers:
        chars = string.digits
        if exclude_ambiguous:
            chars = "".join(c for c in chars if c not in AMBIGUOUS_CHARS)
        pool += chars
        required.append(secrets.choice(chars))

    if symbols:
        chars = string.punctuation
        pool += chars
        required.append(secrets.choice(chars))

    if not pool:
        raise ValueError("At least one character class must be selected.")

    # Generate remaining characters
    remaining_length = length - len(required)
    password_chars = required + [secrets.choice(pool) for _ in range(remaining_length)]

    # Shuffle to avoid predictable positions for required characters
    # Fisher-Yates shuffle using secrets for randomness
    for i in range(len(password_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

    return "".join(password_chars)


def generate_pin(length: int = 4) -> str:
    """
    Generate a numeric PIN.
    
    Args:
        length: PIN length (4–6 digits, default 4).
    
    Returns:
        Generated PIN string.
    """
    length = max(4, min(6, length))
    return "".join(secrets.choice(string.digits) for _ in range(length))


def generate_passphrase(word_count: int = 4) -> str:
    """
    Generate a passphrase from random dictionary words.
    
    Args:
        word_count: Number of words (3–5, default 4).
    
    Returns:
        Hyphen-separated passphrase string.
    """
    word_count = max(3, min(5, word_count))
    words = [secrets.choice(WORD_LIST) for _ in range(word_count)]
    return "-".join(words)


def generate_password(options: dict) -> dict:
    """
    Main entry point for password generation.
    
    Args:
        options: dict with keys:
            - type: "standard" | "pin" | "passphrase"
            - length: desired length (for standard/pin)
            - word_count: number of words (for passphrase)
            - uppercase, lowercase, numbers, symbols: bool (for standard)
            - exclude_ambiguous: bool (for standard)
    
    Returns:
        dict with 'password' and 'type' keys.
    """
    pw_type = options.get("type", "standard")

    if pw_type == "pin":
        password = generate_pin(options.get("length", 4))
    elif pw_type == "passphrase":
        password = generate_passphrase(options.get("word_count", 4))
    else:
        password = generate_standard(
            length=options.get("length", 16),
            uppercase=options.get("uppercase", True),
            lowercase=options.get("lowercase", True),
            numbers=options.get("numbers", True),
            symbols=options.get("symbols", True),
            exclude_ambiguous=options.get("exclude_ambiguous", False)
        )

    return {"password": password, "type": pw_type}
