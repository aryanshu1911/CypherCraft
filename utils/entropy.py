"""
entropy.py — Password strength analysis.

Calculates entropy, estimated crack time, strength label,
and policy compliance checks.

Entropy formula: E = L × log2(C)
    where L = password length, C = character set size

Crack time: T = 2^E / guesses_per_second
    assuming 10 billion (10^10) guesses per second
"""

import math
import re

# Assumed brute-force speed: 10 billion guesses per second
GUESSES_PER_SECOND = 10_000_000_000


def _get_charset_size(password: str) -> int:
    """
    Determine the character set size based on what types
    of characters appear in the password.
    
    Returns:
        Integer representing the total character set size.
    """
    charset = 0
    if re.search(r"[a-z]", password):
        charset += 26   # lowercase letters
    if re.search(r"[A-Z]", password):
        charset += 26   # uppercase letters
    if re.search(r"[0-9]", password):
        charset += 10   # digits
    if re.search(r"[^a-zA-Z0-9]", password):
        charset += 32   # symbols / special characters
    return charset


def _format_crack_time(seconds: float) -> str:
    """
    Convert raw seconds into a human-readable time string.
    
    Returns:
        Human-readable string like "3 hours", "2.5 centuries", etc.
    """
    if seconds < 0.001:
        return "Instantly"
    if seconds < 1:
        return "Less than a second"
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    if seconds < 3600:
        return f"{seconds / 60:.1f} minutes"
    if seconds < 86400:
        return f"{seconds / 3600:.1f} hours"
    if seconds < 31536000:
        return f"{seconds / 86400:.1f} days"
    
    years = seconds / 31536000
    if years < 100:
        return f"{years:.1f} years"
    if years < 10_000:
        return f"{years / 100:.0f} centuries"
    return "Virtually uncrackable"


def _get_strength_label(entropy: float) -> dict:
    """
    Map entropy value to a strength label and color.
    
    Returns:
        dict with 'label' and 'color' keys.
    """
    if entropy < 28:
        return {"label": "Very Weak", "color": "#ef4444"}     # red
    if entropy < 36:
        return {"label": "Weak", "color": "#f97316"}          # orange
    if entropy < 60:
        return {"label": "Moderate", "color": "#eab308"}      # yellow
    if entropy < 80:
        return {"label": "Strong", "color": "#22c55e"}        # green
    return {"label": "Very Strong", "color": "#06b6d4"}       # cyan


def analyze_password(password: str) -> dict:
    """
    Perform a complete strength analysis on the given password.
    
    Args:
        password: The plaintext password to analyze.
    
    Returns:
        dict containing:
            - length: Password length
            - charset_size: Size of the character set used
            - entropy: Bits of entropy
            - crack_time: Human-readable crack time estimate
            - crack_time_seconds: Raw crack time in seconds
            - strength: { label, color }
            - policy: dict of policy check results
    """
    if not password:
        return {
            "length": 0,
            "charset_size": 0,
            "entropy": 0,
            "crack_time": "Instantly",
            "crack_time_seconds": 0,
            "strength": {"label": "Very Weak", "color": "#ef4444"},
            "policy": {
                "min_length": False,
                "has_uppercase": False,
                "has_lowercase": False,
                "has_number": False,
                "has_symbol": False
            }
        }

    length = len(password)
    charset_size = _get_charset_size(password)
    
    # Entropy = length × log2(charset_size)
    entropy = length * math.log2(charset_size) if charset_size > 0 else 0
    
    # Crack time = 2^entropy / guesses_per_second
    if entropy > 0:
        # Use log to avoid overflow for very high entropy values
        log_combinations = entropy * math.log10(2)
        log_guesses = math.log10(GUESSES_PER_SECOND)
        log_seconds = log_combinations - log_guesses
        
        if log_seconds > 30:  # Astronomically large
            crack_time_seconds = float("inf")
        else:
            crack_time_seconds = 10 ** log_seconds
    else:
        crack_time_seconds = 0

    return {
        "length": length,
        "charset_size": charset_size,
        "entropy": round(entropy, 2),
        "crack_time": _format_crack_time(crack_time_seconds),
        "crack_time_seconds": crack_time_seconds if crack_time_seconds != float("inf") else -1,
        "strength": _get_strength_label(entropy),
        "policy": {
            "min_length": length >= 8,
            "has_uppercase": bool(re.search(r"[A-Z]", password)),
            "has_lowercase": bool(re.search(r"[a-z]", password)),
            "has_number": bool(re.search(r"[0-9]", password)),
            "has_symbol": bool(re.search(r"[^a-zA-Z0-9]", password))
        }
    }
