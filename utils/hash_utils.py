"""
hash_utils.py — SHA-1 hashing and HaveIBeenPwned breach checking.

Uses k-anonymity model: only the first 5 characters of the SHA-1 hash
are sent to the HIBP API. The full hash never leaves this module.
"""

import hashlib
import httpx

# HIBP API endpoint for k-anonymity range queries
HIBP_API_URL = "https://api.pwnedpasswords.com/range/"


def sha1_hash(text: str) -> str:
    """
    Compute SHA-1 hex digest of a plaintext string.
    
    Args:
        text: The plaintext string to hash.
    
    Returns:
        Uppercase hex string of the SHA-1 digest.
    """
    return hashlib.sha1(text.encode("utf-8")).hexdigest().upper()


async def check_breach(password: str) -> dict:
    """
    Check if a password has appeared in known data breaches using
    the HaveIBeenPwned k-anonymity API.
    
    Process:
        1. Hash the password with SHA-1.
        2. Send only the first 5 characters (prefix) to HIBP.
        3. Receive list of hash suffixes that match the prefix.
        4. Compare the remaining suffix locally.
    
    Args:
        password: The plaintext password to check.
    
    Returns:
        dict with keys:
            - breached (bool): Whether the password was found.
            - count (int): Number of times found in breaches.
            - error (str | None): Error message if request failed.
    """
    try:
        full_hash = sha1_hash(password)
        prefix = full_hash[:5]
        suffix = full_hash[5:]

        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                f"{HIBP_API_URL}{prefix}",
                headers={"User-Agent": "PasswordGuardian-MiniProject"}
            )
            response.raise_for_status()

        # Parse response: each line is "HASH_SUFFIX:COUNT"
        for line in response.text.splitlines():
            parts = line.split(":")
            if len(parts) == 2 and parts[0].strip() == suffix:
                return {
                    "breached": True,
                    "count": int(parts[1].strip()),
                    "error": None
                }

        return {"breached": False, "count": 0, "error": None}

    except httpx.TimeoutException:
        return {"breached": False, "count": 0, "error": "Request timed out. Please try again."}
    except httpx.HTTPStatusError as e:
        return {"breached": False, "count": 0, "error": f"API error: {e.response.status_code}"}
    except Exception as e:
        return {"breached": False, "count": 0, "error": f"Network error: {str(e)}"}
