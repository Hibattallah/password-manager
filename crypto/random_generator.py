"""
Cryptographically secure random password generation, built on Python's
`secrets` module (CSPRNG), never `random`.
"""

import secrets
import string

from config import settings

LOWER = string.ascii_lowercase
UPPER = string.ascii_uppercase
DIGITS = string.digits
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?/|~"

# Characters that are easy to confuse visually
AMBIGUOUS = "il1Lo0O"


def generate_password(
    length: int = settings.DEFAULT_PASSWORD_LENGTH,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    avoid_ambiguous: bool = False,
) -> str:
    """
    Generate a random password guaranteed to contain at least one
    character from each selected character class.
    """
    if not (settings.MIN_PASSWORD_LENGTH <= length <= settings.MAX_PASSWORD_LENGTH):
        raise ValueError(
            f"Password length must be between {settings.MIN_PASSWORD_LENGTH} "
            f"and {settings.MAX_PASSWORD_LENGTH}."
        )

    pools = []
    if use_lower:
        pools.append(LOWER)
    if use_upper:
        pools.append(UPPER)
    if use_digits:
        pools.append(DIGITS)
    if use_symbols:
        pools.append(SYMBOLS)

    if not pools:
        raise ValueError("At least one character class must be enabled.")

    if avoid_ambiguous:
        pools = ["".join(c for c in pool if c not in AMBIGUOUS) for pool in pools]

    all_chars = "".join(pools)

    # Guarantee at least one char from each selected pool
    password_chars = [secrets.choice(pool) for pool in pools]
    remaining = length - len(password_chars)
    password_chars += [secrets.choice(all_chars) for _ in range(remaining)]

    # Shuffle securely so the guaranteed chars aren't always at the front
    for i in range(len(password_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

    return "".join(password_chars)


def generate_passphrase(word_count: int = 5, separator: str = "-") -> str:
    """
    Generate a simple, memorable passphrase using a small built-in wordlist.
    For a production system, replace WORDLIST with the full EFF diceware list.
    """
    words = [secrets.choice(_WORDLIST) for _ in range(word_count)]
    return separator.join(words)


_WORDLIST = [
    "orbit", "maple", "quartz", "ember", "willow", "granite", "cobalt", "harbor",
    "meadow", "falcon", "cipher", "lantern", "canyon", "nimbus", "ripple", "thistle",
    "voyage", "zenith", "amber", "boulder", "cascade", "drift", "ember", "frost",
    "glacier", "horizon", "ivory", "juniper", "kestrel", "lumen", "mosaic", "nebula",
]
