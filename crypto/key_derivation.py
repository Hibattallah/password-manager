"""
Derives the AES-256 vault encryption key from the user's master password
using PBKDF2-HMAC-SHA256.

A unique random salt is generated per user at registration and stored
alongside the (separate) Argon2 password hash in the database. The salt is
not secret, but it must be unique per user and never reused, so that two
users with the same master password end up with different encryption keys.
"""

import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from config import settings


def generate_kdf_salt() -> bytes:
    """Cryptographically secure random salt for PBKDF2."""
    return os.urandom(settings.PBKDF2_SALT_LEN)


def derive_key(master_password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit AES key from the master password and salt.

    Uses PBKDF2-HMAC-SHA256 with a high iteration count to slow down
    brute-force / dictionary attacks against the master password.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=settings.AES_KEY_LEN,
        salt=salt,
        iterations=settings.PBKDF2_ITERATIONS,
    )
    return kdf.derive(master_password.encode("utf-8"))
