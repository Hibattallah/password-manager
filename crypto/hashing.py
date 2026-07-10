"""
Master password hashing and verification.

We use Argon2id (via argon2-cffi) to hash the master password for storage.
Argon2id is the current OWASP-recommended algorithm because it is resistant
to both GPU cracking (memory-hard) and side-channel attacks (hybrid mode).

IMPORTANT: This hash is used ONLY to verify the master password at login.
It is NOT used as the encryption key. The encryption key is derived
separately via PBKDF2 (see key_derivation.py) so that a leaked password
hash can never directly yield the vault's encryption key.
"""

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHash

from config import settings

_hasher = PasswordHasher(
    time_cost=settings.ARGON2_TIME_COST,
    memory_cost=settings.ARGON2_MEMORY_COST,
    parallelism=settings.ARGON2_PARALLELISM,
    hash_len=settings.ARGON2_HASH_LEN,
    salt_len=settings.ARGON2_SALT_LEN,
)


def hash_master_password(master_password: str) -> str:
    """Return an Argon2id hash string (includes algorithm params + salt)."""
    return _hasher.hash(master_password)


def verify_master_password(master_password: str, stored_hash: str) -> bool:
    """Return True if the supplied password matches the stored hash."""
    try:
        _hasher.verify(stored_hash, master_password)
        return True
    except (VerifyMismatchError, InvalidHash):
        return False


def needs_rehash(stored_hash: str) -> bool:
    """True if the stored hash was created with weaker/older parameters."""
    return _hasher.check_needs_rehash(stored_hash)
