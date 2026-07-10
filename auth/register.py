"""
New user / vault registration.
"""

import re

from database import database
from crypto import hashing, key_derivation

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")


class RegistrationError(Exception):
    pass


def validate_master_password(password: str):
    if len(password) < 10:
        raise RegistrationError("Master password must be at least 10 characters long.")
    if not re.search(r"[A-Z]", password):
        raise RegistrationError("Master password must contain an uppercase letter.")
    if not re.search(r"[a-z]", password):
        raise RegistrationError("Master password must contain a lowercase letter.")
    if not re.search(r"[0-9]", password):
        raise RegistrationError("Master password must contain a digit.")
    if not re.search(r"[^A-Za-z0-9]", password):
        raise RegistrationError("Master password must contain a special character.")


def register_user(username: str, master_password: str, confirm_password: str) -> int:
    """Create a new vault user. Returns the new user's id."""
    if not USERNAME_RE.match(username):
        raise RegistrationError(
            "Username must be 3-32 characters: letters, digits, underscore, dot or hyphen."
        )

    if database.get_user_by_username(username) is not None:
        raise RegistrationError(f"Username '{username}' is already taken.")

    if master_password != confirm_password:
        raise RegistrationError("Passwords do not match.")

    validate_master_password(master_password)

    master_hash = hashing.hash_master_password(master_password)
    kdf_salt = key_derivation.generate_kdf_salt()

    user_id = database.create_user(username, master_hash, kdf_salt.hex())
    return user_id
