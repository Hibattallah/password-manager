"""
Login / vault unlock flow.

Workflow (matches project spec):
  Verify Master Password -> Derive Encryption Key -> Unlock Vault
"""

from database import database
from crypto import hashing, key_derivation
from auth.session import Session


class LoginError(Exception):
    pass


def login(username: str, master_password: str, session: Session) -> Session:
    user = database.get_user_by_username(username)
    if user is None:
        # Same error as wrong password, to avoid username enumeration
        raise LoginError("Invalid username or master password.")

    if not hashing.verify_master_password(master_password, user["master_hash"]):
        raise LoginError("Invalid username or master password.")

    # Optionally upgrade the stored hash if Argon2 parameters were strengthened
    if hashing.needs_rehash(user["master_hash"]):
        new_hash = hashing.hash_master_password(master_password)
        database.update_master_hash(user["id"], new_hash)

    kdf_salt = bytes.fromhex(user["kdf_salt"])
    encryption_key = key_derivation.derive_key(master_password, kdf_salt)

    session.start(user_id=user["id"], username=user["username"], key=encryption_key)
    return session
