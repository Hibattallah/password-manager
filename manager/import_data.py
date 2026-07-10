"""
Import credentials from an encrypted backup file created by export.py.

Every imported entry is re-encrypted with the CURRENT session's vault key
before being inserted, so the live vault is always encrypted with the
logged-in user's own derived key -- never with the backup password's key.
"""

import json

from config import settings
from crypto import encryption, key_derivation
from manager.vault import add_credential
from auth.session import Session


class ImportError_(Exception):
    pass


def import_vault(session: Session, backup_password: str, input_path: str) -> int:
    with open(input_path, "rb") as f:
        data = f.read()

    magic_len = len(settings.EXPORT_MAGIC)
    salt_len = settings.PBKDF2_SALT_LEN

    magic = data[:magic_len]
    if magic != settings.EXPORT_MAGIC:
        raise ImportError_("Not a valid Secure Password Manager backup file.")

    salt = data[magic_len:magic_len + salt_len]
    encrypted_blob = data[magic_len + salt_len:].decode("ascii")

    backup_key = key_derivation.derive_key(backup_password, salt)

    try:
        plaintext_json = encryption.decrypt(encrypted_blob, backup_key)
    except encryption.DecryptionError:
        raise ImportError_("Wrong backup password or corrupted backup file.")

    payload = json.loads(plaintext_json)
    imported_count = 0
    for entry in payload.get("entries", []):
        add_credential(
            session,
            service=entry["service"],
            username=entry["username"],
            password=entry["password"],
            notes=entry.get("notes"),
        )
        imported_count += 1

    return imported_count
