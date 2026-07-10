"""
Export the vault to an encrypted backup file.

The backup is protected independently of the live vault: the user supplies
a (possibly different) backup password, from which a fresh key is derived
with a fresh PBKDF2 salt. This means a backup file is self-contained and
can be restored even without access to the original SQLite database.

Backup file format (binary):
    MAGIC (8 bytes) || salt (16 bytes) || base64-json-of(nonce+ciphertext via encryption.encrypt)
Simplified: we store salt raw, then the encryption.encrypt() base64 string
of the JSON payload, so the layout on disk is:
    MAGIC || salt (16 raw bytes) || b64(nonce||ciphertext+tag)
"""

import json

from config import settings
from crypto import encryption, key_derivation
from manager.vault import list_credentials
from auth.session import Session


def export_vault(session: Session, backup_password: str, output_path: str) -> str:
    entries = list_credentials(session)

    payload = {
        "version": 1,
        "username": session.username,
        "entries": [
            {
                "service": e.service,
                "username": e.username,
                "password": e.password,
                "notes": e.notes,
            }
            for e in entries
        ],
    }
    plaintext_json = json.dumps(payload)

    salt = key_derivation.generate_kdf_salt()
    backup_key = key_derivation.derive_key(backup_password, salt)
    encrypted_blob = encryption.encrypt(plaintext_json, backup_key)

    with open(output_path, "wb") as f:
        f.write(settings.EXPORT_MAGIC)
        f.write(salt)
        f.write(encrypted_blob.encode("ascii"))

    return output_path
