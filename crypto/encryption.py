"""
AES-256-GCM authenticated encryption/decryption helpers.

GCM (Galois/Counter Mode) is used instead of plain CBC because it provides
both confidentiality AND integrity/authenticity in a single primitive: any
tampering with the ciphertext is detected on decryption (InvalidTag), which
protects against silent data corruption or malicious modification of the
encrypted database contents.

Each encryption call uses a fresh random 96-bit nonce (never reused with the
same key), which is stored alongside the ciphertext since it is not secret.
"""

import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from config import settings


class DecryptionError(Exception):
    """Raised when ciphertext fails authentication (tampering or wrong key)."""


def encrypt(plaintext: str, key: bytes) -> str:
    """
    Encrypt a UTF-8 string with AES-256-GCM.

    Returns a single base64 string encoding [nonce || ciphertext+tag],
    convenient for storing in a single SQLite TEXT column.
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(settings.AES_NONCE_LEN)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), associated_data=None)
    blob = nonce + ciphertext
    return base64.b64encode(blob).decode("ascii")


def decrypt(token: str, key: bytes) -> str:
    """
    Decrypt a base64 [nonce || ciphertext+tag] blob produced by encrypt().

    Raises DecryptionError if the key is wrong or the data was tampered with.
    """
    try:
        blob = base64.b64decode(token)
        nonce, ciphertext = blob[:settings.AES_NONCE_LEN], blob[settings.AES_NONCE_LEN:]
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
        return plaintext.decode("utf-8")
    except (InvalidTag, ValueError):
        raise DecryptionError("Failed to decrypt data: wrong key or corrupted/tampered data.")
