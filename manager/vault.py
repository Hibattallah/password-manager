"""
Vault operations: add, edit, delete, and list credential entries.

Every credential field (username, password, notes) is encrypted with
AES-256-GCM using the session's derived key BEFORE being sent to the
database layer. Decryption happens only when data needs to be displayed
to the authenticated user.
"""

from dataclasses import dataclass
from typing import Optional, List

from database import database
from crypto import encryption
from auth.session import Session


@dataclass
class VaultEntry:
    id: int
    service: str
    username: str
    password: str
    notes: Optional[str]
    created_at: str
    updated_at: str


def _decrypt_row(row, key: bytes) -> VaultEntry:
    notes = encryption.decrypt(row["notes_enc"], key) if row["notes_enc"] else None
    return VaultEntry(
        id=row["id"],
        service=row["service"],
        username=encryption.decrypt(row["username_enc"], key),
        password=encryption.decrypt(row["password_enc"], key),
        notes=notes,
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def add_credential(session: Session, service: str, username: str, password: str, notes: str = None) -> int:
    key = session.key
    username_enc = encryption.encrypt(username, key)
    password_enc = encryption.encrypt(password, key)
    notes_enc = encryption.encrypt(notes, key) if notes else None
    return database.add_entry(session.user_id, service, username_enc, password_enc, notes_enc)


def list_credentials(session: Session) -> List[VaultEntry]:
    key = session.key
    rows = database.get_entries(session.user_id)
    return [_decrypt_row(row, key) for row in rows]


def get_credential(session: Session, entry_id: int) -> Optional[VaultEntry]:
    key = session.key
    row = database.get_entry(entry_id, session.user_id)
    if row is None:
        return None
    return _decrypt_row(row, key)


def update_credential(session: Session, entry_id: int, service: str, username: str, password: str, notes: str = None) -> bool:
    key = session.key
    existing = database.get_entry(entry_id, session.user_id)
    if existing is None:
        return False
    username_enc = encryption.encrypt(username, key)
    password_enc = encryption.encrypt(password, key)
    notes_enc = encryption.encrypt(notes, key) if notes else None
    database.update_entry(entry_id, session.user_id, service, username_enc, password_enc, notes_enc)
    return True


def delete_credential(session: Session, entry_id: int) -> bool:
    existing = database.get_entry(entry_id, session.user_id)
    if existing is None:
        return False
    database.delete_entry(entry_id, session.user_id)
    return True
