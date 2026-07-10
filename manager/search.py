"""
Search credentials by service name. The 'service' field is stored in
plaintext (it is just a label like "Gmail" or "GitHub") so it can be
searched/sorted efficiently with a SQL LIKE query without ever decrypting
the sensitive fields of non-matching entries.
"""

from typing import List

from database import database
from manager.vault import _decrypt_row, VaultEntry
from auth.session import Session


def search_credentials(session: Session, query: str) -> List[VaultEntry]:
    key = session.key
    rows = database.search_entries(session.user_id, query)
    return [_decrypt_row(row, key) for row in rows]
