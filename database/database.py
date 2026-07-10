"""
Thin SQLite access layer. Keeps SQL in one place and always uses
parameterized queries to prevent SQL injection.
"""

import sqlite3
from contextlib import contextmanager

from config import settings
from database.models import SCHEMA


def init_db():
    """Create tables if they don't already exist."""
    with get_connection() as conn:
        conn.executescript(SCHEMA)
        conn.commit()


@contextmanager
def get_connection():
    conn = sqlite3.connect(settings.DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

def create_user(username: str, master_hash: str, kdf_salt_hex: str) -> int:
    with get_connection() as conn:
        cur = conn.execute(
            "INSERT INTO users (username, master_hash, kdf_salt) VALUES (?, ?, ?)",
            (username, master_hash, kdf_salt_hex),
        )
        conn.commit()
        return cur.lastrowid


def get_user_by_username(username: str):
    with get_connection() as conn:
        cur = conn.execute("SELECT * FROM users WHERE username = ?", (username,))
        return cur.fetchone()


def update_master_hash(user_id: int, new_hash: str):
    with get_connection() as conn:
        conn.execute("UPDATE users SET master_hash = ? WHERE id = ?", (new_hash, user_id))
        conn.commit()


# ---------------------------------------------------------------------------
# Vault entries
# ---------------------------------------------------------------------------

def add_entry(user_id: int, service: str, username_enc: str, password_enc: str, notes_enc: str = None) -> int:
    with get_connection() as conn:
        cur = conn.execute(
            """INSERT INTO vault_entries (user_id, service, username_enc, password_enc, notes_enc)
               VALUES (?, ?, ?, ?, ?)""",
            (user_id, service, username_enc, password_enc, notes_enc),
        )
        conn.commit()
        return cur.lastrowid


def get_entries(user_id: int):
    with get_connection() as conn:
        cur = conn.execute(
            "SELECT * FROM vault_entries WHERE user_id = ? ORDER BY service COLLATE NOCASE",
            (user_id,),
        )
        return cur.fetchall()


def get_entry(entry_id: int, user_id: int):
    with get_connection() as conn:
        cur = conn.execute(
            "SELECT * FROM vault_entries WHERE id = ? AND user_id = ?",
            (entry_id, user_id),
        )
        return cur.fetchone()


def update_entry(entry_id: int, user_id: int, service: str, username_enc: str, password_enc: str, notes_enc: str = None):
    with get_connection() as conn:
        conn.execute(
            """UPDATE vault_entries
               SET service = ?, username_enc = ?, password_enc = ?, notes_enc = ?,
                   updated_at = datetime('now')
               WHERE id = ? AND user_id = ?""",
            (service, username_enc, password_enc, notes_enc, entry_id, user_id),
        )
        conn.commit()


def delete_entry(entry_id: int, user_id: int):
    with get_connection() as conn:
        conn.execute("DELETE FROM vault_entries WHERE id = ? AND user_id = ?", (entry_id, user_id))
        conn.commit()


def search_entries(user_id: int, query: str):
    with get_connection() as conn:
        cur = conn.execute(
            """SELECT * FROM vault_entries
               WHERE user_id = ? AND service LIKE ?
               ORDER BY service COLLATE NOCASE""",
            (user_id, f"%{query}%"),
        )
        return cur.fetchall()
