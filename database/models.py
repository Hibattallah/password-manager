"""
SQLite schema definitions for the password manager.

Note: only the master password's Argon2 hash and the PBKDF2 salt are
stored for the `users` table. Vault entry secrets (passwords, notes) are
stored ONLY in encrypted (AES-256-GCM) form -- the plaintext never touches
disk.
"""

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT UNIQUE NOT NULL,
    master_hash     TEXT NOT NULL,      -- Argon2id hash of master password
    kdf_salt        TEXT NOT NULL,      -- base64 PBKDF2 salt (hex actually)
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS vault_entries (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL,
    service         TEXT NOT NULL,          -- plaintext label, used for search/sort
    username_enc    TEXT NOT NULL,          -- AES-256-GCM encrypted
    password_enc    TEXT NOT NULL,          -- AES-256-GCM encrypted
    notes_enc       TEXT,                   -- AES-256-GCM encrypted, optional
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_vault_user ON vault_entries(user_id);
CREATE INDEX IF NOT EXISTS idx_vault_service ON vault_entries(service);
"""
