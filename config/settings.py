"""
Central configuration for the Secure Password Manager.

Keeping every tunable security parameter in one place makes it easy to
audit and adjust (e.g. raising PBKDF2 iterations as hardware gets faster).
"""

import os

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STORAGE_DIR = os.path.join(BASE_DIR, "storage")
DB_PATH = os.path.join(STORAGE_DIR, "vault.db")

os.makedirs(STORAGE_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# Password hashing (master password verification) - Argon2id
# ---------------------------------------------------------------------------
ARGON2_TIME_COST = 3          # number of iterations
ARGON2_MEMORY_COST = 65536    # 64 MB
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN = 32
ARGON2_SALT_LEN = 16

# ---------------------------------------------------------------------------
# Key derivation (encryption key from master password) - PBKDF2-HMAC-SHA256
# ---------------------------------------------------------------------------
PBKDF2_ITERATIONS = 390_000   # OWASP 2023+ recommendation for SHA-256
PBKDF2_SALT_LEN = 16
AES_KEY_LEN = 32              # 256-bit AES key

# ---------------------------------------------------------------------------
# AES-GCM encryption
# ---------------------------------------------------------------------------
AES_NONCE_LEN = 12            # 96-bit nonce, standard for GCM

# ---------------------------------------------------------------------------
# Password generator defaults
# ---------------------------------------------------------------------------
DEFAULT_PASSWORD_LENGTH = 20
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128

# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------
SESSION_IDLE_TIMEOUT_SECONDS = 300  # auto-lock vault after 5 minutes idle

# ---------------------------------------------------------------------------
# Export / Import
# ---------------------------------------------------------------------------
EXPORT_MAGIC = b"SPMBAK01"    # identifies our encrypted backup format
