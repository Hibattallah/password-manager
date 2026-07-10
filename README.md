# Secure Password Manager

A command-line password manager built for a cybersecurity coursework project.
It demonstrates secure authentication, encryption, key management, and
database protection using modern cryptographic primitives.

## Security Features

- **Master password authentication** — a single master password unlocks the vault.
- **Argon2id password hashing** — the master password itself is never stored; only its Argon2id hash is.
- **PBKDF2-HMAC-SHA256 key derivation** — the AES encryption key is derived from the master password with 390,000 iterations, separately from the login hash.
- **AES-256-GCM encryption** — every stored username, password, and note is individually encrypted with authenticated encryption (tamper detection included).
- **Cryptographically secure password generation** — via Python's `secrets` module.
- **Encrypted SQLite storage** — credential secrets are stored only in ciphertext form.
- **Encrypted backups** — export/import vault data protected by a separate backup password.
- **In-memory key destruction** — the encryption key is zeroed out on logout or exit.

## Requirements

- Ubuntu (or any Linux distribution) with Python 3.8+
- pip

## Installation

```bash
git clone <your-repo-url>
cd password-manager
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python3 app.py
```

See `docs/MANUAL.md` (or `docs/MANUAL.docx`) for a full usage guide.

## Project Structure

```
password-manager/
├── app.py                 # CLI entry point
├── config/settings.py      # Security parameters and paths
├── database/                # SQLite access layer + schema
├── crypto/                  # Hashing, key derivation, AES encryption, password generator
├── auth/                    # Register / login / session management
├── manager/                  # Vault CRUD, search, export, import
├── tests/                    # Unit tests
└── storage/                  # SQLite database file (created at runtime)
```

## Running Tests

```bash
python3 -m unittest discover tests
```

## License

MIT — see `LICENSE`.
