"""
In-memory session object.

Holds the derived AES-256 encryption key ONLY for the duration of an
unlocked session. The key never touches disk. When the session ends
(logout, app close, or idle timeout) the key bytes are overwritten
before being released, as a defense-in-depth measure against memory
disclosure (best-effort in a garbage-collected language like Python).
"""

import time

from config import settings


class Session:
    def __init__(self):
        self.user_id = None
        self.username = None
        self._key = None
        self._last_activity = None

    # -- lifecycle ---------------------------------------------------------

    def start(self, user_id: int, username: str, key: bytes):
        self.user_id = user_id
        self.username = username
        self._key = bytearray(key)
        self._last_activity = time.monotonic()

    def touch(self):
        self._last_activity = time.monotonic()

    def is_expired(self) -> bool:
        if self._last_activity is None:
            return True
        return (time.monotonic() - self._last_activity) > settings.SESSION_IDLE_TIMEOUT_SECONDS

    def destroy(self):
        """Best-effort zeroing of the encryption key before discarding it."""
        if self._key is not None:
            for i in range(len(self._key)):
                self._key[i] = 0
        self._key = None
        self.user_id = None
        self.username = None
        self._last_activity = None

    # -- accessors -----------------------------------------------------------

    @property
    def key(self) -> bytes:
        if self._key is None:
            raise RuntimeError("Session is not active. Please log in first.")
        if self.is_expired():
            self.destroy()
            raise RuntimeError("Session expired due to inactivity. Please log in again.")
        self.touch()
        return bytes(self._key)

    @property
    def is_active(self) -> bool:
        return self._key is not None and not self.is_expired()
