"""Message encryption at rest using Fernet (authenticated encryption).

IMPORTANT: this is NOT end-to-end encryption. The server holds the key and
decrypts messages in order to deliver them to connected clients and to load
message history. The goal is only that the SQLite file contains ciphertext,
never plaintext.

Key handling:
- If the CHAT_ENCRYPTION_KEY env var is set, it is used (must be a valid
  Fernet key, e.g. generated with `python -c "from cryptography.fernet
  import Fernet; print(Fernet.generate_key().decode())"`).
- Otherwise a secure random key is generated once and stored in the
  `.chat_secret` file next to chat.db (created automatically, mode 0600).

If the key is lost, previously stored messages can NEVER be decrypted.
Back up .chat_secret (or keep CHAT_ENCRYPTION_KEY safe) and never commit it.
"""
import logging
import os
import threading

from cryptography.fernet import Fernet, InvalidToken  # noqa: F401  (re-exported)

from .paths import data_dir, ensure_secret_file, new_fernet_key

log = logging.getLogger("chat")

ENV_VAR = "CHAT_ENCRYPTION_KEY"
SECRET_FILE = data_dir() / ".chat_secret"

_cipher: Fernet | None = None
# Guards lazy initialisation: without it, several worker threads racing on the
# first encrypt() call could each generate/read a different key and some
# messages would fail to store (observed under a 100-client load test).
_cipher_lock = threading.Lock()


def _load_key() -> bytes:
    env = os.environ.get(ENV_VAR, "").strip()
    if env:
        key = env.encode("utf-8")
        try:
            Fernet(key)
        except Exception:
            raise RuntimeError(
                f"{ENV_VAR} is set but is not a valid Fernet key. "
                "Generate one with: python -c \"from cryptography.fernet "
                "import Fernet; print(Fernet.generate_key().decode())\""
            )
        return key
    # ensure_secret_file() serialises creation across threads and processes,
    # so every worker ends up with the same key (the old code could generate
    # competing keys and silently lose messages).
    key = ensure_secret_file(SECRET_FILE, new_fernet_key).strip()
    try:
        Fernet(key)
    except Exception:
        raise RuntimeError(
            f"{SECRET_FILE} exists but does not contain a valid Fernet key. "
            "Restore the correct key file or previously stored messages "
            "cannot be decrypted."
        )
    return key


def get_cipher() -> Fernet:
    global _cipher
    if _cipher is None:
        with _cipher_lock:          # double-checked: one key, ever
            if _cipher is None:
                _cipher = Fernet(_load_key())
    return _cipher


def encrypt(plaintext: str) -> str:
    """Encrypt plaintext -> ASCII ciphertext string for SQLite storage."""
    return get_cipher().encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt(token: str) -> str:
    """Decrypt a ciphertext string -> plaintext. Raises on failure."""
    return get_cipher().decrypt(token.encode("ascii")).decode("utf-8")
