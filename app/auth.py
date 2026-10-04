"""Auth: PBKDF2 password hashing (stdlib) + server-side sessions in SQLite."""
import hashlib
import hmac
import secrets

from . import db
from .config import SESSION_LIFETIME_DAYS

ITERATIONS = 200_000


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS)
    return f"pbkdf2_sha256${ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters, salt_hex, hash_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iters)
        )
        return hmac.compare_digest(dk.hex(), hash_hex)
    except Exception:
        return False


# Valid-format hash used only to equalize login timing when the username
# does not exist (result is discarded; mitigates user enumeration).
_DUMMY_HASH = hash_password(secrets.token_hex(16))


def dummy_verify(password: str) -> None:
    """Burn the same PBKDF2 cost as a real check; callers ignore the result."""
    verify_password(password, _DUMMY_HASH)


def create_session(user_id: int) -> str:
    token = secrets.token_hex(32)
    db.execute("INSERT INTO sessions (id, user_id) VALUES (?, ?)", (token, user_id))
    return token


def get_session_user(token: str | None):
    if not token:
        return None
    row = db.query_one(
        "SELECT u.id, u.name, u.username FROM sessions s "
        "JOIN users u ON u.id = s.user_id WHERE s.id = ? "
        "AND datetime(s.created_at) > datetime('now', ?)",
        (token, f"-{SESSION_LIFETIME_DAYS} days"),
    )
    if row:
        return dict(row)
    # Unknown or expired: opportunistically drop the dead row.
    db.execute("DELETE FROM sessions WHERE id = ?", (token,))
    return None


def delete_session(token: str | None) -> None:
    if not token:
        return
    db.execute("DELETE FROM sessions WHERE id = ?", (token,))
