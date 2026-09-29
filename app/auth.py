"""Auth: PBKDF2 password hashing (stdlib) + server-side sessions in SQLite."""
import hashlib
import hmac
import secrets

from . import db

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


def create_session(user_id: int) -> str:
    token = secrets.token_hex(32)
    db.execute("INSERT INTO sessions (id, user_id) VALUES (?, ?)", (token, user_id))
    return token


def get_session_user(token: str | None):
    if not token:
        return None
    row = db.query_one(
        "SELECT u.id, u.name, u.username FROM sessions s "
        "JOIN users u ON u.id = s.user_id WHERE s.id = ?",
        (token,),
    )
    return dict(row) if row else None


def delete_session(token: str | None) -> None:
    if not token:
        return
    db.execute("DELETE FROM sessions WHERE id = ?", (token,))
