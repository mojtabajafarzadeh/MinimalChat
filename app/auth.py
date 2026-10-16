"""Auth: PBKDF2 password hashing (stdlib) + server-side sessions in SQLite."""
import hashlib
import hmac
import secrets

from . import db
from .config import SESSION_IDLE_DAYS, SESSION_LIFETIME_DAYS

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
    db.execute(
        "INSERT INTO sessions (id, user_id, created_at, last_seen) "
        "VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
        (token, user_id),
    )
    return token


def get_session_user(token: str | None):
    """Resolve a session token to its user, or None.

    Two independent limits now apply. The absolute lifetime is unchanged; the
    idle timeout is new, because a 30-day-old cookie that is still being sent
    is exactly what a stolen session looks like, and without an idle bound
    there is no server-side signal at all (A-03).

    Touching last_seen on every read is one UPDATE per authenticated request.
    That is not free, so it only happens once the recorded value is older than
    a minute -- a session is not idle if it was used a moment ago, and the
    write would not change the answer.
    """
    if not token:
        return None
    row = db.query_one(
        "SELECT u.id, u.name, u.username, "
        "       CAST(strftime('%s','now') AS INTEGER) "
        "         - CAST(strftime('%s', COALESCE(s.last_seen, s.created_at)) "
        "               AS INTEGER) AS idle_seconds "
        "FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = ? "
        "AND datetime(s.created_at) > datetime('now', ?)",
        (token, f"-{SESSION_LIFETIME_DAYS} days"),
    )
    if not row:
        # Unknown or past the absolute lifetime: drop the dead row.
        db.execute("DELETE FROM sessions WHERE id = ?", (token,))
        return None

    if row["idle_seconds"] is not None and row["idle_seconds"] > SESSION_IDLE_DAYS * 86400:
        db.execute("DELETE FROM sessions WHERE id = ?", (token,))
        return None

    if (row["idle_seconds"] or 0) > 60:
        db.execute(
            "UPDATE sessions SET last_seen = CURRENT_TIMESTAMP WHERE id = ?",
            (token,),
        )
    return {"id": row["id"], "name": row["name"], "username": row["username"]}


def delete_session(token: str | None) -> None:
    if not token:
        return
    db.execute("DELETE FROM sessions WHERE id = ?", (token,))


def purge_expired_sessions() -> int:
    """Drop every session past either limit. Returns how many went.

    Called at startup. Without it the table only shrinks when a token is
    presented, so abandoned sessions accumulate for as long as the deployment
    lives.

    Counted with changes() rather than the DELETE's return value: db.execute
    hands back lastrowid, which for a DELETE is meaningless.
    """
    before = db.query_one("SELECT COUNT(*) AS n FROM sessions")["n"]
    db.execute(
        "DELETE FROM sessions "
        "WHERE datetime(created_at) <= datetime('now', ?) "
        "OR datetime(COALESCE(last_seen, created_at)) <= datetime('now', ?)",
        (f"-{SESSION_LIFETIME_DAYS} days", f"-{SESSION_IDLE_DAYS} days"),
    )
    after = db.query_one("SELECT COUNT(*) AS n FROM sessions")["n"]
    return max(0, before - after)
