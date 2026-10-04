"""Admin-panel authentication: password from env, server-side sessions.

Separate from chat-user sessions on purpose: the admin is not a chat user,
there is no default password, and the whole panel (routes included) only
exists while ADMIN_PASSWORD is set. Sessions live in SQLite so they keep
working when several worker processes share one database. Tokens are never
logged and expire after ADMIN_SESSION_HOURS.
"""
import hmac
import secrets

from . import db
from .config import ADMIN_PASSWORD

ADMIN_COOKIE = "admin_session"
ADMIN_SESSION_HOURS = 12


def enabled() -> bool:
    return bool(ADMIN_PASSWORD)


def verify_password(password: str) -> bool:
    return hmac.compare_digest(password, ADMIN_PASSWORD) if enabled() else False


def create_session() -> str:
    token = secrets.token_hex(32)
    db.execute("INSERT INTO admin_sessions (id, expires_at) VALUES (?, "
               "datetime('now', ?))", (token, f"+{ADMIN_SESSION_HOURS} hours"))
    return token


def valid_session(token: str | None) -> bool:
    if not token:
        return False
    row = db.query_one(
        "SELECT 1 FROM admin_sessions WHERE id = ? "
        "AND datetime(expires_at) > datetime('now')",
        (token,),
    )
    if row:
        return True
    # Unknown or expired: drop it so the table cannot grow without bound.
    db.execute("DELETE FROM admin_sessions WHERE id = ?", (token,))
    return False


def delete_session(token: str | None) -> None:
    if not token:
        return
    db.execute("DELETE FROM admin_sessions WHERE id = ?", (token,))