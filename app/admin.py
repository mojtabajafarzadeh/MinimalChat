"""Admin-panel authentication: password from env, server-side sessions.

Separate from chat-user sessions on purpose: the admin is not a chat user,
there is no default password, and the whole panel (routes included) only
exists while a password is configured. Sessions live in SQLite so they keep
working when several worker processes share one database. Tokens are never
logged and expire after ADMIN_SESSION_HOURS.

The password may be given either in plaintext (ADMIN_PASSWORD) or as a PBKDF2
hash (ADMIN_PASSWORD_HASH). The hash form is preferred: the secret on disk is
then not itself a credential, which matters because .env, /proc/<pid>/environ
and process listings are all readable. The hash wins when both are set.
"""
import hmac
import secrets

from . import auth, db
from .config import ADMIN_PASSWORD, ADMIN_PASSWORD_HASH

ADMIN_COOKIE = "admin_session"
ADMIN_SESSION_HOURS = 12


def enabled() -> bool:
    return bool(ADMIN_PASSWORD or ADMIN_PASSWORD_HASH)


def verify_password(password: str) -> bool:
    if ADMIN_PASSWORD_HASH:
        return auth.verify_password(password, ADMIN_PASSWORD_HASH)
    if ADMIN_PASSWORD:
        return hmac.compare_digest(password, ADMIN_PASSWORD)
    return False


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