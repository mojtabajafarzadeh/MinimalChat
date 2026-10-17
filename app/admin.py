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

One credential guards the whole install -- it can delete every user and every
message -- and nothing else protects it: the backoff in app.security slows a
guessing run but a distributed one gets one tally per address. A long random
password is therefore the actual control, which is why a weak configured one
is reported at startup rather than accepted silently (I-03).
"""
import hmac
import secrets

from . import auth, db, security
from .config import (
    ADMIN_LOCKOUT_GRACE,
    ADMIN_LOCKOUT_HALF_LIFE,
    ADMIN_LOCKOUT_MAX,
    ADMIN_LOCKOUT_STEP,
    ADMIN_PASSWORD,
    ADMIN_PASSWORD_HASH,
)

ADMIN_COOKIE = "admin_session"
ADMIN_SESSION_HOURS = 12

# Below this a password is not worth having: the whole database sits behind
# one guessable secret. Not a complexity rule -- length is what counts, so a
# 6-character mix of every class still fails and a long passphrase passes.
MIN_ADMIN_PASSWORD_CHARS = 12


def enabled() -> bool:
    return bool(ADMIN_PASSWORD or ADMIN_PASSWORD_HASH)


def password_strength() -> str | None:
    """Why the configured password is too weak, or None when it is fine.

    Only meaningful for the plaintext form: a hash hides the length, so
    hashed admins get nothing to judge and the warning is simply skipped.
    """
    if not ADMIN_PASSWORD:
        return None
    if len(ADMIN_PASSWORD) < MIN_ADMIN_PASSWORD_CHARS:
        return (f"ADMIN_PASSWORD is {len(ADMIN_PASSWORD)} characters; "
                f"use at least {MIN_ADMIN_PASSWORD_CHARS}")
    if ADMIN_PASSWORD.isalpha() or ADMIN_PASSWORD.isdigit():
        return ("ADMIN_PASSWORD is a single character class (letters or "
                "digits only); add length or a second class")
    return None


def apply_lockout_config() -> None:
    """Hand the backoff curve to security, which cannot read app.config."""
    security.configure_admin_lockout(ADMIN_LOCKOUT_STEP, ADMIN_LOCKOUT_GRACE,
                                     ADMIN_LOCKOUT_MAX,
                                     ADMIN_LOCKOUT_HALF_LIFE)


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