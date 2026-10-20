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


def plaintext_refusal() -> str | None:
    """Why the panel must not be served in this configuration, or None.

    The admin password is the single credential that guards every user and
    every message in the database, and the panel posts it outside the encrypted
    channel: admin.html loads no channel code by design (see README). On
    loopback the password never leaves the machine, and with TLS the hop is
    encrypted, so both are allowed. A plain-HTTP interface that other machines
    can reach is a cleartext password on the wire, so that combination is
    refused unless it was chosen explicitly.
    """
    if not enabled():
        return None
    from . import config          # read at call time, so tests can patch it
    if config.ADMIN_ALLOW_PLAINTEXT:
        return None
    if config.SSL_CERTFILE and config.SSL_KEYFILE:
        return None
    if config.HOST in config.LOOPBACK_HOSTS:
        return None
    return (
        f"The admin panel is enabled, but this server serves plain HTTP on "
        f"{config.HOST} and the panel posts its password outside the encrypted "
        "channel (admin.html loads no channel code), so that password would "
        "cross the network in cleartext.\n"
        "Fix one of these:\n"
        "  - configure SSL_CERTFILE/SSL_KEYFILE, or terminate TLS in a proxy;\n"
        "  - bind to loopback (HOST=127.0.0.1) and reach it over a tunnel;\n"
        "  - set ADMIN_ALLOW_PLAINTEXT=true if you accept the exposure.\n"
        "Clear ADMIN_PASSWORD/ADMIN_PASSWORD_HASH instead to disable the panel."
    )


def create_session() -> str:
    token = secrets.token_hex(32)
    db.execute("INSERT INTO admin_sessions (id, expires_at) VALUES (?, "
               "datetime('now', ?))", (token, f"+{ADMIN_SESSION_HOURS} hours"))
    return token


def valid_session(token: str | None) -> bool:
    """Is this admin session live?

    The row is looked up by id alone and the expiry is judged here, so an
    unknown token and a dead one are distinguishable. Only the dead one is
    deleted: an unconditional DELETE on every miss turned each request carrying
    a random cookie into a write, and the app has a single SQLite writer.
    """
    if not token:
        return False
    row = db.query_one(
        "SELECT CAST(strftime('%s','now') AS INTEGER) "
        "         - CAST(strftime('%s', expires_at) AS INTEGER) AS overdue "
        "FROM admin_sessions WHERE id = ?",
        (token,),
    )
    if not row:
        return False
    if row["overdue"] is not None and row["overdue"] >= 0:
        # Expired: this row is genuinely dead, so reclaim it.
        db.execute("DELETE FROM admin_sessions WHERE id = ?", (token,))
        return False
    return True


def delete_session(token: str | None) -> None:
    if not token:
        return
    db.execute("DELETE FROM admin_sessions WHERE id = ?", (token,))