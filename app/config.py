"""Application settings.

Priority (low to high): built-in defaults < `.env` file < real environment
variables. The `.env` file lives next to run.py (project root, or bundle
directory in the packaged version) and is optional — the app works without
it. No third-party dependency: the parser below is a tiny stdlib reader.
"""
import logging
import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent  # project root / bundle dir
ENV_FILE = ROOT / ".env"

_DEFAULT_PORT = 8001


def _parse_bool(value: str, default: bool) -> bool:
    v = value.strip().lower()
    if v in ("1", "true", "yes", "on"):
        return True
    if v in ("0", "false", "no", "off"):
        return False
    return default


def _load_dotenv(path: Path | str) -> dict:
    """Read KEY=VALUE lines. Never overrides real environment variables."""
    values: dict = {}
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError:
        return values
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key, val = key.strip(), val.strip()
        if val[:1] in ("'", '"'):
            # Quoted: a '#' inside the quotes is part of the value, not a
            # comment. The closing quote wins even if a comment follows it.
            quote = val[0]
            end = val.find(quote, 1)
            if end > 0:
                val = val[1:end]
            else:
                val = val[1:].split("#", 1)[0].strip()
        elif "#" in val:  # trailing comment outside quotes
            val = val.split("#", 1)[0].rstrip()
        if key and key not in os.environ and key not in values:
            values[key] = val
    return values


_file_values = _load_dotenv(ENV_FILE)


def get(key: str, default: str = "") -> str:
    if key in os.environ:
        return os.environ[key]
    return _file_values.get(key, default)


def _get_port() -> int:
    try:
        return int(get("PORT", str(_DEFAULT_PORT)))
    except ValueError:
        return _DEFAULT_PORT


HOST = get("HOST", "127.0.0.1")
PORT = _get_port()
REGISTRATION_ENABLED = _parse_bool(get("REGISTRATION_ENABLED", "true"), True)


def _get_busy_timeout_ms() -> int:
    try:
        ms = int(get("DB_BUSY_TIMEOUT_MS", "10000"))
    except ValueError:
        return 10000
    return max(1000, min(ms, 120000))


def _get_int(key: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(get(key, str(default)))
    except ValueError:
        return default
    return max(minimum, min(value, maximum))


def _get_float(key: str, default: float, minimum: float, maximum: float) -> float:
    try:
        value = float(get(key, str(default)))
    except ValueError:
        return default
    return max(minimum, min(value, maximum))


# How long SQLite waits on a locked database before raising
# "database is locked" (writes additionally retry, see db.execute).
DB_BUSY_TIMEOUT_MS = _get_busy_timeout_ms()

# --- transport security (P0/P1 hardening) ---
# TLS certificate for HTTPS/WSS. Empty = plain HTTP (local dev).
SSL_CERTFILE = get("SSL_CERTFILE", "")
SSL_KEYFILE = get("SSL_KEYFILE", "")
# Max WebSocket frame size in bytes (DoS guard: full frames are parsed
# before the 1000-char message limit applies).
WS_MAX_SIZE_BYTES = _get_int("WS_MAX_SIZE_BYTES", 65536, 4096, 16 * 1024 * 1024)
# Absolute session lifetime in days (0 = expire immediately; for tests).
SESSION_LIFETIME_DAYS = _get_int("SESSION_LIFETIME_DAYS", 30, 0, 3650)
# Idle lifetime in days: a session unused for this long is dead even if it is
# inside the absolute window. A stolen cookie that keeps being used looks
# exactly like a live one, so an absolute bound alone gives the server no
# signal to act on (A-03). 0 disables the idle check.
SESSION_IDLE_DAYS = _get_int("SESSION_IDLE_DAYS", 14, 0, 3650)
# Rate limits (per window, sliding). Tuned for humans, not floods.
RATE_LOGIN_PER_MIN = _get_int("RATE_LOGIN_PER_MIN", 20, 1, 10000)
RATE_REGISTER_PER_MIN = _get_int("RATE_REGISTER_PER_MIN", 30, 1, 10000)
RATE_MSG_PER_MIN = _get_int("RATE_MSG_PER_MIN", 120, 1, 100000)
RATE_ADMIN_LOGIN_PER_MIN = _get_int("RATE_ADMIN_LOGIN_PER_MIN", 10, 1, 10000)
# Backoff for FAILED admin logins (A-04). The sliding window above bounds the
# rate of attempts; these bound the total, because the delay for the Nth
# failure in a row is step * 2 ** max(0, N - grace) seconds. The grace period
# keeps the first few fat-fingered attempts free; past it the curve doubles
# per failure, so a scripted attack slows to nothing. Step 0 disables the
# backoff entirely and leaves only the window.
ADMIN_LOCKOUT_STEP = _get_float("ADMIN_LOCKOUT_STEP", 1.0, 0.0, 60.0)
ADMIN_LOCKOUT_GRACE = _get_float("ADMIN_LOCKOUT_GRACE", 5.0, 0.0, 100.0)
ADMIN_LOCKOUT_MAX = _get_float("ADMIN_LOCKOUT_MAX", 120.0, 0.0, 3600.0)
# A failure counts half as much after this many seconds, so an operator who
# fumbles a couple of times is never locked out.
ADMIN_LOCKOUT_HALF_LIFE = _get_float("ADMIN_LOCKOUT_HALF_LIFE", 300.0, 10.0, 86400.0)

# --- WebSocket connection limits (DoS guard) ---
# The message rate limit bounds how much one socket can SAY, not how many
# sockets a client can OPEN; without these, a single client can hold thousands
# of open connections, each one a coroutine plus a row in the peer table.
# Per user, so one account cannot exhaust the server.
MAX_SOCKETS_PER_USER = _get_int("MAX_SOCKETS_PER_USER", 5, 1, 1000)
# Per client IP, which is what actually bounds a flood spread across accounts.
MAX_SOCKETS_PER_IP = _get_int("MAX_SOCKETS_PER_IP", 20, 1, 10000)

# Reverse-proxy support. Rate limits are keyed on the direct peer address by
# default, because X-Forwarded-For is client-spoofable. Behind a proxy that
# makes every user share one key, so MAX_SOCKETS_PER_IP becomes a site-wide
# socket ceiling. Name the proxy here and the header is believed -- but only
# from a request that actually arrived from a listed address, and only its
# rightmost untrusted hop is used.
# Examples: "127.0.0.1,::1" for a local nginx, or the pod/service CIDR.
TRUSTED_PROXY_CIDRS = [c.strip() for c in get("TRUSTED_PROXY_CIDRS", "").split(",")
                      if c.strip()]

# --- process model ---
# Number of uvicorn worker processes. 1 is the supported default: SQLite and
# the WebSocket fan-out are shared safely, and no load balancer is needed.
# >1 runs several processes against one shared database (WAL is enabled
# automatically); see run.py for the extra checks that implies.
WORKERS = _get_int("WORKERS", 1, 1, 256)
# With >1 worker the public-room broadcast is per-process, so clients on
# different workers land in different rooms. Set this to true only if that is
# acceptable (or if a sticky-session proxy guarantees one worker per client).
ALLOW_SPLIT_ROOMS = _parse_bool(get("ALLOW_SPLIT_ROOMS", "false"), False)

# --- application-layer encrypted transport (TLS alternative) ---
# When enabled, the browser negotiates an encrypted channel with the server
# (ECDH P-256 + ECDSA + HKDF + AES-256-GCM) and sends no session cookies, so
# neither credentials, tokens nor messages travel in cleartext. Set to false
# to fall back to plain HTTP (not recommended).
ENC_ENABLED = _parse_bool(get("ENC_ENABLED", "true"), True)
# Show the server key fingerprint in the UI and pin it (TOFU). Keep enabled:
# this is what makes a MITM detectable.
ENC_SHOW_FINGERPRINT = _parse_bool(get("ENC_SHOW_FINGERPRINT", "true"), True)
# Handshakes per minute per IP. Generous enough for many users behind one NAT
# (a school/office), still bounded against abuse.
ENC_HANDSHAKE_PER_MIN = _get_int("ENC_HANDSHAKE_PER_MIN", 120, 5, 100000)

# --- admin panel ---
# to the default. The panel only exists when a password is configured.
# Prefixes owned by another feature. The admin routes are registered before
# the encrypted-bridge routes, so an ADMIN_PATH that collides with one would
# shadow it: ADMIN_PATH=/enc would serve the panel at /enc and turn
# /enc/api/login into the admin login instead of the bridge's.
_RESERVED_PATHS = {
    "/", "/login", "/register", "/chat", "/api", "/static", "/ws", "/enc",
}


def _get_admin_path() -> str:
    p = get("ADMIN_PATH", "/admin").strip()
    if not p.startswith("/"):
        p = "/" + p
    p = p.rstrip("/") or "/"
    if (
        not re.fullmatch(r"/[A-Za-z0-9_-]+", p)
        or p in _RESERVED_PATHS
        or p.startswith("/api/")
    ):
        logging.getLogger("chat").warning(
            "Ignoring unsafe ADMIN_PATH %r, using /admin", get("ADMIN_PATH", "")
        )
        return "/admin"
    return p


ADMIN_PATH = _get_admin_path()
# Empty = admin panel disabled entirely (all its routes return 404).
ADMIN_PASSWORD = get("ADMIN_PASSWORD", "")
# Optional PBKDF2 hash of the admin password, so the secret on disk can be a
# hash instead of the password itself. Generate one with:
#   python -c "from app.auth import hash_password; print(hash_password(input()))"
# Set it alongside ADMIN_PASSWORD (or on its own -- a hash alone is enough to
# authenticate). When present it wins, and ADMIN_PASSWORD is never compared.
ADMIN_PASSWORD_HASH = get("ADMIN_PASSWORD_HASH", "")
