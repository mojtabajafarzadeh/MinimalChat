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
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
            val = val[1:-1]
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
# Rate limits (per window, sliding). Tuned for humans, not floods.
RATE_LOGIN_PER_MIN = _get_int("RATE_LOGIN_PER_MIN", 20, 1, 10000)
RATE_REGISTER_PER_MIN = _get_int("RATE_REGISTER_PER_MIN", 30, 1, 10000)
RATE_MSG_PER_MIN = _get_int("RATE_MSG_PER_MIN", 120, 1, 100000)
RATE_ADMIN_LOGIN_PER_MIN = _get_int("RATE_ADMIN_LOGIN_PER_MIN", 10, 1, 10000)

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
# to the default. The panel only exists when ADMIN_PASSWORD is set.
_RESERVED_PATHS = {"/", "/login", "/register", "/chat", "/api", "/static", "/ws"}


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
