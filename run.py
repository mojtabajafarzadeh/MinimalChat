"""Single-command startup: `python run.py`. Installs deps, creates DB, serves the app.

Process model
-------------
WORKERS defaults to 1: one process owns the WebSocket fan-out and the
encrypted-channel state, so there is nothing to coordinate.

Raising WORKERS runs several uvicorn processes against ONE shared SQLite
database. Before doing that this script fails fast on the two things that
would silently break:

1. A network filesystem. SQLite's WAL journal mode needs shared memory, which
   NFS/CIFS/9p and friends do not provide; SQLite documents WAL as unsupported
   there, so the result is broken locking and potential data loss.
2. The public-room broadcast. Each worker only knows its own sockets, so
   clients spread over several workers see separate rooms. Set
   ALLOW_SPLIT_ROOMS=true to accept that deliberately (e.g. behind a
   sticky-session proxy that keeps each client on one worker).
"""
import logging
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def _load_dotenv(path) -> dict:
    """Minimal KEY=VALUE reader for the one setting needed before install.

    Duplicated from app.config on purpose: ensure_deps() has to run before the
    app package is importable (that is the whole point -- the deps may not be
    installed yet). Real environment variables still win over the file.
    """
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
            # comment. Closing quote wins, even if a comment follows it.
            quote = val[0]
            end = val.find(quote, 1)
            if end > 0:
                val = val[1:end]
            else:
                val = val[1:].split("#", 1)[0].strip()
        elif "#" in val:
            val = val.split("#", 1)[0].rstrip()
        if key and key not in os.environ and key not in values:
            values[key] = val
    return values


# Shown in the startup log, the UI and the README when the operator has
# deliberately accepted per-worker rooms.
SPLIT_ROOMS_WARNING = (
    "Split-rooms mode is active: users on different workers do not see each "
    "other's messages. Public chat is split into one room per worker process. "
    "Keep WORKERS=1 unless you really want this."
)


# Module-level logger (pattern used elsewhere in the codebase)
log = logging.getLogger("chat")


def log_server_identity() -> None:
    """Print the server's long-term fingerprint at startup.

    The fingerprint is what makes the encrypted channel verifiable: the browser
    only ever learns it from the same connection it is trying to verify, so on
    its own it proves nothing. Printing it here gives the operator a way to read
    it over a channel the client does not control (SSH console, container log,
    the machine in front of them) and pin it in the UI.

    It is derived from the persisted signing key, so it survives restarts and
    is identical for every worker.
    """
    from app.config import ENC_ENABLED

    if not ENC_ENABLED:
        return
    try:
        from app import enc

        info = enc.status()
    except Exception as exc:
        # Never fail startup over a diagnostic: the key is loaded again on the
        # first handshake, where the real error will surface.
        log.warning("could not read the server identity fingerprint: %s", exc)
        print("WARNING: could not read the server identity fingerprint: " + str(exc),
              flush=True)
        return

    fingerprint = info["fingerprint"]
    log.info("server identity fingerprint: %s", fingerprint)
    print("\n" + "-" * 72, flush=True)
    print("Server identity fingerprint (chat-enc-v1 signing key):", flush=True)
    print("  " + fingerprint, flush=True)
    print("Verify it over a channel the browser cannot influence (this console, "
          "the host's logs), then paste it into 'Server identity' in the web UI "
          "to pin it. Clients that pinned it refuse to connect if it ever changes.",
          flush=True)
    print("-" * 72 + "\n", flush=True)


def _pip_index_args() -> list:
    """Index arguments for pip, from PIP_INDEX_URL (env or .env).

    Unset or blank means PyPI, which is pip's own default -- so the flag is
    omitted entirely rather than passed as empty. The variable is read with
    the same stdlib .env reader app.config uses, because ensure_deps() runs
    before app.config is importable.
    """
    raw = os.environ.get("PIP_INDEX_URL", "")
    if not raw.strip():
        raw = _load_dotenv(ROOT / ".env").get("PIP_INDEX_URL", "")
    raw = raw.strip()
    return ["--index-url", raw] if raw else []


def ensure_deps() -> None:
    try:
        import fastapi, uvicorn, cryptography  # noqa: F401
        return
    except ImportError:
        index = _pip_index_args()
        where = index[1] if index else "PyPI (default)"
        print(f"Installing dependencies (fastapi, uvicorn, cryptography) "
              f"from {where}...")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", *index,
             '-r', str(ROOT / "requirements.txt")]
        )


def preflight(workers: int, allow_split_rooms: bool) -> None:
    """Refuse configurations that cannot work, before anything binds a port.

    Returns nothing; raises SystemExit / RuntimeError when it refuses.
    """
    sys.path.insert(0, str(ROOT))
    from app.paths import check_local_filesystem
    from app.db import DB_PATH

    fstype = check_local_filesystem(DB_PATH.parent, require_local=workers > 1)
    if workers <= 1:
        return

    from app.config import ENC_ENABLED
    if ENC_ENABLED:
        raise SystemExit(
            f"WORKERS={workers} is not supported while ENC_ENABLED=true.\n"
            "The encrypted channel keeps its handshake sessions in the worker "
            "that created them, so a request landing on another worker fails "
            "with 'Session expired'. Either run WORKERS=1 (recommended) or set "
            "ENC_ENABLED=false for a multi-worker deployment."
        )
    if not allow_split_rooms:
        raise SystemExit(
            f"WORKERS={workers} is not supported out of the box: each worker "
            "broadcasts only to its own WebSocket connections, so the public "
            "room is split into one room per worker.\n"
            f"Notes: database is shared via WAL (filesystem: {fstype or 'unknown'}).\n"
            "Set ALLOW_SPLIT_ROOMS=true if that is acceptable, or keep "
            "WORKERS=1 (recommended), or put a sticky-session proxy in front."
        )
    # Accepted deliberately: shout about it, in the log and on screen.
    logging.getLogger("chat").warning(SPLIT_ROOMS_WARNING)
    print("\n" + "!" * 72, flush=True)
    print("WARNING: " + SPLIT_ROOMS_WARNING, flush=True)
    print("!" * 72 + "\n", flush=True)


def main() -> None:
    ensure_deps()
    import uvicorn

    sys.path.insert(0, str(ROOT))
    from app.config import (
        ALLOW_SPLIT_ROOMS,
        HOST,
        PORT,
        SSL_CERTFILE,
        SSL_KEYFILE,
        WS_MAX_SIZE_BYTES,
        WORKERS,
    )
    from app.db import init_db

    preflight(WORKERS, ALLOW_SPLIT_ROOMS)
    init_db()
    log_server_identity()

    use_tls = bool(SSL_CERTFILE and SSL_KEYFILE)
    scheme = "https" if use_tls else "http"
    mode = f"{WORKERS} worker(s)" if WORKERS > 1 else "single process"
    print(f"Chat app running at {scheme}://{HOST}:{PORT} [{mode}]", flush=True)
    uvicorn.run(
        "app.main:app",
        host=HOST,
        port=PORT,
        workers=WORKERS,          # >1 shares one SQLite file in WAL mode
        server_header=False,      # don't advertise the server version
        ws_max_size=WS_MAX_SIZE_BYTES,  # bound WebSocket frame parsing (DoS guard)
        ssl_certfile=SSL_CERTFILE or None,
        ssl_keyfile=SSL_KEYFILE or None,
    )


if __name__ == "__main__":
    main()