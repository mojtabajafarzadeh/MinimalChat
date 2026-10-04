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
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# Shown in the startup log, the UI and the README when the operator has
# deliberately accepted per-worker rooms.
SPLIT_ROOMS_WARNING = (
    "Split-rooms mode is active: users on different workers do not see each "
    "other's messages. Public chat is split into one room per worker process. "
    "Keep WORKERS=1 unless you really want this."
)


def ensure_deps() -> None:
    try:
        import fastapi, uvicorn, cryptography  # noqa: F401
        return
    except ImportError:
        print("Installing dependencies (fastapi, uvicorn, cryptography)...")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "-i", "https://mirror.ferdowsi.cloud/artifactory/api/pypi/pip-virtual/simple", '-r', str(ROOT / "requirements.txt")]
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