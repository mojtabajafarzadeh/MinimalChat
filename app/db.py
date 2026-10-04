"""SQLite helpers. Uses only Python's built-in sqlite3 module.

Concurrency model (single server process):
- WAL journal mode: readers never block writers and vice versa.
- Every call opens its own short-lived connection (never shared between
  threads), so reads need no lock at all.
- Writes take a small in-process lock and additionally retry with backoff
  on "database is locked", after the busy-timeout has been exhausted.
- busy_timeout (DB_BUSY_TIMEOUT_MS, default 10s) makes transient locks wait
  instead of failing fast.

messages table shape (current):
    id, sender_id, recipient_id (NULL = public), reply_to_id (NULL = no
    reply), content (Fernet ciphertext, never plaintext), created_at

Migration: databases created by the older version have
messages(id, user_id, content=plaintext, created_at). On startup the old
rows are copied into the new shape with their content encrypted, and only
then is the old table replaced. If anything fails mid-migration the old
table is left untouched, so no user data is destroyed.
"""
import logging
import os
import sqlite3
import threading
import time

from . import crypto
from .config import DB_BUSY_TIMEOUT_MS
from .paths import data_dir

log = logging.getLogger("chat")

# chat.db lives in CHAT_DATA_DIR (or the project root by default).
DB_PATH = data_dir() / "chat.db"

# Serializes writers inside this process. Readers take no lock: under WAL
# each of them uses its own connection and never blocks on writers.
# _init_lock guards startup/migration only.
_write_lock = threading.Lock()
_init_lock = threading.Lock()
_WRITE_RETRIES = 3

NEW_MESSAGES_SQL = """
CREATE TABLE messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recipient_id INTEGER NULL REFERENCES users(id) ON DELETE CASCADE,
    reply_to_id INTEGER NULL REFERENCES messages(id),
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""

DM_INDEX_SQL = (
    "CREATE INDEX IF NOT EXISTS idx_messages_dm "
    "ON messages (sender_id, recipient_id)"
)


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(
        str(DB_PATH), check_same_thread=False, timeout=DB_BUSY_TIMEOUT_MS / 1000
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute(f"PRAGMA busy_timeout = {DB_BUSY_TIMEOUT_MS}")
    return conn


def _columns(conn: sqlite3.Connection, table: str) -> list:
    return [r["name"] for r in conn.execute(f"PRAGMA table_info({table})")]


def _migrate_messages(conn: sqlite3.Connection) -> None:
    tables = {
        r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    if "messages" not in tables:
        conn.execute(NEW_MESSAGES_SQL)
        conn.execute(DM_INDEX_SQL)
        return
    if "sender_id" in _columns(conn, "messages"):
        # Already on the new schema.
        conn.execute(DM_INDEX_SQL)
        return
    # Old schema: messages(id, user_id, content=plaintext, created_at).
    # Copy rows into the new shape, encrypting content, before dropping.
    old_rows = conn.execute(
        "SELECT id, user_id, content, created_at FROM messages ORDER BY id"
    ).fetchall()
    conn.execute("DROP TABLE IF EXISTS messages_new")
    conn.execute(NEW_MESSAGES_SQL.replace("TABLE messages", "TABLE messages_new"))
    for r in old_rows:
        conn.execute(
            "INSERT INTO messages_new (id, sender_id, recipient_id, content, created_at)"
            " VALUES (?, ?, NULL, ?, ?)",
            (r["id"], r["user_id"], crypto.encrypt(r["content"]), r["created_at"]),
        )
    copied = conn.execute("SELECT COUNT(*) FROM messages_new").fetchone()[0]
    if copied != len(old_rows):
        raise RuntimeError(
            f"Message migration aborted: copied {copied} of {len(old_rows)} rows. "
            "Old table left untouched."
        )
    conn.execute("DROP TABLE messages")
    conn.execute("ALTER TABLE messages_new RENAME TO messages")
    conn.execute(DM_INDEX_SQL)


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _init_lock:
        conn = get_conn()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                -- Admin panel sessions live here too so they survive restarts
                -- and work across worker processes sharing this database.
                CREATE TABLE IF NOT EXISTS admin_sessions (
                    id TEXT PRIMARY KEY,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL
                );
                """
            )
            _migrate_messages(conn)
            # Reply references (added later): nullable, no backfill needed.
            if "reply_to_id" not in _columns(conn, "messages"):
                conn.execute(
                    "ALTER TABLE messages ADD COLUMN reply_to_id "
                    "INTEGER NULL REFERENCES messages(id)"
                )
            # WAL: readers don't block writers (persisted in the db file).
            # NORMAL synchronous is the documented safe pairing with WAL.
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.commit()
            _lock_down_files()
        finally:
            conn.close()


def _lock_down_files() -> None:
    """Database files hold ciphertext + hashes: owner-only access,
    like .chat_secret (WAL sidecar files included)."""
    for suffix in ("", "-wal", "-shm", "-journal"):
        try:
            os.chmod(DB_PATH.parent / f"{DB_PATH.name}{suffix}", 0o600)
        except OSError:
            pass


def query_one(sql: str, params: tuple = ()):
    # No lock: own short-lived connection per call + WAL => safe & concurrent.
    conn = get_conn()
    try:
        cur = conn.execute(sql, params)
        return cur.fetchone()
    finally:
        conn.close()


def query_all(sql: str, params: tuple = ()):
    # No lock: own short-lived connection per call + WAL => safe & concurrent.
    conn = get_conn()
    try:
        cur = conn.execute(sql, params)
        return cur.fetchall()
    finally:
        conn.close()


def execute(sql: str, params: tuple = ()):
    """Run INSERT/UPDATE/DELETE, return lastrowid.

    Retries with backoff if the database is momentarily locked, so a burst
    of concurrent writers degrades gracefully instead of erroring out.
    """
    with _write_lock:
        last_exc: Exception | None = None
        for attempt in range(_WRITE_RETRIES + 1):
            try:
                conn = get_conn()
                try:
                    cur = conn.execute(sql, params)
                    conn.commit()
                    return cur.lastrowid
                finally:
                    conn.close()
            except sqlite3.OperationalError as e:
                if "locked" in str(e).lower() and attempt < _WRITE_RETRIES:
                    last_exc = e
                    log.warning("sqlite busy, retrying write (%d/%d)",
                                attempt + 1, _WRITE_RETRIES)
                    time.sleep(0.05 * (2 ** attempt))
                    continue
                raise
        raise last_exc  # pragma: no cover - loop always returns or raises
