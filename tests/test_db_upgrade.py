"""The upgrade path: an existing database must still start.

Adding a column is the kind of change that is invisible on a fresh install and
fatal on a real one. `init_db` ran the backfill UPDATE and then, still inside
the transaction Python's sqlite3 had opened implicitly, tried
`PRAGMA synchronous=NORMAL` -- which refuses to run inside a transaction. On a
database already in WAL mode, which is every database this app has ever
written, startup raised and the server exited.

Fresh installs never saw it, because the CREATE TABLE already has the column
and the migration branch is skipped. These tests build databases the OLD code
would have produced and run the real init_db against them.
"""
import importlib
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# The schema as it was before last_seen existed (commit 28ff07d and earlier).
OLD_SCHEMA = """
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE sessions (
        id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE admin_sessions (
        id TEXT PRIMARY KEY,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP NOT NULL
    );
    CREATE TABLE messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        recipient_id INTEGER NULL REFERENCES users(id) ON DELETE CASCADE,
        reply_to_id INTEGER NULL REFERENCES messages(id),
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
"""


class UpgradeTestBase(unittest.TestCase):
    def _build_old_db(self, path, journal="WAL", with_data=True):
        conn = sqlite3.connect(str(path))
        try:
            if journal:
                conn.execute(f"PRAGMA journal_mode={journal}")
            conn.executescript(OLD_SCHEMA)
            if with_data:
                conn.execute(
                    "INSERT INTO users (name, username, password_hash) "
                    "VALUES ('Alice', 'alice', 'hash')")
                conn.execute(
                    "INSERT INTO sessions (id, user_id) VALUES ('tok-alice', 1)")
            conn.commit()
        finally:
            conn.close()

    def _init_against(self, directory):
        """Run the real init_db against the database in `directory`."""
        os.environ["CHAT_DATA_DIR"] = str(directory)
        for name in ("app.config", "app.db", "app.auth", "app.crypto",
                     "app.paths"):
            sys.modules.pop(name, None)
        importlib.import_module("app.config")
        db = importlib.import_module("app.db")
        db.DB_PATH = Path(directory) / "chat.db"
        db.init_db()
        return db


class WalUpgradeTests(UpgradeTestBase):
    """The case that actually breaks: an existing deployment is in WAL."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="chat-upgrade-wal-"))
        self._build_old_db(self.tmp / "chat.db", journal="WAL")

    def tearDown(self):
        os.environ.pop("CHAT_DATA_DIR", None)
        for name in ("app.config", "app.db", "app.auth", "app.crypto",
                     "app.paths"):
            sys.modules.pop(name, None)

    def test_an_existing_wal_database_still_starts(self):
        """The regression: this raised
        OperationalError: Safety level may not be changed inside a transaction
        and took the server down at startup."""
        self._init_against(self.tmp)          # must not raise

    def test_the_column_is_added(self):
        self._init_against(self.tmp)
        conn = sqlite3.connect(self.tmp / "chat.db")
        try:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(sessions)")}
        finally:
            conn.close()
        self.assertIn("last_seen", cols,
                      "the migration did not run")

    def test_existing_sessions_survive_and_are_backfilled(self):
        """A user's live session must not be invalidated by the upgrade."""
        self._init_against(self.tmp)
        conn = sqlite3.connect(self.tmp / "chat.db")
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute(
                "SELECT id, last_seen, created_at FROM sessions").fetchone()
        finally:
            conn.close()
        self.assertIsNotNone(row, "the existing session row was lost")
        self.assertEqual(row["id"], "tok-alice")
        self.assertIsNotNone(
            row["last_seen"],
            "last_seen was left NULL, which would expire the session on the "
            "next read instead of treating it as active now")

    def test_the_pragmas_are_applied_after_upgrading(self):
        """The commit has to happen BEFORE the PRAGMAs, not only at the end."""
        self._init_against(self.tmp)
        conn = sqlite3.connect(self.tmp / "chat.db")
        try:
            mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(mode.lower(), "wal",
                         "journal_mode was not re-asserted on the upgraded DB")

    def test_upgrading_twice_is_harmless(self):
        self._init_against(self.tmp)          # first run migrates
        self._init_against(self.tmp)          # second is a no-op
        conn = sqlite3.connect(self.tmp / "chat.db")
        try:
            rows = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(rows, 1, "the session row was duplicated or dropped")


class DeleteJournalUpgradeTests(UpgradeTestBase):
    """A database from before WAL was introduced."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="chat-upgrade-dj-"))
        self._build_old_db(self.tmp / "chat.db", journal=None)

    def tearDown(self):
        os.environ.pop("CHAT_DATA_DIR", None)
        for name in ("app.config", "app.db", "app.auth", "app.crypto",
                     "app.paths"):
            sys.modules.pop(name, None)

    def test_a_delete_journal_database_is_upgraded_to_wal(self):
        self._init_against(self.tmp)
        conn = sqlite3.connect(self.tmp / "chat.db")
        try:
            mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
            cols = {r[1] for r in conn.execute("PRAGMA table_info(sessions)")}
        finally:
            conn.close()
        self.assertEqual(mode.lower(), "wal",
                         "a delete-journal DB was not moved to WAL")
        self.assertIn("last_seen", cols)


class EmptyUpgradeTests(UpgradeTestBase):
    """An old database with no rows at all -- the UPDATE still opens a
    transaction, so it needs the commit too."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="chat-upgrade-empty-"))
        self._build_old_db(self.tmp / "chat.db", journal="WAL",
                           with_data=False)

    def tearDown(self):
        os.environ.pop("CHAT_DATA_DIR", None)
        for name in ("app.config", "app.db", "app.auth", "app.crypto",
                     "app.paths"):
            sys.modules.pop(name, None)

    def test_an_empty_old_database_upgrades(self):
        self._init_against(self.tmp)


class FreshInstallTests(UpgradeTestBase):
    """A clean install never took the migration branch; it must still work."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="chat-fresh-"))

    def tearDown(self):
        os.environ.pop("CHAT_DATA_DIR", None)
        for name in ("app.config", "app.db", "app.auth", "app.crypto",
                     "app.paths"):
            sys.modules.pop(name, None)

    def test_a_fresh_install_creates_everything(self):
        self._init_against(self.tmp)
        conn = sqlite3.connect(self.tmp / "chat.db")
        try:
            tables = {r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
            cols = {r[1] for r in conn.execute("PRAGMA table_info(sessions)")}
        finally:
            conn.close()
        self.assertIn("sessions", tables)
        self.assertIn("last_seen", cols)

    def test_a_fresh_install_starts_twice(self):
        self._init_against(self.tmp)
        self._init_against(self.tmp)


class CommitOrderingTests(unittest.TestCase):
    """A structural guard: the commit must sit before the PRAGMAs, or this
    only shows up again on somebody's upgrade."""

    def test_commit_precedes_the_pragmas(self):
        src = (ROOT / "app" / "db.py").read_text(encoding="utf-8")
        body = src.split("def init_db", 1)[1].split("def _lock_down_files", 1)[0]
        wal_at = body.index('PRAGMA journal_mode=WAL')
        sync_at = body.index("PRAGMA synchronous=NORMAL")
        # The LAST commit before the first PRAGMA is the one that matters --
        # rindex over the whole body would find the commit AFTER them.
        head = body[:wal_at]
        self.assertIn("conn.commit()", head,
                      "nothing is committed before journal_mode is set")
        commit_at = head.rindex("conn.commit()")
        self.assertLess(commit_at, wal_at,
                        "the migrations are still uncommitted when "
                        "journal_mode is set")
        self.assertLess(commit_at, sync_at,
                        "the migrations are still uncommitted when "
                        "synchronous is set")

    def test_no_write_lands_between_the_last_commit_and_the_pragmas(self):
        """A future migration added after the commit would reopen the window."""
        src = (ROOT / "app" / "db.py").read_text(encoding="utf-8")
        body = src.split("def init_db", 1)[1].split("def _lock_down_files", 1)[0]
        tail = body[body.rindex("conn.commit()"):]
        for statement in ("INSERT ", "UPDATE ", "ALTER ", "DELETE ",
                          "CREATE ", "DROP "):
            with self.subTest(statement=statement):
                self.assertNotIn(
                    statement, tail,
                    f"a {statement.strip()} appears after the final commit "
                    "and before the PRAGMAs; it would reopen the transaction "
                    "that makes them fail")


if __name__ == "__main__":
    unittest.main()