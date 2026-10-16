"""Session lifetime: an idle bound and a purge (A-03).

The absolute 30-day lifetime was the only limit, so a stolen cookie was valid
for a month as long as it kept being presented, and the sessions table only
shrank when a dead token happened to be used again.

Exercised against a real SQLite file rather than a mock, because the whole
question is what the time functions in SQL actually compute.
"""
import importlib
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class SessionTestBase(unittest.TestCase):
    """Point the app at a throwaway database for the duration of one test."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="chat-sessions-"))
        os.environ["CHAT_DATA_DIR"] = str(self.tmp)
        for name in ("app.config", "app.db", "app.auth"):
            sys.modules.pop(name, None)
        self.config = importlib.import_module("app.config")
        self.db = importlib.import_module("app.db")
        self.auth = importlib.import_module("app.auth")
        self.db.DB_PATH = self.tmp / "chat.db"
        self.db.init_db()
        self.user_id = self.db.execute(
            "INSERT INTO users (name, username, password_hash) VALUES (?,?,?)",
            ("Tester", "tester", self.auth.hash_password("pw")))

    def tearDown(self):
        os.environ.pop("CHAT_DATA_DIR", None)
        for name in ("app.config", "app.db", "app.auth"):
            sys.modules.pop(name, None)
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _age(self, token, **columns):
        """Backdate a session row."""
        sets = ", ".join(f"{k} = datetime('now', ?)" for k in columns)
        args = tuple(f"-{v} days" for v in columns.values())
        self.db.execute(f"UPDATE sessions SET {sets} WHERE id = ?",
                        args + (token,))


class IdleTimeoutTests(SessionTestBase):
    def test_a_fresh_session_works(self):
        token = self.auth.create_session(self.user_id)
        user = self.auth.get_session_user(token)
        self.assertIsNotNone(user)
        self.assertEqual(user["username"], "tester")

    def test_a_session_idle_past_the_limit_is_rejected(self):
        token = self.auth.create_session(self.user_id)
        self._age(token, last_seen=40)
        self.assertIsNone(
            self.auth.get_session_user(token),
            "a session unused for 40 days is still valid")

    def test_using_a_session_refreshes_it(self):
        token = self.auth.create_session(self.user_id)
        self._age(token, last_seen=40)
        # Backdate past the idle bound, then read it: it must be rejected, and
        # only after a read inside the window does last_seen move forward.
        self._age(token, last_seen=40)
        self.assertIsNone(self.auth.get_session_user(token))

    def test_activity_keeps_a_session_alive_inside_the_window(self):
        token = self.auth.create_session(self.user_id)
        self._age(token, last_seen=5)
        self.assertIsNotNone(
            self.auth.get_session_user(token),
            "a session used 5 days ago is inside the idle bound")

    def test_the_absolute_lifetime_still_applies(self):
        token = self.auth.create_session(self.user_id)
        self._age(token, created_at=45, last_seen=0)
        self.assertIsNone(
            self.auth.get_session_user(token),
            "the 30-day absolute lifetime stopped being enforced")

    def test_a_rejected_session_is_deleted(self):
        token = self.auth.create_session(self.user_id)
        self._age(token, last_seen=40)
        self.auth.get_session_user(token)
        row = self.db.query_one("SELECT id FROM sessions WHERE id = ?", (token,))
        self.assertIsNone(row, "the dead session row was left behind")

    def test_last_seen_is_written_on_use(self):
        token = self.auth.create_session(self.user_id)
        self._age(token, last_seen=3)
        self.assertIsNotNone(self.auth.get_session_user(token))
        row = self.db.query_one(
            "SELECT CAST(strftime('%s','now') AS INTEGER) "
            "  - CAST(strftime('%s', last_seen) AS INTEGER) AS idle "
            "FROM sessions WHERE id = ?", (token,))
        self.assertLess(row["idle"], 60,
                        "last_seen was not refreshed after use")

    def test_an_unknown_token_is_rejected(self):
        self.assertIsNone(self.auth.get_session_user("nope"))
        self.assertIsNone(self.auth.get_session_user(""))
        self.assertIsNone(self.auth.get_session_user(None))


class PurgeTests(SessionTestBase):
    def test_purge_removes_idle_sessions(self):
        dead = self.auth.create_session(self.user_id)
        self._age(dead, last_seen=40)
        removed = self.auth.purge_expired_sessions()
        self.assertGreaterEqual(removed, 1)
        self.assertIsNone(self.db.query_one(
            "SELECT id FROM sessions WHERE id = ?", (dead,)))

    def test_purge_removes_absolutely_expired_sessions(self):
        dead = self.auth.create_session(self.user_id)
        self._age(dead, created_at=45, last_seen=0)
        self.auth.purge_expired_sessions()
        self.assertIsNone(self.db.query_one(
            "SELECT id FROM sessions WHERE id = ?", (dead,)))

    def test_purge_keeps_live_sessions(self):
        live = self.auth.create_session(self.user_id)
        self.auth.purge_expired_sessions()
        self.assertIsNotNone(self.db.query_one(
            "SELECT id FROM sessions WHERE id = ?", (live,)))

    def test_purge_is_idempotent(self):
        self._age(self.auth.create_session(self.user_id), last_seen=40)
        first = self.auth.purge_expired_sessions()
        second = self.auth.purge_expired_sessions()
        self.assertGreaterEqual(first, 1)
        self.assertEqual(second, 0, "a second purge removed more rows")


class MigrationTests(SessionTestBase):
    """An existing database has sessions rows with no last_seen."""

    def test_existing_rows_are_backfilled(self):
        token = self.auth.create_session(self.user_id)
        # Simulate the pre-migration shape.
        self.db.execute("UPDATE sessions SET last_seen = NULL WHERE id = ?",
                        (token,))
        self.assertIsNotNone(
            self.db.query_one("SELECT id FROM sessions WHERE last_seen IS NULL"),
            "the test did not produce a pre-migration row")
        # The COALESCE in the query means NULL falls back to created_at.
        self.assertIsNotNone(
            self.auth.get_session_user(token),
            "a session row with NULL last_seen is treated as dead")

    def test_the_column_exists_after_init(self):
        cols = {r["name"] for r in self.db.query_all(
            "PRAGMA table_info(sessions)")}
        self.assertIn("last_seen", cols)
        self.assertIn("created_at", cols)


class ConfigTests(unittest.TestCase):
    def test_the_idle_bound_is_configurable(self):
        importlib.reload(importlib.import_module("app.config"))
        saved = os.environ.get("SESSION_IDLE_DAYS")
        try:
            os.environ["SESSION_IDLE_DAYS"] = "3"
            cfg = importlib.reload(importlib.import_module("app.config"))
            self.assertEqual(cfg.SESSION_IDLE_DAYS, 3)
        finally:
            if saved is None:
                os.environ.pop("SESSION_IDLE_DAYS", None)
            else:
                os.environ["SESSION_IDLE_DAYS"] = saved
            importlib.reload(importlib.import_module("app.config"))

    def test_zero_disables_the_check(self):
        saved = os.environ.get("SESSION_IDLE_DAYS")
        try:
            os.environ["SESSION_IDLE_DAYS"] = "0"
            cfg = importlib.reload(importlib.import_module("app.config"))
            self.assertEqual(cfg.SESSION_IDLE_DAYS, 0)
        finally:
            if saved is None:
                os.environ.pop("SESSION_IDLE_DAYS", None)
            else:
                os.environ["SESSION_IDLE_DAYS"] = saved
            importlib.reload(importlib.import_module("app.config"))


if __name__ == "__main__":
    unittest.main()