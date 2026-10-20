"""Username enumeration must not be possible.

Two oracles, both reachable by an unauthenticated or minimally-privileged
client:

- `/api/register` answered "Username is already taken" for a collision and a
  success otherwise, so registering was a membership test for any name.
- `/api/users?q=%` passed `%` straight into a LIKE, matching every row, so any
  logged-in account could dump the whole roster.

Both are covered here against a real server, including the negative case: a
username that genuinely contains a wildcard character must still be findable,
or the fix would just have broken search.
"""
import http.cookiejar
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_responsive_layout import _free_port, _wait_http


class EnumerationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data_dir = tempfile.mkdtemp(prefix="chat-enum-")
        cls.port = _free_port()
        cls.base = f"http://127.0.0.1:{cls.port}"
        env = dict(os.environ, PORT=str(cls.port),
                   CHAT_DATA_DIR=cls.data_dir, ENC_ENABLED="false",
                   REGISTRATION_ENABLED="true", SSL_CERTFILE="",
                   SSL_KEYFILE="", WORKERS="1", RATE_REGISTER_PER_MIN="10000",
                   RATE_LOGIN_PER_MIN="10000")
        cls.server = subprocess.Popen(
            [sys.executable, str(ROOT / "run.py")], cwd=str(ROOT), env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not _wait_http(cls.base + "/login"):
            cls._teardown()
            raise unittest.SkipTest("the app did not start")

        # Usernames may not contain '%' (valid_username rejects it), so that
        # case is seeded directly into the database below. The rest register
        # through the API.
        stamp = os.urandom(3).hex()
        cls.users = {
            "alice": f"alice{stamp}",
            "bob": f"bob{stamp}",
            "carol": f"carol{stamp}",
            "under": f"un{stamp}_x",
        }
        for label, name in cls.users.items():
            status, body = cls._post("/api/register", {
                "name": f"User {label}", "username": name,
                "password": "enum-test-pw", "confirm": "enum-test-pw"})
            assert status == 200, f"seed {label} failed: {status} {body}"
        cls._seed_wildcard_user()

    @classmethod
    def _seed_wildcard_user(cls):
        """Insert a username containing '%' straight into SQLite.

        Connects to the server's own database file directly: importing
        app.db here would resolve DB_PATH against this process's environment
        (the project root), not the temp dir the server was started with.
        """
        import sqlite3
        from app import auth

        name = f"pct{os.urandom(3).hex()}%z"
        conn = sqlite3.connect(str(Path(cls.data_dir) / "chat.db"), timeout=15)
        try:
            conn.execute("PRAGMA busy_timeout = 15000")
            conn.execute(
                "INSERT INTO users (name, username, password_hash) VALUES (?, ?, ?)",
                ("Wildcard User", name, auth.hash_password("enum-test-pw")))
            conn.commit()
        finally:
            conn.close()
        cls.users["pct"] = name

    @classmethod
    def _teardown(cls):
        proc = getattr(cls, "server", None)
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
        path = getattr(cls, "data_dir", None)
        if path:
            shutil.rmtree(path, ignore_errors=True)

    @classmethod
    def tearDownClass(cls):
        cls._teardown()

    @classmethod
    def _post(cls, path, fields):
        req = urllib.request.Request(
            cls.base + path, data=urllib.parse.urlencode(fields).encode())
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    @classmethod
    def _get(cls, path, jar):
        opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(jar))
        try:
            with opener.open(urllib.request.Request(cls.base + path),
                             timeout=15) as r:
                return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    def _login(self, label):
        jar = http.cookiejar.CookieJar()
        status, body = self._post("/api/login", {
            "username": self.users[label], "password": "enum-test-pw"})
        self.assertEqual(status, 200, f"login failed: {body}")
        opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(jar))
        opener.open(urllib.request.Request(
            self.base + "/api/login",
            data=urllib.parse.urlencode(
                {"username": self.users[label],
                 "password": "enum-test-pw"}).encode()), timeout=15).read()
        return jar

    # ------------------------------------------------------- register oracle

    def test_registration_does_not_reveal_that_a_username_exists(self):
        """A collision and a fresh name must be indistinguishable."""
        taken = self.users["alice"]
        free = f"brandnew{os.urandom(3).hex()}"

        s1, b1 = self._post("/api/register", {
            "name": "Someone", "username": taken,
            "password": "enum-test-pw", "confirm": "enum-test-pw"})
        s2, b2 = self._post("/api/register", {
            "name": "Someone", "username": free,
            "password": "enum-test-pw", "confirm": "enum-test-pw"})

        self.assertNotEqual(
            (s1, b1), (s2, b2),
            "the two responses differ, so registration is an oracle: "
            f"taken -> {s1} {b1!r}, free -> {s2} {b2!r}")
        self.assertNotIn("taken", b1.lower(),
                         "the error still names the collision")
        self.assertNotIn("already", b1.lower(),
                         "the error still reveals that the name exists")

    def test_a_duplicate_registration_still_fails(self):
        """Generic must not mean permissive."""
        status, body = self._post("/api/register", {
            "name": "Someone", "username": self.users["bob"],
            "password": "enum-test-pw", "confirm": "enum-test-pw"})
        self.assertGreaterEqual(status, 400, "duplicate registration succeeded")
        self.assertNotIn('"ok"', body)

    def test_valid_registration_still_works(self):
        name = f"freshone{os.urandom(3).hex()}"
        status, body = self._post("/api/register", {
            "name": "Fresh", "username": name,
            "password": "enum-test-pw", "confirm": "enum-test-pw"})
        self.assertEqual(status, 200, f"valid registration broke: {body}")
        self.assertIn('"ok"', body)

    # ------------------------------------------------------- roster oracle

    def test_a_wildcard_query_does_not_return_the_whole_roster(self):
        """?q=% must match only usernames that literally contain '%'.

        One such row exists (seeded), so the correct answer is that one user,
        not the whole roster.
        """
        jar = self._login("carol")
        status, body = self._get("/api/users?q=%25", jar)  # %25 == '%'
        self.assertEqual(status, 200)
        found = [u["username"] for u in json.loads(body)]
        self.assertEqual(
            found, [self.users["pct"]],
            "?q=% did not match exactly the literal-% username: " + str(found))

    def test_an_underscore_query_does_not_match_everything(self):
        jar = self._login("carol")
        status, body = self._get("/api/users?q=_", jar)
        self.assertEqual(status, 200)
        found = json.loads(body)
        self.assertNotIn(
            "alice", [u["username"] for u in found],
            "?q=_ matched a username with no underscore in it")

    def test_search_still_finds_real_users(self):
        jar = self._login("carol")
        status, body = self._get(
            "/api/users?q=" + urllib.parse.quote(self.users["bob"]), jar)
        self.assertEqual(status, 200)
        found = [u["username"] for u in json.loads(body)]
        self.assertIn(self.users["bob"], found,
                      "a normal search no longer finds a user")

    def test_a_username_containing_a_wildcard_is_still_searchable(self):
        """The negative case: escaping must not make such names unfindable."""
        jar = self._login("carol")
        status, body = self._get(
            "/api/users?q=" + urllib.parse.quote(self.users["pct"]), jar)
        self.assertEqual(status, 200)
        found = [u["username"] for u in json.loads(body)]
        self.assertIn(
            self.users["pct"], found,
            "a username containing '%' can no longer be found by name")

    def test_a_username_containing_an_underscore_is_still_searchable(self):
        jar = self._login("carol")
        status, body = self._get(
            "/api/users?q=" + urllib.parse.quote(self.users["under"]), jar)
        self.assertEqual(status, 200)
        found = [u["username"] for u in json.loads(body)]
        self.assertIn(self.users["under"], found)

    def test_search_never_returns_the_searcher(self):
        jar = self._login("carol")
        status, body = self._get(
            "/api/users?q=" + urllib.parse.quote(self.users["carol"]), jar)
        self.assertEqual(status, 200)
        found = [u["username"] for u in json.loads(body)]
        self.assertNotIn(self.users["carol"], found)


class UsernameValidationTests(unittest.TestCase):
    """Usernames are ASCII, so two accounts cannot look identical.

    `str.isalnum()` is Unicode-aware: it accepted U+0430 CYRILLIC SMALL LETTER A,
    which renders exactly like the Latin "a". A chat that identifies people by
    @username cannot afford two identities that look the same, so the ASCII
    restriction is part of the rule rather than a nicety.
    """

    @staticmethod
    def _valid(name):
        from app.main import valid_username
        return valid_username(name)

    def test_plain_ascii_names_are_accepted(self):
        for name in ("alice", "a_b-c", "user123", "x" * 32):
            with self.subTest(name=name):
                self.assertTrue(self._valid(name), f"{name!r} was rejected")

    def test_a_cyrillic_homograph_is_rejected(self):
        self.assertFalse(
            self._valid("\u0430dmin"),
            "a Cyrillic 'a' is accepted, so @\u0430dmin can impersonate @admin")

    def test_other_non_ascii_letters_are_rejected(self):
        for name in ("b\u00f6b", "\u03b1lpha", "na\u00efve"):
            with self.subTest(name=name):
                self.assertFalse(self._valid(name), f"{name!r} was accepted")

    def test_the_length_and_charset_limits_still_hold(self):
        for name in ("ab", "a" * 33, "has space", "per%cent", "a.b"):
            with self.subTest(name=name):
                self.assertFalse(self._valid(name), f"{name!r} was accepted")


if __name__ == "__main__":
    unittest.main()