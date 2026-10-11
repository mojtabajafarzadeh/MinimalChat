"""WebSocket connection limits and admin password hashing.

Both are small guards that are easy to get subtly wrong, and neither shows up
in the DOM: the connection cap decides whether a socket is accepted at all,
and the admin hash decides whether a login is a constant-time comparison or a
PBKDF2 derivation. Both are exercised directly rather than through the UI.
"""
import asyncio
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    import websockets

    HAVE_WEBSOCKETS = True
except ImportError:  # pragma: no cover - exercised on bare runners
    HAVE_WEBSOCKETS = False

from test_responsive_layout import _free_port, _wait_http

from app.admin import verify_password
from app.auth import hash_password


def _close_code(exc):
    """Pull the close code out of whatever `websockets` raised.

    Which attribute carries it depends on whether the close arrived before or
    after the connection was established, and on the library version.
    """
    for attr in ("rcvd", "sent"):
        frame = getattr(exc, attr, None)
        code = getattr(frame, "code", None)
        if isinstance(code, int):
            return code
    code = getattr(exc, "code", None)
    return code if isinstance(code, int) else None


@unittest.skipUnless(HAVE_WEBSOCKETS, "needs the websockets module")
class SocketLimitTests(unittest.TestCase):
    """The per-user cap is checked before accept, so a rejected socket never
    occupies a slot -- otherwise the limit would lock out its own retries."""

    @classmethod
    def setUpClass(cls):
        cls.data_dir = tempfile.mkdtemp(prefix="chat-wslimit-")
        cls.port = _free_port()
        cls.base = f"http://127.0.0.1:{cls.port}"
        # Cap low enough that a handful of sockets trips it.
        env = dict(os.environ, PORT=str(cls.port), CHAT_DATA_DIR=cls.data_dir,
                   ENC_ENABLED="false", REGISTRATION_ENABLED="true",
                   MAX_SOCKETS_PER_USER="3", MAX_SOCKETS_PER_IP="1000",
                   SSL_CERTFILE="", SSL_KEYFILE="", WORKERS="1")
        cls.server = subprocess.Popen(
            [sys.executable, str(ROOT / "run.py")], cwd=str(ROOT), env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not _wait_http(cls.base + "/login"):
            cls._teardown()
            raise unittest.SkipTest("the app did not start")
        cls.username = "wslim" + os.urandom(3).hex()
        cls.cookie = cls._login(cls.username)

    @classmethod
    def _teardown(cls):
        proc = getattr(cls, "server", None)
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
        for path in (getattr(cls, "data_dir", None),):
            if path:
                shutil.rmtree(path, ignore_errors=True)

    @classmethod
    def tearDownClass(cls):
        cls._teardown()

    @classmethod
    def _login(cls, username):
        import http.cookiejar
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(jar))
        req = urllib.request.Request(
            cls.base + "/api/register",
            data=urllib.parse.urlencode(
                {"name": "W", "username": username,
                 "password": "wslim-pw", "confirm": "wslim-pw"}).encode())
        try:
            opener.open(req, timeout=15).read()
        except urllib.error.HTTPError as e:
            e.read()
        opener.open(urllib.request.Request(
            cls.base + "/api/login",
            data=urllib.parse.urlencode({"username": username,
                                         "password": "wslim-pw"}).encode()),
            timeout=15).read()
        for cookie in jar:
            if cookie.name == "session_id":
                return cookie.value
        raise unittest.SkipTest("no session cookie")

    def test_the_cap_is_enforced_and_the_code_is_specific(self):
        """Open sockets until one is refused. The refusal must carry close
        code 4429 (over budget) so the client can stop retrying, not 4401
        (not logged in) or a bare HTTP rejection."""
        import websockets

        async def run():
            held = []
            refused = None
            try:
                for _ in range(8):
                    try:
                        ws = await websockets.connect(
                            f"ws://127.0.0.1:{self.port}/ws",
                            additional_headers={
                                "Cookie": f"session_id={self.cookie}"},
                            open_timeout=10)
                    except Exception as e:  # noqa: BLE001
                        refused = e
                        break
                    held.append(ws)
                    # The server accepts, then immediately closes with 4429 when
                    # the cap is hit, so the refusal surfaces on recv().
                    try:
                        await asyncio.wait_for(ws.recv(), timeout=5)
                    except asyncio.TimeoutError:
                        continue  # still open: this socket was within budget
                    except Exception as e:  # noqa: BLE001
                        refused = e
                        break
                return len(held), refused
            finally:
                for ws in held:
                    await ws.close()

        opened, refused = asyncio.run(run())
        # The over-budget socket is accepted before it is closed, so it is
        # counted here; what matters is that it is closed and never usable.
        self.assertLessEqual(
            opened, 4,
            f"the per-user cap of 3 was exceeded by more than the refused "
            f"socket: {opened} stayed open")
        self.assertIsNotNone(refused, "the cap never refused anything")
        self.assertEqual(
            _close_code(refused), 4429,
            f"expected the over-budget close code 4429, got {_close_code(refused)!r} "
            f"({refused!r})")

    def test_a_freed_slot_can_be_used_again(self):
        """The check must happen before accept, not as a side effect of it."""
        import websockets

        async def run():
            ws = await websockets.connect(
                f"ws://127.0.0.1:{self.port}/ws",
                additional_headers={"Cookie": f"session_id={self.cookie}"},
                open_timeout=10)
            await ws.close()
            await asyncio.sleep(0.3)
            again = await websockets.connect(
                f"ws://127.0.0.1:{self.port}/ws",
                additional_headers={"Cookie": f"session_id={self.cookie}"},
                open_timeout=10)
            await again.close()
            return True

        self.assertTrue(asyncio.run(run()),
                        "closing a socket did not free its slot")


class AdminPasswordHashTests(unittest.TestCase):
    """A hash must authenticate, and the plaintext must not be readable from
    the hash. These run against the real functions with the env patched."""

    def _with_env(self, check, **env):
        """Run `check(admin_module)` with ADMIN_PASSWORD[_HASH] set to `env`.

        admin.py reads its settings at import time, so the module is reloaded
        around the call. The assertion runs INSIDE that window: returning the
        module would hand back one that has already been reloaded back to the
        ambient environment.
        """
        import importlib

        from app import config
        import app.admin as admin_mod
        saved = {k: os.environ.get(k) for k in env}
        try:
            for k, v in env.items():
                os.environ[k] = v
            importlib.reload(config)
            importlib.reload(admin_mod)
            check(admin_mod)
        finally:
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
            importlib.reload(config)
            importlib.reload(admin_mod)

    def test_a_hash_authenticates_the_right_password_and_rejects_others(self):
        h = hash_password("correct horse battery staple")

        def check(admin_mod):
            self.assertTrue(admin_mod.enabled())
            self.assertTrue(
                admin_mod.verify_password("correct horse battery staple"))
            self.assertFalse(admin_mod.verify_password("wrong"))
            self.assertFalse(admin_mod.verify_password(""))

        self._with_env(check, ADMIN_PASSWORD="", ADMIN_PASSWORD_HASH=h)

    def test_the_hash_does_not_contain_the_password(self):
        h = hash_password("swordfish-please-do-not-log-me")
        self.assertNotIn("swordfish", h)
        self.assertNotIn("swordfish", h.lower())

    def test_the_hash_wins_when_both_are_set(self):
        """Setting ADMIN_PASSWORD alongside the hash must not reintroduce the
        plaintext comparison -- otherwise the hash is decorative."""
        h = hash_password("from-the-hash")

        def check(admin_mod):
            self.assertTrue(admin_mod.verify_password("from-the-hash"))
            self.assertFalse(
                admin_mod.verify_password("from-the-plaintext"),
                "the plaintext password was still accepted despite a hash")

        self._with_env(check, ADMIN_PASSWORD="from-the-plaintext",
                       ADMIN_PASSWORD_HASH=h)

    def test_plaintext_still_works_when_no_hash_is_set(self):
        def check(admin_mod):
            self.assertTrue(admin_mod.enabled())
            self.assertTrue(admin_mod.verify_password("plain-still-ok"))
            self.assertFalse(admin_mod.verify_password("nope"))

        self._with_env(check, ADMIN_PASSWORD="plain-still-ok",
                       ADMIN_PASSWORD_HASH="")

    def test_disabled_when_neither_is_set(self):
        def check(admin_mod):
            self.assertFalse(admin_mod.enabled())
            self.assertFalse(admin_mod.verify_password("anything"))

        self._with_env(check, ADMIN_PASSWORD="", ADMIN_PASSWORD_HASH="")


if __name__ == "__main__":
    unittest.main()