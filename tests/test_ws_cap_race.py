"""The per-user socket cap must hold under CONCURRENT connects.

`would_exceed()` and `connect()` each took the lock separately, so N sockets
arriving together all observed a free slot and all registered. The audit
reproduced it live: 6 concurrent connects at a cap of 5, all 6 opened.

Sequential testing cannot catch this -- the existing sequential test passes
either way. These tests connect in parallel and assert the cap holds.
"""
import asyncio
import http.cookiejar
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


@unittest.skipUnless(HAVE_WEBSOCKETS, "needs the websockets module")
class ConcurrentSocketCapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data_dir = tempfile.mkdtemp(prefix="chat-toctou-")
        cls.port = _free_port()
        cls.base = f"http://127.0.0.1:{cls.port}"
        env = dict(os.environ, PORT=str(cls.port),
                   CHAT_DATA_DIR=cls.data_dir, ENC_ENABLED="false",
                   REGISTRATION_ENABLED="true",
                   MAX_SOCKETS_PER_USER="5", MAX_SOCKETS_PER_IP="1000",
                   SSL_CERTFILE="", SSL_KEYFILE="", WORKERS="1")
        cls.server = subprocess.Popen(
            [sys.executable, str(ROOT / "run.py")], cwd=str(ROOT), env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not _wait_http(cls.base + "/login"):
            cls._teardown()
            raise unittest.SkipTest("the app did not start")
        cls.username = "toctou" + os.urandom(3).hex()
        cls.cookie = cls._register_and_login()

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
    def _register_and_login(cls):
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(jar))
        opener.open(urllib.request.Request(
            cls.base + "/api/register",
            data=urllib.parse.urlencode(
                {"name": "T", "username": cls.username,
                 "password": "toctou-pw", "confirm": "toctou-pw"}).encode()),
            timeout=15).read()
        opener.open(urllib.request.Request(
            cls.base + "/api/login",
            data=urllib.parse.urlencode(
                {"username": cls.username,
                 "password": "toctou-pw"}).encode()), timeout=15).read()
        for cookie in jar:
            if cookie.name == "session_id":
                return cookie.value
        raise unittest.SkipTest("no session cookie")

    def _connect_concurrently(self, n):
        """Open n sockets at once; return how many ended up usable.

        Every socket is closed before returning, so consecutive calls start
        from a clean pool -- otherwise a later test sees slots the previous
        one still holds and wrongly concludes the cap is too tight.
        """
        async def run():
            results = await asyncio.gather(
                *[self._connect_one(i) for i in range(n)],
                return_exceptions=True)
            held = [r for r in results
                    if r is not None and not isinstance(r, Exception)]
            for ws in held:
                try:
                    await ws.close()
                except Exception:
                    pass
            # Let the server observe the closes before the next batch.
            await asyncio.sleep(0.4)
            return len(held)

        return asyncio.run(run()), n

    async def _connect_one(self, i):
        """Connect and report whether the server kept it open."""
        import websockets
        try:
            ws = await websockets.connect(
                f"ws://127.0.0.1:{self.port}/ws",
                additional_headers={"Cookie": f"session_id={self.cookie}"},
                open_timeout=10)
        except Exception:
            return None
        # The server accepts first, then closes with 4429 when over budget,
        # so a kept socket shows up as a timeout on recv().
        try:
            await asyncio.wait_for(ws.recv(), timeout=1.5)
            return None
        except asyncio.TimeoutError:
            return ws
        except Exception:
            return None

    def test_concurrent_connects_cannot_exceed_the_per_user_cap(self):
        """The property that matters, asserted against a real server.

        This is a regression guard, NOT a reproduction of a known breach. The
        audit reported 6/6 sockets opening at a cap of 5, but that was not
        reproducible here: the same burst against the pre-fix split
        check-then-increment code also capped correctly.

        The reason is now understood, and it is why the fix is still right.
        Both forms run on a single-threaded event loop, and `asyncio.Lock`
        excludes other coroutines even across an `await` inside the critical
        section -- so the old split form had no window *in this runtime*.
        Verified directly: four coroutines holding the same lock across a
        yield run strictly one after another.

        A burst over real WebSockets still holds the cap at every size tried,
        including 80. What the fix removes is the dependency on that
        implementation detail: the budget read and the registration are one
        critical section, so correctness no longer rests on there being no
        await point between them.
        """
        for n in (8, 16, 32):
            with self.subTest(burst=n):
                opened, _ = self._connect_concurrently(n)
                self.assertLessEqual(
                    opened, 5,
                    f"burst of {n} kept {opened} sockets open, over the "
                    "per-user cap of 5")

    def test_concurrent_connects_still_allow_the_cap(self):
        """Atomic reservation must not under-serve either: below the cap,
        every connection should succeed."""
        opened, _ = self._connect_concurrently(3)
        self.assertEqual(
            opened, 3,
            f"only {opened}/3 connections succeeded below the cap")

    def test_check_and_register_share_one_lock(self):
        """Structural guard for I-02.

        The runtime happens to serialise coroutines such that the old split
        form also held the cap, so a behavioural test alone cannot tell the
        two apart. This one asserts the *shape*: the budget read and the
        registration must sit in the same critical section, so correctness
        does not depend on there being no yield point between them.
        """
        src = (ROOT / "app" / "websocket.py").read_text(encoding="utf-8")
        self.assertNotIn("would_exceed", src,
                         "the split check/connect API is back")

        body = src.split("async def connect", 1)[1]
        body = body.split("async def disconnect", 1)[0]

        # Exactly one critical section: no second `async with self.lock`
        # (that would be a separate acquisition) and none before it.
        self.assertEqual(
            body.count("async with self.lock"), 1,
            "connect() must take the lock exactly once, so the budget check "
            "and the registration cannot be split")

        # The read and the write must both live inside that section.
        lock_at = body.index("async with self.lock")
        read_at = body.index("held = sum(")
        write_at = body.index("self.peers[ws] =")
        self.assertLess(lock_at, read_at,
                        "the budget is read before the lock is taken")
        self.assertLess(read_at, write_at,
                        "the budget must be read before the socket is "
                        "registered, inside the same section")
        self.assertIn("return False", body.split("async with self.lock")[1],
                      "an over-budget socket must be refused, not registered")

    def test_an_over_budget_socket_is_never_registered(self):
        """A rejected socket must not occupy a slot -- if it did, repeated
        rejections would eventually lock the user out entirely."""
        src = (ROOT / "app" / "websocket.py").read_text(encoding="utf-8")
        body = src.split("async def connect", 1)[1]
        body = body.split("async def disconnect", 1)[0]
        section = body.split("async with self.lock", 1)[1]
        close_at = section.index("ws.close(code=4429)")
        write_at = section.index("self.peers[ws] =")
        self.assertLess(
            close_at, write_at,
            "the registration happens before the refusal returns, so a "
            "rejected socket still occupies a slot")




if __name__ == "__main__":
    unittest.main()