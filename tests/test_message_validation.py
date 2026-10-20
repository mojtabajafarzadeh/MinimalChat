"""Message length: over-long input is refused, not silently cut.

The server used to truncate at 1000 characters. The sender's own echo carries
the truncated text, so the cut looked exactly like the message that was sent --
half a sentence could disappear with nothing anywhere saying so. Refusing with
an error is the only version the sender can notice.

A real server and a real WebSocket, because the limit lives in the frame loop
and nowhere a unit test could reach.
"""
import asyncio
import json
import os
import shutil
import subprocess
import sys
import tempfile
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

LIMIT = 1000


@unittest.skipUnless(HAVE_WEBSOCKETS, "needs the websockets module")
class MessageLengthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data_dir = tempfile.mkdtemp(prefix="chat-msglen-")
        cls.port = _free_port()
        cls.base = f"http://127.0.0.1:{cls.port}"
        env = dict(os.environ, PORT=str(cls.port), CHAT_DATA_DIR=cls.data_dir,
                   ENC_ENABLED="false", REGISTRATION_ENABLED="true",
                   SSL_CERTFILE="", SSL_KEYFILE="", WORKERS="1")
        cls.server = subprocess.Popen(
            [sys.executable, str(ROOT / "run.py")], cwd=str(ROOT), env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not _wait_http(cls.base + "/login"):
            cls._teardown()
            raise unittest.SkipTest("the app did not start")
        cls.cookie = cls._register()

    @classmethod
    def _register(cls):
        import http.cookiejar

        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(jar))
        username = "len" + os.urandom(3).hex()
        req = urllib.request.Request(
            cls.base + "/api/register",
            data=urllib.parse.urlencode(
                {"name": "Len", "username": username,
                 "password": "len-pw-123", "confirm": "len-pw-123"}).encode())
        with opener.open(req, timeout=15) as r:
            r.read()
        for cookie in jar:
            if cookie.name == "session_id":
                return cookie.value
        raise unittest.SkipTest("no session cookie")

    @classmethod
    def _teardown(cls):
        proc = getattr(cls, "server", None)
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
        shutil.rmtree(getattr(cls, "data_dir", ""), ignore_errors=True)

    @classmethod
    def tearDownClass(cls):
        cls._teardown()

    async def _send(self, text):
        import websockets

        ws = await websockets.connect(
            f"ws://127.0.0.1:{self.port}/ws",
            additional_headers={"Cookie": f"session_id={self.cookie}"},
            open_timeout=10)
        try:
            await ws.send(json.dumps({"type": "public", "content": text}))
            return json.loads(await asyncio.wait_for(ws.recv(), timeout=10))
        finally:
            await ws.close()

    def test_an_over_long_message_is_refused_with_a_reason(self):
        reply = asyncio.run(self._send("x" * (LIMIT + 1)))
        self.assertEqual(reply.get("kind"), "error",
                         f"an over-long message was not refused: {reply!r}")
        self.assertIn("too long", reply.get("error", "").lower())

    def _history(self):
        req = urllib.request.Request(
            f"{self.base}/api/messages?limit=200",
            headers={"Cookie": f"session_id={self.cookie}"})
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read())

    def test_the_refused_message_is_not_stored(self):
        """Refusing in the socket loop but still writing the row would be a
        half-fix: history would hold what the sender was told had failed."""
        payload = "q" * (LIMIT + 7)
        asyncio.run(self._send(payload))
        stored = [m for m in self._history()
                  if "q" * 20 in (m.get("content") or "")]
        self.assertEqual(
            stored, [],
            "the refused message reached the history anyway: "
            + str([len(m.get("content") or "") for m in stored]))

    def test_a_message_at_the_limit_is_accepted_in_full(self):
        text = "y" * LIMIT
        reply = asyncio.run(self._send(text))
        self.assertEqual(reply.get("kind"), "public", f"got {reply!r}")
        self.assertEqual(
            reply["content"], text,
            "a message at the documented limit was shortened anyway")
