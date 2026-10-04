"""Unread badges on the conversation list.

The counters live in the page, so the only honest way to check them is a real
browser with a real WebSocket: a badge has to appear when a message arrives
for a conversation that is not on screen, has to stay away from the one that
is, and has to clear when you go and read it. Nothing is persisted here by
design, so a reload resetting every badge to zero is part of the contract
rather than a bug.

Requires a Chrome/Chromium binary plus `websocket-client` and `websockets`,
so it skips on a bare CI runner instead of reporting a pass it did not earn.
"""
import asyncio
import http.cookiejar
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
    import websocket

    HAVE_WEBSOCKET = True
except ImportError:  # pragma: no cover - exercised on bare runners
    HAVE_WEBSOCKET = False

try:
    import websockets

    HAVE_WEBSOCKETS = True
except ImportError:  # pragma: no cover - exercised on bare runners
    HAVE_WEBSOCKETS = False

from test_responsive_layout import CdpSession, _find_chrome, _free_port, _wait_http

# Reads every badge in one go: the pixels, and the accessible name that says
# the same thing in words.
BADGES = """
(() => {
  const read = (button) => {
    const b = button.querySelector('.conv-badge');
    return {
      name: button.querySelector('.conv-name').textContent,
      label: button.getAttribute('aria-label'),
      text: b ? b.textContent : null,
      shown: b ? !b.classList.contains('hidden') : false,
    };
  };
  const out = {public: read(document.getElementById('btn-public')), dms: {}};
  document.querySelectorAll('#conversations .conv').forEach((b) => {
    const row = read(b);
    out.dms[row.name.replace(/^@/, '')] = row;
  });
  out.messages = document.querySelectorAll('#messages .msg').length;
  out.title = document.getElementById('view-title').textContent;
  return out;
})()
"""


@unittest.skipUnless(HAVE_WEBSOCKET, "needs the websocket-client module")
@unittest.skipUnless(HAVE_WEBSOCKETS, "needs the websockets module")
@unittest.skipIf(_find_chrome() is None, "needs a Chrome/Chromium binary")
class UnreadBadgeTests(unittest.TestCase):
    """Two real accounts, one real browser, one real socket between them."""

    alice = "alice" + os.urandom(3).hex()
    bob = "bob" + os.urandom(3).hex()
    # A third account nobody else touches: the tests share one database, so a
    # sender used elsewhere would already have a row by the time this runs.
    carol = "carol" + os.urandom(3).hex()

    @classmethod
    def setUpClass(cls):
        cls.data_dir = tempfile.mkdtemp(prefix="chat-unread-")
        cls.profile = tempfile.mkdtemp(prefix="chrome-unread-")
        cls.port = _free_port()
        cls.cdp_port = _free_port()
        cls.base = f"http://127.0.0.1:{cls.port}"
        env = dict(os.environ, PORT=str(cls.port), CHAT_DATA_DIR=cls.data_dir,
                   ENC_ENABLED="false", REGISTRATION_ENABLED="true",
                   ADMIN_PATH="/admin", ADMIN_PASSWORD="unread-admin-pw",
                   SSL_CERTFILE="", SSL_KEYFILE="", WORKERS="1")
        cls.server = subprocess.Popen(
            [sys.executable, str(ROOT / "run.py")], cwd=str(ROOT), env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not _wait_http(cls.base + "/login"):
            cls._teardown()
            raise unittest.SkipTest("the app did not start")
        cls.chrome = subprocess.Popen(
            [_find_chrome(), "--headless=new", "--no-sandbox", "--disable-gpu",
             "--disable-dev-shm-usage", f"--remote-debugging-port={cls.cdp_port}",
             f"--user-data-dir={cls.profile}", "about:blank"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not _wait_http(f"http://127.0.0.1:{cls.cdp_port}/json/version"):
            cls._teardown()
            raise unittest.SkipTest("headless Chrome did not start")
        for username in (cls.alice, cls.bob, cls.carol):
            cls._post("/api/register", {"name": username.capitalize(),
                                       "username": username,
                                       "password": "unread-pw",
                                       "confirm": "unread-pw"})

    @classmethod
    def _teardown(cls):
        for proc in (getattr(cls, "chrome", None), getattr(cls, "server", None)):
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
        for path in (getattr(cls, "data_dir", None), getattr(cls, "profile", None)):
            if path:
                shutil.rmtree(path, ignore_errors=True)

    @classmethod
    def tearDownClass(cls):
        cls._teardown()

    @classmethod
    def _post(cls, path, fields):
        req = urllib.request.Request(cls.base + path,
                                     data=urllib.parse.urlencode(fields).encode())
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                r.read()
        except urllib.error.HTTPError as e:
            e.read()

    @classmethod
    def _session_cookie(cls, username):
        """CookieJar rather than a headers dict: login sets several cookies."""
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(jar))
        opener.open(urllib.request.Request(
            cls.base + "/api/login",
            data=urllib.parse.urlencode({"username": username,
                                         "password": "unread-pw"}).encode()),
            timeout=15).read()
        for cookie in jar:
            if cookie.name == "session_id":
                return cookie.value
        raise unittest.SkipTest(f"no session cookie for {username}")

    def setUp(self):
        self.page = self._open_page()
        self.page.viewport(1280, 800)
        self.page.cookie("session_id", self._session_cookie(self.alice))
        self.page.goto(self.base + "/chat")
        time.sleep(1.5)
        self.assertEqual("/chat", self.page.evaluate("location.pathname"))

    def tearDown(self):
        try:
            self.page.ws.close()
        except Exception:
            pass

    def _open_page(self):
        with urllib.request.urlopen(
                f"http://127.0.0.1:{self.cdp_port}/json/list", timeout=15) as r:
            targets = json.load(r)
        target = next(t for t in targets if t.get("type") == "page")
        ws = websocket.create_connection(target["webSocketDebuggerUrl"], timeout=30,
                                         suppress_origin=True)
        session = CdpSession(ws)
        session.send("Page.enable")
        session.send("Runtime.enable")
        session.send("Network.enable")
        # The auth pages carry no cache headers, so Chrome would otherwise
        # reuse a previous run's HTML.
        session.send("Network.setCacheDisabled", cacheDisabled=True)
        return session

    def badges(self):
        return self.page.evaluate(BADGES)

    def bob_says(self, frames, sender=None):
        """Push frames from another account over a real WebSocket.

        Each one is acknowledged by the server's own echo before the next goes
        out, so a caller never has to guess how long the write took.
        """
        sender = sender or self.bob
        async def run():
            url = f"ws://127.0.0.1:{self.port}/ws"
            async with websockets.connect(url, additional_headers={
                    "Cookie": f"session_id={self._session_cookie(sender)}"}) as ws:
                for frame in frames:
                    await ws.send(json.dumps(frame))
                    await asyncio.wait_for(ws.recv(), timeout=15)

        asyncio.run(run())
        # Stored and echoed, but the browser still needs a tick to paint the
        # badge the frame causes.
        time.sleep(0.6)

    def open_dm_with_bob(self):
        """Go through the real DM form rather than poking the view directly."""
        self.page.evaluate(
            "(() => { const i = document.getElementById('dm-input');"
            " i.value = %r; document.getElementById('dm-form')"
            ".dispatchEvent(new Event('submit', {cancelable: true})); })()"
            % self.bob)
        time.sleep(1.2)
        self.assertIn(self.bob, self.badges()["title"])

    def test_a_badge_marks_arrivals_while_you_are_looking_elsewhere(self):
        found = self.badges()
        self.assertEqual("Public Chat", found["title"])
        self.assertFalse(found["public"]["shown"],
                         "the conversation you are looking at must not badge")
        self.assertEqual("Public Chat", found["public"]["label"],
                         "a conversation with nothing unread needs no extra words")

        # Public is on screen, so this must not badge it.
        self.bob_says([{"type": "public", "content": "on screen"}])
        self.assertFalse(self.badges()["public"]["shown"],
                         "a message in the open conversation was counted as unread")

        # Move to the DM. Now public is off screen.
        self.open_dm_with_bob()
        self.bob_says([{"type": "public", "content": "off screen"}])
        found = self.badges()
        self.assertTrue(found["public"]["shown"],
                        "a public message arriving while reading a DM went unmarked")
        self.assertEqual("1", found["public"]["text"])
        self.assertIn("1 unread message", found["public"]["label"],
                      "the badge is hidden from AT, so the name has to say it")

        # DMs for the conversation on screen are read on arrival, so leaving
        # that DM must not produce a badge for messages already seen.
        before = self.badges()["messages"]
        self.bob_says([{"type": "dm", "to": self.alice, "content": "one"},
                       {"type": "dm", "to": self.alice, "content": "two"}])
        found = self.badges()
        self.assertFalse(found["dms"][self.bob]["shown"],
                         "messages in the open DM were counted as unread")
        self.assertEqual(before + 2, found["messages"],
                         "they should have been rendered instead")

        self.page.evaluate("document.getElementById('btn-public').click()")
        time.sleep(0.8)
        found = self.badges()
        self.assertFalse(found["public"]["shown"],
                         "the badge survived opening the conversation it counted")
        self.assertFalse(found["dms"][self.bob]["shown"],
                         "messages read on arrival were counted as unread later")

        # Now the DM is the one off screen.
        self.bob_says([{"type": "dm", "to": self.alice, "content": "three"},
                       {"type": "dm", "to": self.alice, "content": "four"},
                       {"type": "dm", "to": self.alice, "content": "five"}])
        self.assertEqual("3", self.badges()["dms"][self.bob]["text"],
                         "counts should accumulate across arrivals")

        self.open_dm_with_bob()
        self.assertFalse(self.badges()["dms"][self.bob]["shown"],
                         "the badge survived opening the conversation it counted")

    def test_a_first_message_from_a_stranger_badges_a_row_that_did_not_exist(self):
        """The row and its badge are created by the same frame, so a badge that
        only paints over an existing row would miss every new conversation."""
        self.assertNotIn(self.carol, self.badges()["dms"])
        self.bob_says([{"type": "dm", "to": self.alice, "content": "hello?"}],
                      sender=self.carol)
        found = self.badges()
        self.assertIn(self.carol, found["dms"],
                      "the conversation list never learned about this sender")
        self.assertTrue(found["dms"][self.carol]["shown"],
                        "the brand-new conversation got no badge")
        self.assertEqual("1", found["dms"][self.carol]["text"])

    def test_the_count_stops_at_99_plus(self):
        """An unbounded number would push the label out of its own row."""
        self.open_dm_with_bob()
        self.page.evaluate("document.getElementById('btn-public').click()")
        time.sleep(0.8)
        self.bob_says([{"type": "dm", "to": self.alice, "content": f"n{i}"}
                       for i in range(101)])
        found = self.badges()
        self.assertTrue(found["dms"][self.bob]["shown"])
        self.assertEqual("99+", found["dms"][self.bob]["text"],
                         "101 unread messages must not render as 101")
        # The digit count is capped; the accessible name should not have to be.
        self.assertIn("101 unread messages", found["dms"][self.bob]["label"])

    def test_a_reload_starts_from_zero(self):
        """No read state is persisted, and that is the design, not a gap."""
        self.open_dm_with_bob()
        self.page.evaluate("document.getElementById('btn-public').click()")
        time.sleep(0.8)
        self.bob_says([{"type": "dm", "to": self.alice, "content": "before reload"}])
        self.assertEqual("1", self.badges()["dms"][self.bob]["text"])

        self.page.goto(self.base + "/chat")
        time.sleep(1.5)
        found = self.badges()
        self.assertFalse(found["public"]["shown"])
        for name, row in found["dms"].items():
            self.assertFalse(row["shown"],
                             f"{name} still badged after a reload: the counters "
                             "are meant to be per page load")


if __name__ == "__main__":
    unittest.main()