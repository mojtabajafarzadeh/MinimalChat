"""A changed server identity must fail closed.

The identity check is only worth having if the page also refuses to *use* a
connection it could not verify. Before this test existed the behaviour was
pinned only structurally (test_channel_hardening), and the risky path was
reasoned about rather than observed: a failed handshake left `Api` on its
default plain mode, so a login typed into the page would have been posted in
cleartext -- to a server the page had just decided it could not trust.

What the browser shows that no unit test can:

- the page really is blocked after a rotation (`Api.mode`), with the warning
  banner and the panel open;
- submitting the login form issues **no request at all** -- proven with a
  `window.fetch` spy, not by inspecting the code;
- logging out keeps the pin, so the rotation is still detectable afterwards.

A real key rotation is the only way to reach the blocked state, so the server is
stopped, `enc_keys.json` deleted, and the server restarted *on the same port*:
localStorage is origin-scoped, and a new port would look like a new site with no
pin to change.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    import websocket

    HAVE_WEBSOCKET = True
except ImportError:  # pragma: no cover - exercised on bare runners
    HAVE_WEBSOCKET = False

from test_responsive_layout import CdpSession, _find_chrome, _free_port, _wait_http

USERNAME = "failclosed"
PASSWORD = "fail-closed-pw"


@unittest.skipUnless(HAVE_WEBSOCKET, "needs the websocket-client module")
@unittest.skipIf(_find_chrome() is None, "needs a Chrome/Chromium binary")
class ChangedIdentityFailsClosedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data_dir = tempfile.mkdtemp(prefix="chat-failclosed-")
        cls.profile = tempfile.mkdtemp(prefix="chrome-failclosed-")
        cls.port = _free_port()
        cls.base = f"http://127.0.0.1:{cls.port}"
        cls.server = None
        cls._start_server()

        cls.cdp_port = _free_port()
        cls.chrome = subprocess.Popen(
            [_find_chrome(), "--headless=new", "--no-sandbox", "--disable-gpu",
             "--disable-dev-shm-usage", f"--remote-debugging-port={cls.cdp_port}",
             f"--user-data-dir={cls.profile}", "about:blank"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not _wait_http(f"http://127.0.0.1:{cls.cdp_port}/json/version"):
            cls._teardown()
            raise unittest.SkipTest("headless Chrome did not start")
        cls.page = cls._open_page()

    # ---------------------------------------------------------------- plumbing

    @classmethod
    def _start_server(cls):
        env = dict(os.environ, PORT=str(cls.port), CHAT_DATA_DIR=cls.data_dir,
                   ENC_ENABLED="true", REGISTRATION_ENABLED="true",
                   SSL_CERTFILE="", SSL_KEYFILE="", WORKERS="1")
        cls.server = subprocess.Popen(
            [sys.executable, str(ROOT / "run.py")], cwd=str(ROOT), env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not _wait_http(cls.base + "/login"):
            cls._teardown()
            raise unittest.SkipTest("the app did not start")

    @classmethod
    def _stop_server(cls):
        if cls.server and cls.server.poll() is None:
            cls.server.terminate()
            try:
                cls.server.wait(timeout=15)
            except subprocess.TimeoutExpired:
                cls.server.kill()

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
    def _open_page(cls):
        with urllib.request.urlopen(
                f"http://127.0.0.1:{cls.cdp_port}/json/list", timeout=15) as r:
            targets = json.load(r)
        target = next(t for t in targets if t.get("type") == "page")
        ws = websocket.create_connection(target["webSocketDebuggerUrl"],
                                         timeout=30, suppress_origin=True)
        session = CdpSession(ws)
        session.send("Page.enable")
        session.send("Runtime.enable")
        session.send("Network.enable")
        session.send("Network.setCacheDisabled", cacheDisabled=True)
        return session

    def _await_eval(self, source):
        """Evaluate an async expression and wait for its promise."""
        out = self.page.send("Runtime.evaluate", expression=source,
                             returnByValue=True, awaitPromise=True)
        if out.get("exceptionDetails"):
            raise AssertionError(out["exceptionDetails"].get("text", "page error"))
        return out.get("result", {}).get("value")

    def _fingerprint(self):
        with urllib.request.urlopen(self.base + "/enc/status", timeout=15) as r:
            return json.load(r)["fingerprint"]

    def _load(self, seconds=2.5):
        self.page.goto(self.base + "/login")
        time.sleep(seconds)

    # ------------------------------------------------------------------- test

    def test_a_changed_identity_blocks_and_sends_nothing(self):
        self._load()
        self.assertEqual(self.page.evaluate("Api.mode"), "enc",
                         "the channel did not come up on a healthy server")
        pin = self.page.evaluate("Api.pinnedFingerprint()")
        self.assertTrue(pin, "the first visit should pin automatically")

        # Sign in (registration signs in over the channel), then log out.
        registered = self._await_eval(
            "(async () => { try {"
            " await Api.register('Fail Closed', '" + USERNAME + "', "
            "'" + PASSWORD + "', '" + PASSWORD + "');"
            " return 'OK'; } catch (e) { return 'ERR: ' + e.message; } })()")
        self.assertEqual(registered, "OK", registered)
        self._await_eval("(async () => { await Api.logout(); return 'done'; })()")

        self.assertEqual(
            self.page.evaluate("Enc.pinnedFingerprint()"), pin,
            "logging out dropped the pinned server identity, which is a "
            "one-click downgrade to trust-on-first-use")

        # Rotate the signing key and come back to the *same origin*.
        self._stop_server()
        os.unlink(Path(self.data_dir) / "enc_keys.json")
        self._start_server()
        rotated = self._fingerprint().replace(" ", "")
        self.assertNotEqual(rotated, pin.replace(" ", ""),
                            "the key was not actually replaced")

        self._load()
        self.assertEqual(
            self.page.evaluate("Api.mode"), "blocked",
            "a changed identity left the page usable, so the next thing typed "
            "into it would travel on the plain transport")
        self.assertTrue(self.page.evaluate("Api.identityChanged"),
                        "the client did not notice the identity change")
        self.assertTrue(
            self.page.evaluate("!!document.getElementById('identity-warning')"),
            "no warning banner after an identity change")

        # Count what the page tries to send from here on.
        self.page.evaluate(
            "(() => { window.__sent = []; const original = window.fetch;"
            " window.fetch = function (url, opts) {"
            "   window.__sent.push(String(url));"
            "   return original.apply(this, arguments); }; return 'ok'; })()")

        # The operator types credentials and presses Log in.
        self.page.evaluate(
            "(() => {"
            " document.getElementById('username').value = '" + USERNAME + "';"
            " document.getElementById('password').value = '" + PASSWORD + "';"
            " document.getElementById('form').requestSubmit();"
            " return 'ok'; })()")
        time.sleep(1.0)

        sent = self.page.evaluate("window.__sent") or []
        self.assertEqual(
            sent, [],
            "the blocked page still made network calls: " + str(sent))
        message = self.page.evaluate("document.getElementById('error').textContent")
        self.assertIn("unverified", (message or "").lower(),
                      "the reader was not told why nothing happened: "
                      + repr(message))

        # And the same holds for the API layer, not just the form.
        direct = self._await_eval(
            "(async () => { try { await Api.login('a', 'b'); return 'SENT'; }"
            " catch (e) { return 'BLOCKED: ' + e.message; } })()")
        self.assertTrue(direct.startswith("BLOCKED:"), direct)
        self.assertEqual(self.page.evaluate("window.__sent"), [],
                         "Api.login still reached the network while blocked")
