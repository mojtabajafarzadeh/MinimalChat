"""Server-identity verification: the log line and the pinning panel.

Two halves of one feature. `run.py` prints the signing-key fingerprint at
startup so an operator can read it somewhere the browser cannot reach, and the
UI lets that value be pasted back in and compared against what the connection
actually presents. The browser only ever learns the fingerprint from the same
connection it is meant to verify, so on its own it proves nothing -- which is
exactly why the two halves have to agree.

The key-rotation scenario is the one worth automating: the whole point of a
pin is that it fires when the server identity changes, and that path only runs
when a handshake rejects, which no amount of reading the code will convince you
about.

Requires a Chrome/Chromium binary and the `websocket-client` module, so it skips
on a bare CI runner instead of reporting a pass it did not earn.
"""
import http.cookiejar
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
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

from test_responsive_layout import CdpSession, _find_chrome, _free_port, _wait_http

FINGERPRINT_RE = re.compile(r"[0-9A-F]{4}(?: [0-9A-F]{4}){15}")


def read_enc_status(base: str) -> dict:
    with urllib.request.urlopen(base + "/enc/status", timeout=15) as r:
        return json.load(r)


class StartupLoggingTests(unittest.TestCase):
    """The fingerprint has to be visible without a browser."""

    def test_startup_prints_the_fingerprint_and_it_survives_a_restart(self):
        env = dict(os.environ, CHAT_DATA_DIR=tempfile.mkdtemp(prefix="chat-fp-"),
                   SSL_CERTFILE="", SSL_KEYFILE="", WORKERS="1")
        try:
            port = _free_port()
            env["PORT"] = str(port)
            fingerprints = []
            for _ in range(2):
                proc = subprocess.Popen([sys.executable, str(ROOT / "run.py")],
                                        cwd=str(ROOT), env=env,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, text=True)
                try:
                    _wait_http(f"http://127.0.0.1:{port}/login")
                    time.sleep(1.0)
                finally:
                    proc.terminate()
                    output = proc.communicate(timeout=20)[0]
                found = FINGERPRINT_RE.findall(output or "")
                self.assertTrue(
                    found,
                    "startup did not print a fingerprint:\n" + (output or ""))
                fingerprints.append(found[0])

            self.assertEqual(
                fingerprints[0], fingerprints[1],
                "the fingerprint changed across a restart, which would make "
                "every pinned client think it was being intercepted")
        finally:
            shutil.rmtree(env["CHAT_DATA_DIR"], ignore_errors=True)

    def test_fingerprint_matches_the_public_status_endpoint(self):
        """The console and the browser must not disagree about the identity."""
        data_dir = tempfile.mkdtemp(prefix="chat-fp-")
        env = dict(os.environ, CHAT_DATA_DIR=data_dir, SSL_CERTFILE="",
                   SSL_KEYFILE="", WORKERS="1")
        proc = None
        try:
            port = _free_port()
            env["PORT"] = str(port)
            proc = subprocess.Popen([sys.executable, str(ROOT / "run.py")],
                                    cwd=str(ROOT), env=env,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True)
            base = f"http://127.0.0.1:{port}"
            self.assertTrue(_wait_http(base + "/login"))
            time.sleep(1.0)
            self.assertEqual(FINGERPRINT_RE.fullmatch(
                read_enc_status(base)["fingerprint"]).group(0),
                read_enc_status(base)["fingerprint"])
        finally:
            if proc:
                proc.terminate()
                proc.communicate(timeout=20)
            shutil.rmtree(data_dir, ignore_errors=True)


@unittest.skipUnless(HAVE_WEBSOCKET, "needs the websocket-client module")
@unittest.skipIf(_find_chrome() is None, "needs a Chrome/Chromium binary")
class VerificationPanelTests(unittest.TestCase):
    """Drives the real panel in a real browser, including a key rotation."""

    @classmethod
    def setUpClass(cls):
        cls.data_dir = tempfile.mkdtemp(prefix="chat-identity-")
        cls.profile = tempfile.mkdtemp(prefix="chrome-identity-")
        cls.port = _free_port()
        cls.cdp_port = _free_port()
        cls.base = f"http://127.0.0.1:{cls.port}"
        cls.log = ""
        cls._start_server()
        cls.chrome = subprocess.Popen(
            [_find_chrome(), "--headless=new", "--no-sandbox", "--disable-gpu",
             "--disable-dev-shm-usage", f"--remote-debugging-port={cls.cdp_port}",
             f"--user-data-dir={cls.profile}", "about:blank"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not _wait_http(f"http://127.0.0.1:{cls.cdp_port}/json/version"):
            cls._teardown()
            raise unittest.SkipTest("headless Chrome did not start")

    @classmethod
    def _teardown(cls):
        for proc in (getattr(cls, "chrome", None), getattr(cls, "server", None)):
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
            if proc and proc.stdout:
                proc.stdout.close()
        for path in (getattr(cls, "data_dir", None), getattr(cls, "profile", None)):
            if path:
                shutil.rmtree(path, ignore_errors=True)

    @classmethod
    def tearDownClass(cls):
        cls._teardown()

    @classmethod
    def _start_server(cls):
        env = dict(os.environ, PORT=str(cls.port), CHAT_DATA_DIR=cls.data_dir,
                   SSL_CERTFILE="", SSL_KEYFILE="", WORKERS="1")
        cls.server = subprocess.Popen(
            [sys.executable, str(ROOT / "run.py")], cwd=str(ROOT), env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if not _wait_http(cls.base + "/login"):
            raise unittest.SkipTest("the app did not start")
        time.sleep(1.0)
        cls.log += cls._drain(cls.server)

    @staticmethod
    def _drain(proc):
        """Read the startup banner without blocking on a live process."""
        os.set_blocking(proc.stdout.fileno(), False)
        time.sleep(0.4)
        try:
            return proc.stdout.read() or ""
        except Exception:
            return ""

    def setUp(self):
        self.page = self._open_page()

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
        # The auth pages are served without cache headers, so Chrome would
        # otherwise serve a previous run's HTML.
        session.send("Network.setCacheDisabled", cacheDisabled=True)
        return session

    def _load_login(self):
        self.page.viewport(1000, 800)
        self.page.goto(self.base + "/login")
        time.sleep(2.5)

    def _submit(self, value):
        self.page.evaluate(
            "(() => { const i = document.getElementById('identity-expected');"
            f" i.value = {json.dumps(value)};"
            " document.querySelector('.identity-form')"
            ".dispatchEvent(new Event('submit', {cancelable:true})); })()")
        time.sleep(0.4)

    def _result(self):
        return self.page.evaluate(
            "(() => { const r = document.querySelector('.identity-result');"
            " return [r.className, r.textContent]; })()")

    def _panel_values(self):
        return self.page.evaluate(
            "[...document.querySelectorAll('.identity-value')]"
            ".map((n) => n.textContent)")

    # ------------------------------------------------------------------ tests

    def test_browser_fingerprint_matches_the_startup_log(self):
        """The value an operator reads must be the value the page computes."""
        logged = FINGERPRINT_RE.search(self.log)
        self.assertIsNotNone(logged, "no fingerprint in the startup log")
        self._load_login()
        live = self._panel_values()[0]
        self.assertEqual(live.replace(" ", ""), logged.group(0).replace(" ", ""),
                         "the panel and the server log disagree about identity")

    def test_a_wrong_fingerprint_is_reported_and_never_pinned(self):
        self._load_login()
        self.page.evaluate("document.querySelector('.identity-toggle').click()")
        time.sleep(0.3)
        pinned_before = self.page.evaluate("Api.pinnedFingerprint()")

        self._submit("A" * 64)
        classes, message = self._result()
        self.assertIn("is-bad", classes)
        self.assertIn("NOT match", message)
        self.assertEqual(self.page.evaluate("Api.pinnedFingerprint()"),
                         pinned_before,
                         "a mismatched fingerprint must not overwrite the pin")

    def test_malformed_input_is_rejected_without_touching_the_pin(self):
        self._load_login()
        self.page.evaluate("document.querySelector('.identity-toggle').click()")
        time.sleep(0.3)
        pinned_before = self.page.evaluate("Api.pinnedFingerprint()")
        self._submit("not-a-fingerprint")
        classes, message = self._result()
        self.assertIn("is-bad", classes)
        self.assertIn("64 hex", message)
        self.assertEqual(self.page.evaluate("Api.pinnedFingerprint()"),
                         pinned_before)

    def test_a_correct_fingerprint_pins_even_when_messily_formatted(self):
        """Operators paste from a terminal, so spacing and case cannot matter."""
        self._load_login()
        self.page.evaluate("Api.clearPin()")
        self.page.evaluate("document.querySelector('.identity-toggle').click()")
        time.sleep(0.3)
        live = self._panel_values()[0]
        messy = live.lower().replace(" ", "").replace(":", "")
        self._submit(messy)
        classes, _ = self._result()
        self.assertIn("is-ok", classes, "a messy but valid fingerprint was rejected")
        self.assertEqual(self.page.evaluate("Api.pinnedFingerprint()"), live)

    def test_a_stale_pin_is_replaced_by_verifying_the_new_value(self):
        """Why there is no "forget pin" button.

        Every recovery it offered has to work without it, otherwise its removal
        would strand somebody mid-incident. So: with a pin in place, submitting
        the correct fingerprint replaces it -- no clearing step in between."""
        self._load_login()
        stale = self.page.evaluate("Api.pinnedFingerprint()")
        self.assertTrue(stale)
        live = self._panel_values()[0]
        self.assertEqual(self.page.evaluate("Api.pinnedFingerprint()"), live)

        # A value that is not the live one must not silently become the pin.
        self.page.evaluate("document.querySelector('.identity-toggle').click()")
        time.sleep(0.3)
        self._submit("B" * 64)
        self.assertEqual(self.page.evaluate("Api.pinnedFingerprint()"), stale,
                         "the pin changed even though the value was wrong")

        # Submitting the live value replaces the pin in one step.
        self._submit(live)
        classes, _ = self._result()
        self.assertIn("is-ok", classes)
        self.assertEqual(self.page.evaluate("Api.pinnedFingerprint()"), live)

    def test_the_panel_offers_no_way_to_drop_a_verified_pin(self):
        """A permanent one-click downgrade to TOFU has no compensating benefit,
        so the control must not creep back in unnoticed."""
        self._load_login()
        self.page.evaluate("Api.clearPin()")
        self.page.evaluate("document.querySelector('.identity-toggle').click()")
        time.sleep(0.3)
        labels = self.page.evaluate(
            "[...document.querySelectorAll('.identity-body button')]"
            ".map((b) => b.textContent)")
        self.assertEqual(
            labels, ["copy", "Verify and pin"],
            "the panel should only offer copying and verifying")

    def test_rotating_the_key_surfaces_the_change_and_accepts_the_new_value(self):
        """The pin earns its keep here: the new key is shown, the stale one is
        flagged, and the panel opens by itself instead of hiding the evidence."""
        self._load_login()
        old = self.page.evaluate("Api.pinnedFingerprint()")
        self.assertTrue(old, "the first visit should pin automatically")

        # Rotate: stop, drop the persisted signing key, start again.
        self.server.terminate()
        self.server.wait(timeout=15)
        os.unlink(Path(self.data_dir) / "enc_keys.json")
        self._start_server()
        new = read_enc_status(self.base)["fingerprint"]
        self.assertNotEqual(new, old, "the key was not actually replaced")

        self._load_login()
        self.assertTrue(self.page.evaluate("Api.identityChanged"),
                        "the client did not notice the identity change")
        self.assertTrue(
            self.page.evaluate("!!document.getElementById('identity-warning')"),
            "no warning banner after an identity change")
        self.assertTrue(
            self.page.evaluate("!document.querySelector('.identity-body')"
                               ".classList.contains('hidden')"),
            "the verification panel must open itself on an identity change")

        live, pinned = self._panel_values()
        self.assertEqual(live.replace(" ", ""), new.replace(" ", ""),
                         "the panel must show the fingerprint actually presented")
        self.assertEqual(pinned.replace(" ", ""), old.replace(" ", ""),
                         "the stale pin should still be shown, for comparison")
        self.assertTrue(
            self.page.evaluate("document.querySelectorAll('.identity-value')[1]"
                               ".classList.contains('is-bad')"),
            "the stale pin must be flagged, not silently replaced")
        self.assertIn("verify",
                      self.page.evaluate("document.querySelector("
                                         "'.identity-toggle-hint').textContent"))

        # And the new fingerprint, read from the server, is accepted.
        self._submit(new)
        classes, _ = self._result()
        self.assertIn("is-ok", classes)
        self.assertEqual(self.page.evaluate("Api.pinnedFingerprint()"), new)
        self.assertFalse(
            self.page.evaluate("document.querySelectorAll('.identity-value')[1]"
                               ".classList.contains('is-bad')"),
            "the flag should clear once the new identity is pinned")


if __name__ == "__main__":
    unittest.main()