"""Escaping and CSP.

Neither is observable in the DOM: `esc()` looking incomplete is invisible
until a value reaches a quoted attribute, and a missing CSP is invisible
until something tries to use it. So both are checked directly -- the escaper
as a function, the CSP as a header on real responses.

The escaper test asserts the property that matters rather than an exact
string: after escaping, no quote, angle bracket or ampersand survives, so the
output is inert in both a text node and a single- or double-quoted attribute.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_responsive_layout import _free_port, _wait_http

PAYLOAD = '"><img src=x onerror=alert(1)>'


class EscaperTests(unittest.TestCase):
    """Both copies of esc(), run in a real JS engine.

    Extracting the expression and exec'ing it as Python does not work -- the
    regex literals and single-quoted replacements are not Python. So the
    function is lifted out of the source and executed by node, which is what
    the browser would do.
    """

    @staticmethod
    def _extract(rel):
        import re
        src = (ROOT / rel).read_text(encoding="utf-8")
        m = re.search(r"function esc\(s\) \{.*?\n\s*\}", src, re.S)
        if not m:
            raise AssertionError(f"esc() not found in {rel}")
        return m.group(0)

    def _run(self, rel, inputs):
        """Run the real esc() over inputs; return the outputs."""
        import json
        import subprocess
        fn = self._extract(rel)
        script = (
            fn + "\n"
            "const inputs = " + json.dumps(inputs) + ";\n"
            "console.log(JSON.stringify(inputs.map(esc)));\n"
        )
        proc = subprocess.run(["node", "-e", script], capture_output=True,
                              text=True, timeout=30)
        if proc.returncode != 0:
            raise AssertionError(
                f"node failed on {rel}: {proc.stderr[:400]}")
        return json.loads(proc.stdout)

    def setUp(self):
        if not shutil.which("node"):
            self.skipTest("node is needed to run the real escaper")
        # admin.js, not admin.html: the panel's esc() moved into an external
        # file so the CSP could drop 'unsafe-inline'. The test follows the
        # code, so it has to follow that move too.
        self.sources = ["app/static/app.js", "app/static/admin.js"]

    def _both(self, inputs):
        for rel in self.sources:
            with self.subTest(source=rel):
                yield rel, self._run(rel, inputs)

    def test_angle_brackets_are_escaped(self):
        for rel, out in self._both(["<script>"]):
            self.assertEqual(out[0], "&lt;script&gt;")

    def test_quotes_are_escaped(self):
        """The gap this closes: quotes used to pass through untouched."""
        for rel, out in self._both(['"', "'"]):
            self.assertEqual(out[0], "&quot;")
            self.assertEqual(out[1], "&#39;")

    def test_a_stored_xss_payload_is_inert(self):
        for rel, out in self._both([PAYLOAD]):
            for ch in "<>\"'":
                self.assertNotIn(ch, out[0],
                                 f"{ch!r} survived escaping in {rel}")

    def test_ampersand_is_escaped_first(self):
        """Escaping & last would double-encode the other replacements."""
        for rel, out in self._both(["&lt;"]):
            self.assertEqual(out[0], "&amp;lt;")

    def test_plain_text_is_unchanged(self):
        for rel, out in self._both(["hello world"]):
            self.assertEqual(out[0], "hello world")

    def test_a_username_with_a_quote_cannot_break_out_of_an_attribute(self):
        """The exact latent hazard: esc() used inside a quoted attribute."""
        hostile = 'bob" onmouseover="alert(1)'
        for rel, out in self._both([hostile]):
            attr = 'title="' + out[0] + '"'
            self.assertNotIn('" onmouseover="', attr,
                             f"attribute break-out in {rel}")


class ContentSecurityPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data_dir = tempfile.mkdtemp(prefix="chat-csp-")
        cls.port = _free_port()
        cls.base = f"http://127.0.0.1:{cls.port}"
        env = dict(os.environ, PORT=str(cls.port),
                   CHAT_DATA_DIR=cls.data_dir, ENC_ENABLED="false",
                   REGISTRATION_ENABLED="true", SSL_CERTFILE="",
                   SSL_KEYFILE="", WORKERS="1")
        cls.server = subprocess.Popen(
            [sys.executable, str(ROOT / "run.py")], cwd=str(ROOT), env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not _wait_http(cls.base + "/login"):
            cls._teardown()
            raise unittest.SkipTest("the app did not start")

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

    def _headers(self, path):
        try:
            with urllib.request.urlopen(self.base + path, timeout=15) as r:
                return r.headers
        except urllib.error.HTTPError as e:
            return e.headers

    def test_every_page_carries_a_csp(self):
        for path in ("/login", "/register", "/chat", "/static/style.css"):
            with self.subTest(path=path):
                csp = self._headers(path).get("Content-Security-Policy")
                self.assertIsNotNone(csp, f"{path} has no CSP header")

    def test_the_policy_forbids_remote_origins(self):
        """The property that matters: nothing may be loaded from elsewhere,
        so executed script cannot exfiltrate the channel keys or the pin."""
        csp = self._headers("/login").get("Content-Security-Policy", "")
        self.assertIn("default-src 'self'", csp)
        self.assertIn("object-src 'none'", csp)
        self.assertIn("base-uri 'none'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertIn("form-action 'self'", csp)
        # No wildcard host and no blanket * anywhere.
        self.assertNotIn("*", csp.replace("'unsafe-inline'", ""),
                         "the policy contains a wildcard source")
        self.assertNotIn("http://", csp)
        self.assertNotIn("https://", csp)

    def test_the_policy_still_allows_the_apps_own_websocket(self):
        """connect-src names this origin in ws:// form -- and only this one.

        `'self'` alone would NOT permit the WebSocket, so the origin has to be
        spelled out. The point of the per-response Host is that it names
        exactly one: `ws: wss:` permitted every host on earth, which is the
        channel an injected script exfiltrates through."""
        csp = self._headers("/chat").get("Content-Security-Policy", "")
        self.assertIn(f"ws://127.0.0.1:{self.port}", csp,
                      "the app's own WebSocket would be blocked by this CSP")
        directive = next(p.strip() for p in csp.split(";")
                         if p.strip().startswith("connect-src"))
        self.assertEqual(directive,
                         f"connect-src 'self' ws://127.0.0.1:{self.port}")
        # ... and nothing else is reachable.
        self.assertNotIn("*", csp.replace("'unsafe-inline'", ""))


class NoRemoteAssetsTests(unittest.TestCase):
    """A CSP that permits 'self' only is only meaningful if nothing loads
    from anywhere else."""

    def test_no_external_urls_in_the_pages(self):
        import re
        for html in (ROOT / "app" / "static").glob("*.html"):
            text = html.read_text(encoding="utf-8")
            with self.subTest(page=html.name):
                for url in re.findall(r'(?:src|href)\s*=\s*"([^"]+)"', text):
                    self.assertFalse(
                        url.startswith(("http://", "https://", "//")),
                        f"{html.name} loads a remote asset: {url}")

    def test_no_external_urls_in_the_css(self):
        text = (ROOT / "app" / "static" / "style.css").read_text(encoding="utf-8")
        self.assertNotIn("http://", text)
        self.assertNotIn("https://", text)
        self.assertNotIn("@import", text)


if __name__ == "__main__":
    unittest.main()