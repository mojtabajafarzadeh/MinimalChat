"""The CSP is strict: no 'unsafe-inline' for script, and no blanket ws:.

The policy this file locks in is the difference between "a CSP is present" and
"a CSP is worth having". Both halves were weak before:

- `script-src 'self' 'unsafe-inline'` means an injected inline script runs.
  An XSS does not need to load a remote payload to steal the encrypted
  channel keys -- it can read them straight out of sessionStorage and POST
  them anywhere. 'unsafe-inline' waived exactly the restriction that mattered.
- `connect-src 'self' ws: wss:` permitted a WebSocket to *any* host, which
  is the exfiltration channel an injected script reaches for.

So the guard scripts moved to external .js files and connect-src is built per
response from the Host the client actually reached.
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

from app.security import SecurityHeadersMiddleware

from test_responsive_layout import _free_port, _wait_http

# The literal placeholders and handlers an injected payload would need.
INJECTION_MARKERS = (
    "<script>", "</script>", "onerror=", "onclick=", "onload=",
    "javascript:", "eval(",
)


class ConnectSrcTests(unittest.TestCase):
    """The source list itself -- no server needed, and no way to be fooled by
    how the header happened to be rendered."""

    def test_same_origin_websocket_is_named(self):
        """`ws://host` has to be there: a `ws:` URL is not same-origin with
        an `http:` page as far as CSP is concerned, so `'self'` alone blocks
        the app's own socket."""
        out = SecurityHeadersMiddleware._connect_src("chat.example.com", "http")
        self.assertIn("'self'", out)
        self.assertIn("ws://chat.example.com", out)

    def test_https_never_advertises_a_cleartext_socket(self):
        """wss:// on an https page. Offering ws:// there would hand an
        injected script an unencrypted channel out of a secure page."""
        out = SecurityHeadersMiddleware._connect_src("chat.example.com", "https")
        self.assertIn("wss://chat.example.com", out)
        self.assertNotIn("ws://", out)

    def test_only_one_host_is_reachable(self):
        """The whole point: `ws: wss:` permitted every host on earth, which is
        exactly the channel an injected script exfiltrates through."""
        for host in ("a.example.com", "127.0.0.1:8000", "[::1]:8000"):
            with self.subTest(host=host):
                out = SecurityHeadersMiddleware._connect_src(host, "http")
                self.assertEqual(out, f"'self' ws://{host}")

    def test_no_scheme_wildcards_survive(self):
        """Structural, so it holds whatever the header renders as later."""
        for host in ("a.example.com", "127.0.0.1:8000"):
            out = SecurityHeadersMiddleware._connect_src(host, "http")
            for source in out.split():
                self.assertRegex(source, r"^('self'|(wss?|https?)://.+)$",
                                 f"{source!r} is not a host-scoped source; a "
                                 "scheme-only source permits any host")

    def test_a_hostile_host_fails_closed(self):
        """A Host header is attacker-influenced. None of these may widen the
        policy -- each must produce no connect-src value at all, and the header
        builder must then omit the directive entirely, so the policy falls
        back to default-src 'self' rather than naming anything."""
        import asyncio

        from app.security import SecurityHeadersMiddleware as M

        class _FakeResponse:
            headers: dict = {}

        class _FakeRequest:
            def __init__(self, host):
                self.headers = {"host": host}
                self.url = type("U", (), {"scheme": "http"})()

            async def __call__(self):
                return _FakeResponse()

        async def _next(request):
            return _FakeResponse()

        for host in ('', '   ', 'evil.com; script-src *', 'a b',
                     'x"y', "a'b", 'a/b', 'a\\b', 'a<b', 'a>b', 'a\nb'):
            with self.subTest(host=host):
                self.assertEqual(M._connect_src(host, "http"), "")
                resp = asyncio.run(M(_FakeRequest(host)).dispatch(
                    _FakeRequest(host), _next))
                csp = resp.headers["Content-Security-Policy"]
                self.assertNotIn("connect-src", csp,
                                 f"Host {host!r} produced {csp!r} instead of "
                                 "failing closed to default-src 'self'")
                self.assertIn("default-src 'self'", csp)


class NoInlineScriptTests(unittest.TestCase):
    """The pages themselves. If an inline <script> comes back, the CSP needs
    'unsafe-inline' again, and the weakness above comes straight back."""

    @classmethod
    def setUpClass(cls):
        cls.data_dir = tempfile.mkdtemp(prefix="chat-csp2-")
        cls.port = _free_port()
        cls.base = f"http://127.0.0.1:{cls.port}"
        env = dict(os.environ, PORT=str(cls.port),
                   CHAT_DATA_DIR=cls.data_dir, ENC_ENABLED="false",
                   REGISTRATION_ENABLED="true", SSL_CERTFILE="",
                   SSL_KEYFILE="", WORKERS="1")
        cls.server = subprocess.Popen(
            [sys.executable, str(ROOT / "run.py")], cwd=str(ROOT), env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # The admin panel only exists while a password is configured, so it
        # needs a second instance with one set.
        cls.admin_port = _free_port()
        cls.admin_base = f"http://127.0.0.1:{cls.admin_port}"
        cls.admin_proc = subprocess.Popen(
            [sys.executable, str(ROOT / "run.py")], cwd=str(ROOT),
            env=dict(env, PORT=str(cls.admin_port),
                     ADMIN_PASSWORD="an-admin-passphrase"),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not _wait_http(cls.base + "/login"):
            cls._teardown()
            raise unittest.SkipTest("the app did not start")
        if not _wait_http(cls.admin_base + "/admin"):
            cls._teardown()
            raise unittest.SkipTest("the admin instance did not start")

    @classmethod
    def _teardown(cls):
        for proc in (getattr(cls, "server", None),
                     getattr(cls, "admin_proc", None)):
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

    def _get(self, path):
        try:
            with urllib.request.urlopen(self.base + path, timeout=15) as r:
                return r.read().decode("utf-8"), r.headers
        except urllib.error.HTTPError as e:
            return e.read().decode("utf-8"), e.headers

    def _policy(self, path="/login"):
        _, headers = self._get(path)
        return headers.get("Content-Security-Policy", "")

    def test_script_src_needs_no_unsafe_inline(self):
        """The regression this whole change exists to prevent."""
        for path in ("/login", "/register", "/chat"):
            with self.subTest(path=path):
                policy = self._policy(path)
                directive = next((p.strip() for p in policy.split(";")
                                  if p.strip().startswith("script-src")), "")
                self.assertEqual(directive, "script-src 'self'",
                                 "script-src is not plain 'self'; inline "
                                 "script would be blocked (or, worse, "
                                 "re-enabled with 'unsafe-inline')")

    def test_style_src_is_the_only_unsafe_one_left(self):
        policy = self._policy()
        with_unsafe = [p.strip().split()[0] for p in policy.split(";")
                       if "'unsafe-inline'" in p]
        self.assertEqual(with_unsafe, ["style-src"],
                         f"unexpected directives allow inline: {with_unsafe}")

    def test_no_page_carries_an_inline_script(self):
        for path in ("/login", "/register", "/chat"):
            with self.subTest(path=path):
                body, _ = self._get(path)
                self.assertNotIn("<script>", body,
                                 f"{path} has an inline script, so the CSP "
                                 "would need 'unsafe-inline' for script-src")

    def test_no_page_carries_an_inline_event_handler(self):
        for path in ("/login", "/register", "/chat"):
            with self.subTest(path=path):
                body, _ = self._get(path)
                for marker in ("onerror=", "onclick=", "onload=", "onfocus="):
                    self.assertNotIn(marker, body,
                                     f"{path} has an inline {marker} handler")

    def test_no_page_uses_a_javascript_url(self):
        for path in ("/login", "/register", "/chat"):
            with self.subTest(path=path):
                body, _ = self._get(path)
                self.assertNotIn("javascript:", body)

    def test_every_page_still_loads_its_logic(self):
        """Removing the inline blocks must not remove the behaviour: each page
        has to load the external file that replaces it, or the page silently
        stops working (a login form that does nothing on submit)."""
        for path, script in (("/login", "login.js"),
                             ("/register", "register.js")):
            with self.subTest(path=path):
                body, _ = self._get(path)
                self.assertIn(f'/static/{script}', body)
                asset, _ = self._get(f"/static/{script}")
                self.assertGreater(len(asset), 50,
                                   f"{script} is empty or truncated")

    def test_the_admin_panel_loads_its_logic_too(self):
        """The panel needs a configured password to exist at all, so it is
        served by its own instance with one set."""
        import base64
        import re

        try:
            with urllib.request.urlopen(self.admin_base + "/admin",
                                        timeout=15) as r:
                body = r.read().decode("utf-8")
                policy = r.headers.get("Content-Security-Policy", "")
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8")
            policy = e.headers.get("Content-Security-Policy", "")

        self.assertNotIn("<script>", body)
        self.assertEqual(
            next((p.strip() for p in policy.split(";")
                  if p.strip().startswith("script-src")), ""),
            "script-src 'self'")

        # The API prefix is injected into the panel's LOGIC, not the markup --
        # so wherever the logic is, it must carry the prefix. It normally
        # comes from /static/admin.js; page() may instead hand it over as a
        # data: URL carrying the rewritten file.
        with urllib.request.urlopen(self.admin_base + "/static/admin.js",
                                    timeout=15) as r:
            asset = r.read().decode("utf-8")
        if re.search(r'src="(/static/admin\.js)"', body):
            self.assertIn("'/admin/api'", asset,
                          "ADMIN_PATH was not injected into admin.js; the "
                          "panel would call the user endpoints")
        else:
            inlined = "".join(
                base64.b64decode(url.partition(",")[2]).decode("utf-8", "replace")
                for url in re.findall(r'src="(data:[^"]+)"', body))
            self.assertIn("'/admin/api'", inlined,
                          "the panel logic was served inline but without the "
                          "API prefix")
        self.assertNotIn("__ADMIN_API__", body)


class StaticJsIsSafeTests(unittest.TestCase):
    """Structural: the files that replaced the inline blocks must not smuggle
    an execution sink back in."""

    def test_no_script_file_uses_eval_or_function_constructor(self):
        for js in sorted((ROOT / "app" / "static").glob("*.js")):
            text = js.read_text(encoding="utf-8")
            with self.subTest(file=js.name):
                self.assertNotIn("eval(", text)
                self.assertNotIn("new Function(", text)

    def test_no_script_file_writes_with_document_write_or_insert_adjacent_html(self):
        for js in sorted((ROOT / "app" / "static").glob("*.js")):
            text = js.read_text(encoding="utf-8")
            with self.subTest(file=js.name):
                self.assertNotIn("document.write", text)
                self.assertNotIn("insertAdjacentHTML", text)


if __name__ == "__main__":
    unittest.main()
