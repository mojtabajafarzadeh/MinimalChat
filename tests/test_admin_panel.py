"""The admin panel must actually work.

It could not, in either transport configuration: the page is served at
`/admin` with no trailing slash, so its relative `./api` resolved against the
document URL and escaped to `/api` -- the *user* endpoints. Under the default
ENC_ENABLED that is a 403 from the channel gate; with it off it is a 400 from
the user login (which wants a username). The panel was only reachable by
hand-crafting the request.

These tests log in through the panel's own API and assert it works, under both
transports and under a non-default ADMIN_PATH -- the path is configurable, so
a fix that hardcoded `/admin/api` would pass the default case and still be
wrong.
"""
import http.cookiejar
import json
import os
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

from test_responsive_layout import _free_port, _wait_http

from testsupport import reload_settings, settings_env


class AdminPanelTests(unittest.TestCase):
    """One server per configuration."""

    def _boot(self, enc_enabled: bool, admin_path: str):
        self.data_dir = tempfile.mkdtemp(prefix="chat-admin-")
        self.port = _free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        env = dict(os.environ, PORT=str(self.port),
                   CHAT_DATA_DIR=self.data_dir,
                   ENC_ENABLED="true" if enc_enabled else "false",
                   REGISTRATION_ENABLED="true",
                   ADMIN_PATH=admin_path,
                   ADMIN_PASSWORD="panel-test-password",
                   SSL_CERTFILE="", SSL_KEYFILE="", WORKERS="1")
        self.server = subprocess.Popen(
            [sys.executable, str(ROOT / "run.py")], cwd=str(ROOT), env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not _wait_http(self.base + "/login"):
            self.server.terminate()
            shutil.rmtree(self.data_dir, ignore_errors=True)
            raise unittest.SkipTest("the app did not start")
        self.admin_path = admin_path

    def tearDown(self):
        proc = getattr(self, "server", None)
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
        path = getattr(self, "data_dir", None)
        if path:
            shutil.rmtree(path, ignore_errors=True)

    def _get(self, path):
        req = urllib.request.Request(self.base + path)
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    def _post_jar(self, path, fields, jar):
        opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(jar))
        req = urllib.request.Request(
            self.base + path, data=urllib.parse.urlencode(fields).encode())
        try:
            with opener.open(req, timeout=15) as r:
                return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    # ------------------------------------------------------------------ tests

    def test_the_page_carries_its_own_api_prefix(self):
        """The page must not resolve its API relative to the document URL."""
        self._boot(enc_enabled=False, admin_path="/admin")
        status, body = self._get(self.admin_path)
        self.assertEqual(status, 200, "the admin page is not served")
        self.assertNotIn("__ADMIN_API__", body,
                         "the server did not substitute the API prefix")
        self.assertNotIn("const API = './api'", body,
                         "the panel still uses a relative ./api path")

    def test_login_and_use_the_panel_end_to_end(self):
        self._boot(enc_enabled=False, admin_path="/admin")
        api = self.admin_path + "/api"

        jar = http.cookiejar.CookieJar()
        status, body = self._post_jar(
            api + "/login", {"password": "panel-test-password"}, jar)
        self.assertEqual(status, 200,
                         f"admin login failed: {status} {body}")
        self.assertIn('"ok"', body)

        # The session cookie must now authenticate the user list.
        opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(jar))
        with opener.open(urllib.request.Request(self.base + api + "/users"),
                         timeout=15) as r:
            users = json.loads(r.read())
        self.assertIsInstance(users, list)

        # And it must work for creating a user too. The endpoint returns only
        # {"ok":true,"id":N}, so re-read the list to confirm the new row.
        uname = "paneluser" + os.urandom(3).hex()
        status, body = self._post_jar(
            api + "/users",
            {"name": "Panel User", "username": uname,
             "password": "panel-user-pw", "confirm": "panel-user-pw"}, jar)
        self.assertEqual(status, 200, f"admin create-user failed: {body}")
        with opener.open(urllib.request.Request(self.base + api + "/users"),
                         timeout=15) as r:
            after = json.loads(r.read())
        self.assertTrue(any(u["username"] == uname for u in after),
                        f"created user {uname} is missing from the list")

    def test_a_wrong_admin_password_is_rejected(self):
        """The fix must not have made the panel's login reachable with any
        password, or have pointed it at the user login endpoint."""
        self._boot(enc_enabled=False, admin_path="/admin")
        jar = http.cookiejar.CookieJar()
        status, body = self._post_jar(
            self.admin_path + "/api/login", {"password": "wrong"}, jar)
        self.assertEqual(status, 401, f"wrong password accepted: {body}")

    @staticmethod
    def _panel_logic(page_html, fetch):
        """The admin panel's LOGIC, exactly as the browser would load it.

        Follows what the page actually references rather than assuming a
        form: a plain path -> fetch it, a data: URL -> decode it. Returns
        None when the page references no logic at all.

        (The data: case is dead code now -- the panel's logic is served
        same-origin so `script-src 'self'` permits it -- but it is left here
        so a regression that reintroduces inlining shows up as a readable
        failure here rather than as a silently blocked script.)
        """
        import base64
        import re

        for url in re.findall(r'src="(data:[^"]+)"', page_html):
            text = base64.b64decode(url.partition(",")[2]).decode("utf-8", "replace")
            if "var API" in text:
                return text
        for src in re.findall(r'src="([^"]+\.js)"', page_html):
            status, text = fetch(src)
            if status == 200 and "var API" in text:
                return text
        return None

    def test_the_panel_works_under_a_custom_admin_path(self):
        """ADMIN_PATH is configurable, so a fix hardcoding /admin/api would
        pass the default case and still be wrong.

        The prefix lands in the panel's LOGIC rather than the markup now --
        that logic moved out of an inline <script> so the CSP could drop
        'unsafe-inline' -- so the page is checked for the script it loads and
        the loaded script for the prefix."""
        self._boot(enc_enabled=False, admin_path="/my-control-panel")
        status, body = self._get(self.admin_path)
        self.assertEqual(status, 200)

        logic = self._panel_logic(body, self._get)
        self.assertIsNotNone(
            logic,
            "the panel page references no script that defines its API prefix; "
            "it would call nothing and the panel is dead")
        self.assertIn("/my-control-panel/api", logic,
                      "the panel's logic does not point at its own prefix")
        self.assertNotIn("__ADMIN_API__", logic,
                         "the placeholder was never replaced; the panel would "
                         "call __ADMIN_API__/users and nothing else")

        jar = http.cookiejar.CookieJar()
        status, body = self._post_jar(
            self.admin_path + "/api/login",
            {"password": "panel-test-password"}, jar)
        self.assertEqual(status, 200, f"custom-path login failed: {body}")

    def test_the_panel_script_is_served_same_origin_not_inlined(self):
        """A `data:` script is blocked by `script-src 'self'`, so the panel
        loads with dead logic. Confirmed in Chrome: with the data: form the
        browser logged `script-src-elem :: data` and admin.js never executed.

        So the rewritten copy has to come from a URL the policy permits."""
        self._boot(enc_enabled=False, admin_path="/admin")
        status, body = self._get("/admin")
        self.assertEqual(status, 200)
        self.assertNotIn('src="data:', body,
                         "the panel's logic is inlined as a data: URL, which "
                         "script-src 'self' blocks in every browser")
        self.assertIn('src="/admin/assets/admin.js"', body,
                      "the panel's logic is not served from the same-origin "
                      "asset route")

    def test_the_asset_route_serves_only_token_carrying_scripts(self):
        """It reads from the static directory, so it must not be a second way
        into every file there -- only the scripts that carry an injection
        token are served."""
        self._boot(enc_enabled=False, admin_path="/admin")
        status, body = self._get("/admin/assets/admin.js")
        self.assertEqual(status, 200)
        self.assertIn("var API", body)
        self.assertNotIn("__ADMIN_API__", body)

        for path in ("/admin/assets/app.js",      # no token
                     "/admin/assets/theme.js",    # no token
                     "/admin/assets/style.css",   # not a .js
                     "/admin/assets/../db.py",    # traversal
                     "/admin/assets/..%2fchat.db"):  # encoded traversal
            with self.subTest(path=path):
                status, _ = self._get(path)
                self.assertEqual(status, 404,
                                 f"{path} is served by the asset route")

    def test_the_asset_route_follows_admin_path(self):
        """The prefix is configurable, so the rewrite has to follow it --
        otherwise the panel at a custom prefix loads a 404 for its own logic."""
        self._boot(enc_enabled=False, admin_path="/my-control-panel")
        status, body = self._get("/my-control-panel")
        self.assertEqual(status, 200)
        self.assertIn('src="/my-control-panel/assets/admin.js"', body)
        status, script = self._get("/my-control-panel/assets/admin.js")
        self.assertEqual(status, 200)
        self.assertIn("/my-control-panel/api", script)

    def test_admin_mutations_reject_a_foreign_origin(self):
        """The login endpoints had this check; the three mutating ones did not.

        SameSite=Lax already keeps the cookie off a cross-site POST, so this is
        defence in depth -- but the README promises same-origin enforcement on
        browser POSTs, and a check that exists on half the routes is how that
        promise rots.
        """
        self._boot(enc_enabled=False, admin_path="/admin")
        api = self.admin_path + "/api"
        jar = http.cookiejar.CookieJar()
        status, body = self._post_jar(api + "/login",
                                      {"password": "panel-test-password"}, jar)
        self.assertEqual(status, 200, f"admin login failed: {body}")

        opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(jar))

        def call(path, method="POST", fields=None):
            data = urllib.parse.urlencode(fields).encode() if fields else None
            req = urllib.request.Request(
                self.base + path, data=data, method=method,
                headers={"Origin": "http://evil.example"})
            try:
                with opener.open(req, timeout=15) as r:
                    return r.status
            except urllib.error.HTTPError as e:
                return e.code

        self.assertEqual(
            call(api + "/users",
                 fields={"name": "X", "username": "eviluser",
                         "password": "password1", "confirm": "password1"}),
            403, "creating a user from a foreign origin was not refused")
        self.assertEqual(
            call(api + "/users/1", method="DELETE"), 403,
            "deleting a user from a foreign origin was not refused")
        self.assertEqual(
            call(api + "/users/1/password",
                 fields={"password": "password2", "confirm": "password2"}),
            403, "resetting a password from a foreign origin was not refused")

    def test_the_panel_works_with_the_encrypted_transport_on(self):
        """The default configuration. This is the case that reported 403."""
        self._boot(enc_enabled=True, admin_path="/admin")
        jar = http.cookiejar.CookieJar()
        status, body = self._post_jar(
            self.admin_path + "/api/login",
            {"password": "panel-test-password"}, jar)
        self.assertEqual(
            status, 200,
            f"admin login broken under ENC_ENABLED=true: {status} {body}")


class AdminPathCollisionTests(unittest.TestCase):
    """ADMIN_PATH must not shadow another feature's route family."""

    def _resolve(self, value):
        with settings_env(ADMIN_PATH=value) as config:
            return config.ADMIN_PATH

    def test_enc_is_refused(self):
        """Admin routes register before the encrypted bridge, so /enc would
        turn /enc/api/login into the admin login and break the bridge."""
        self.assertEqual(self._resolve("/enc"), "/admin")

    def test_the_existing_reserved_paths_are_still_refused(self):
        for path in ("/api", "/ws", "/static", "/chat", "/login", "/register"):
            with self.subTest(path=path):
                self.assertEqual(self._resolve(path), "/admin")

    def test_a_normal_custom_path_is_accepted(self):
        self.assertEqual(self._resolve("/my-control-panel"), "/my-control-panel")
        self.assertEqual(self._resolve("/ops_1"), "/ops_1")


if __name__ == "__main__":
    unittest.main()