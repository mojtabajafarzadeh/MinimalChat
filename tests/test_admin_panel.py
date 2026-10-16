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

    def test_the_panel_works_under_a_custom_admin_path(self):
        """ADMIN_PATH is configurable, so a fix hardcoding /admin/api would
        pass the default case and still be wrong."""
        self._boot(enc_enabled=False, admin_path="/my-control-panel")
        status, body = self._get(self.admin_path)
        self.assertEqual(status, 200)
        self.assertIn("/my-control-panel/api", body,
                      "the page does not point at its own prefix")

        jar = http.cookiejar.CookieJar()
        status, body = self._post_jar(
            self.admin_path + "/api/login",
            {"password": "panel-test-password"}, jar)
        self.assertEqual(status, 200, f"custom-path login failed: {body}")

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
        import importlib
        from app import config
        old = os.environ.get("ADMIN_PATH")
        try:
            os.environ["ADMIN_PATH"] = value
            importlib.reload(config)
            return config.ADMIN_PATH
        finally:
            if old is None:
                os.environ.pop("ADMIN_PATH", None)
            else:
                os.environ["ADMIN_PATH"] = old
            importlib.reload(config)

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