"""The app is installable, and stays within what it says it is.

"Installable" here means exactly one thing: the browser will offer to install
it, and the installed copy launches without browser chrome. It does NOT mean
offline, and it does NOT mean push -- both of those are deliberately out of
scope, and the ceiling is pinned below rather than left to a comment.

The service worker exists only to make the install possible. It caches
nothing, and that is checked here for the reason that matters: the channel
keys live in the page's sessionStorage, which a service worker cannot read,
so a cached response would be ciphertext with no key beside it -- and the
message bodies would be on disk in the browser's cache storage regardless.

Requires a Chrome/Chromium binary plus the `websocket-client` module, so it
skips on a bare CI runner instead of reporting a pass it did not earn.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    import websocket

    HAVE_WEBSOCKET = True
except ImportError:  # pragma: no cover - exercised on bare runners
    HAVE_WEBSOCKET = False

from test_responsive_layout import CdpSession, _find_chrome, _free_port, _wait_http

STATIC = ROOT / "app" / "static"


class PwaAssetTests(unittest.TestCase):
    """The files themselves: no server, no browser."""

    def test_the_manifest_exists_and_is_valid_json(self):
        path = STATIC / "manifest.webmanifest"
        self.assertTrue(path.is_file(), "there is no web app manifest")
        try:
            manifest = json.loads(path.read_text(encoding="utf-8"))
        except ValueError as exc:
            self.fail(f"the manifest is not valid JSON: {exc}")
        self.assertEqual("standalone", manifest.get("display"),
                         "without display:standalone the installed copy is a "
                         "browser tab, not an app")
        self.assertTrue(manifest.get("name"), "the manifest has no name")
        self.assertTrue(manifest.get("short_name"),
                        "the manifest has no short name, so the home-screen "
                        "label would be the full one")
        self.assertTrue(manifest.get("start_url"), "the manifest has no start_url")
        self.assertTrue(manifest.get("theme_color"), "the manifest has no theme_color")

    def test_the_manifest_names_icons_that_exist_and_are_the_right_size(self):
        """A manifest whose icons 404 parses fine and still fails to install.

        Checked with the actual PNG header rather than trusting the declared
        size, so a file that is not really the size it claims cannot slip
        through."""
        import struct

        manifest = json.loads(
            (STATIC / "manifest.webmanifest").read_text(encoding="utf-8"))
        icons = manifest.get("icons") or []
        self.assertTrue(icons, "the manifest declares no icons")
        sizes = set()
        for icon in icons:
            src = icon.get("src", "")
            # /static/x.png is served from app/static/x.png
            path = (STATIC / src.rsplit("/", 1)[-1]) if src.startswith("/") \
                else STATIC / src
            with self.subTest(icon=src):
                self.assertTrue(path.is_file(), f"{src} does not exist")
                blob = path.read_bytes()
                self.assertEqual(b"\x89PNG\r\n\x1a\n", blob[:8],
                                 f"{src} is not a PNG")
                width, height = struct.unpack(">II", blob[16:24])
                declared = icon.get("sizes", "")
                self.assertIn(str(width), declared,
                              f"{src} is {width}x{height} but declares "
                              f"{declared}")
                self.assertEqual(width, height, f"{src} is not square")
                sizes.add(width)
        # Chrome wants a 192 and a 512 for a full-size install prompt.
        self.assertIn(192, sizes, "no 192px icon")
        self.assertIn(512, sizes, "no 512px icon")

    def test_the_manifest_offers_a_maskable_icon(self):
        """Android crops the icon to whatever shape the launcher uses, which
        can hide a mark that fills the whole canvas. A maskable icon keeps the
        mark inside the safe zone.

        The `purpose` field is read per icon, not out of the joined text: the
        file names contain "maskable" too, so a substring search over the
        manifest passes whether or not any icon is actually marked maskable.
        """
        manifest = json.loads(
            (STATIC / "manifest.webmanifest").read_text(encoding="utf-8"))
        purposes = [i.get("purpose", "") for i in manifest.get("icons", [])]
        self.assertTrue(
            any("maskable" in p.split() for p in purposes),
            f"no icon is marked maskable (purposes: {purposes}), so the "
            "launcher may crop the mark")

    def test_the_service_worker_caches_nothing(self):
        """The ceiling, pinned.

        The channel keys live in sessionStorage, which a service worker cannot
        read. So a cached response would be ciphertext with no key beside it --
        useless -- while the message bodies would sit on disk in the browser's
        cache storage. A fetch handler is what turns a worker into a cache, so
        its absence is the property that matters.
        """
        text = (STATIC / "sw.js").read_text(encoding="utf-8")
        for banned in ("caches.open", "caches.match", "addEventListener('fetch'",
                       'addEventListener("fetch"', "cache.add", "cache.put"):
            with self.subTest(token=banned):
                self.assertNotIn(banned, text,
                                 f"the service worker uses {banned}; it was "
                                 "supposed to cache nothing")

    def test_the_service_worker_does_not_subscribe_to_push(self):
        """Push is a separate feature with a separate cost (a push service, an
        outbound call, endpoint storage). It is not part of 'installable', and
        a worker that quietly subscribed would have made the ceiling a lie.

        Spelled out rather than grepped for the word "push": the first version
        of this guard looked for the phrase "push event", which no code writes,
        so a worker with a real push handler passed it.
        """
        text = (STATIC / "sw.js").read_text(encoding="utf-8")
        for banned in ("pushManager", ".subscribe(", "addEventListener('push'",
                       'addEventListener("push"', "showNotification"):
            with self.subTest(token=banned):
                self.assertNotIn(banned, text,
                                 f"the service worker references {banned}")


class PwaPageTests(unittest.TestCase):
    """Every page has to point at the manifest, or the install prompt never
    appears on the page the user is actually looking at."""

    pages = ("login.html", "register.html", "chat.html", "admin.html")

    def test_every_page_links_the_manifest(self):
        for name in self.pages:
            with self.subTest(page=name):
                html = (STATIC / name).read_text(encoding="utf-8")
                self.assertIn('rel="manifest"', html,
                              f"{name} does not link a manifest, so the app "
                              "cannot be installed from it")
                self.assertIn("/static/manifest.webmanifest", html)

    def test_every_page_carries_the_apple_home_screen_tags(self):
        """iOS ignores the manifest for the home-screen shortcut and reads
        these instead. Without them the installed copy gets a screenshot of
        the page and the wrong title."""
        for name in self.pages:
            with self.subTest(page=name):
                html = (STATIC / name).read_text(encoding="utf-8")
                self.assertIn("apple-mobile-web-app-capable", html,
                              f"{name} has no apple-mobile-web-app-capable")
                self.assertIn("apple-mobile-web-app-title", html)
                self.assertIn("apple-touch-icon", html,
                              f"{name} has no apple-touch-icon, so the home "
                              "screen shows a screenshot instead of the mark")
                self.assertIn("theme-color", html,
                              f"{name} has no theme-color")


@unittest.skipUnless(HAVE_WEBSOCKET, "needs the websocket-client module")
@unittest.skipIf(_find_chrome() is None, "needs a Chrome/Chromium binary")
class InstallabilityTests(unittest.TestCase):
    """Chrome's own verdict, on the real app."""

    @classmethod
    def setUpClass(cls):
        cls.data_dir = tempfile.mkdtemp(prefix="chat-pwa-")
        cls.profile = tempfile.mkdtemp(prefix="chrome-pwa-")
        cls.port = _free_port()
        cls.cdp_port = _free_port()
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
        for path in (getattr(cls, "data_dir", None), getattr(cls, "profile", None)):
            if path:
                shutil.rmtree(path, ignore_errors=True)

    @classmethod
    def tearDownClass(cls):
        cls._teardown()

    def _get(self, path):
        try:
            with urllib.request.urlopen(self.base + path, timeout=15) as r:
                return r.status, r.headers, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.headers, e.read()

    @staticmethod
    def _await(page, expression):
        """Evaluate an expression that returns a promise, and wait for it.

        `CdpSession.evaluate` does not set awaitPromise, so a promise comes
        back as an empty object -- which is how a test can silently end up
        comparing `{}` against the thing it meant to read. Done here rather
        than by changing the shared helper, because every other test in the
        suite depends on that helper's exact behaviour.
        """
        out = page.send("Runtime.evaluate", expression=expression,
                        awaitPromise=True, returnByValue=True)
        if out.get("exceptionDetails"):
            raise RuntimeError(out["exceptionDetails"].get("text", "page error"))
        return out.get("result", {}).get("value")

    def _page(self):
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
        session.send("Network.setCacheDisabled", cacheDisabled=True)
        return session

    def test_the_worker_is_served_at_the_root_with_the_right_headers(self):
        """The root, because a service worker's scope can never be wider than
        the directory it is served from. And no-cache, because the browser
        only installs a new worker when the bytes differ -- a long-lived cache
        would mean updates never arrive."""
        status, headers, body = self._get("/sw.js")
        self.assertEqual(200, status, "there is no worker at the root")
        self.assertIn("javascript", headers.get("Content-Type", ""),
                      f"the worker is served as "
                      f"{headers.get('Content-Type')!r}")
        self.assertIn("no-cache", headers.get("Cache-Control", ""),
                      "a cached worker never updates")
        self.assertEqual("/", headers.get("Service-Worker-Allowed"),
                         "the worker may only control /")
        self.assertIn(b"skipWaiting", body)

    def test_the_manifest_is_served_with_the_manifest_media_type(self):
        """A manifest served as text/plain is ignored by the browser."""
        status, headers, body = self._get("/manifest.webmanifest")
        self.assertEqual(200, status)
        self.assertIn("manifest", headers.get("Content-Type", ""),
                      f"the manifest is served as "
                      f"{headers.get('Content-Type')!r}")
        self.assertEqual("application/manifest+json",
                         headers.get("Content-Type", "").split(";")[0].strip())

    def test_every_icon_the_manifest_names_is_served(self):
        manifest = json.loads(
            (STATIC / "manifest.webmanifest").read_text(encoding="utf-8"))
        for icon in manifest.get("icons", []):
            src = icon["src"]
            with self.subTest(icon=src):
                status, headers, body = self._get(src)
                self.assertEqual(200, status, f"{src} is not served")
                self.assertEqual(b"\x89PNG\r\n\x1a\n", body[:8],
                                 f"{src} is not a PNG")

    def test_the_worker_registers_with_a_root_scope(self):
        """A worker served from a subdirectory can only control that
        subdirectory, and a scope that does not include the registering page is
        refused outright -- so the scope here is the whole point."""
        page = self._page()
        try:
            page.goto(self.base + "/login")
            time.sleep(4.0)
            scope = self._await(
                page,
                "navigator.serviceWorker.getRegistration()"
                ".then(r => r ? r.scope : null)")
            self.assertIsNotNone(scope, "the service worker did not register")
            self.assertEqual(self.base + "/", scope,
                             f"the worker controls {scope}, not the whole app")
            state = self._await(
                page,
                "navigator.serviceWorker.getRegistration()"
                ".then(r => r && r.active ? 'active' : 'not active')")
            self.assertEqual("active", state,
                             "the worker registered but never activated")
        finally:
            try:
                page.ws.close()
            except Exception:
                pass

    def test_chrome_agrees_the_app_is_installable(self):
        """Chrome's own verdict, not an interpretation of the manifest.

        This is the check that would have caught a manifest with a 404 in one
        of its icons, a missing maskable icon, or a worker that never
        registered -- none of which show up as an error anywhere else.
        """
        page = self._page()
        try:
            page.goto(self.base + "/login")
            time.sleep(5.0)
            manifest = page.send("Page.getAppManifest")
            errors = manifest.get("result", {}).get("errors") or []
            self.assertEqual([], errors,
                             f"the browser could not parse the manifest: {errors}")
            verdict = page.send("Page.getInstallabilityErrors")
            problems = verdict.get("result", {}).get("installabilityErrors")
            self.assertIn(problems, (None, []),
                          f"Chrome will not offer to install the app: {problems}")
        finally:
            try:
                page.ws.close()
            except Exception:
                pass


if __name__ == "__main__":
    unittest.main()
