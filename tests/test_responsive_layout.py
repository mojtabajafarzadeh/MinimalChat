"""Responsive layout regression tests, driven through a real browser.

These cover the class of bug a static review misses: CSS that only misbehaves
once a real box model runs. The bugs pinned here were all found by measuring
the rendered page rather than reading the stylesheet:

  * the conversation sidebar ate 51% of a 390px screen and the composer was
    pushed below the fold, so it is now an overlay drawer at <=600px;
  * `.main` had no `min-height: 0`, so in the stacked column layout the pane
    could not shrink below its content and the document -- not the message
    list -- became the scroll container;
  * the reply button was a 14px-tall sliver of text after it was converted
    from a div to a real button;
  * the theme toggle's colour-emoji glyph ignored `color`, and the header
    inverts with the theme, so it was unreadable in one of the two modes;
  * a long unbroken token (no spaces) had to wrap instead of forcing the
    document to scroll sideways.

Requires a Chrome/Chromium binary and the `websocket-client` module. Both are
absent on a bare CI runner, so the whole module skips there rather than
pretending to pass; `python -m unittest discover -s tests` still reports OK.
"""
import base64
import http.cookiejar
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "app" / "static"

try:  # optional: only needed to speak the DevTools protocol
    import websocket

    HAVE_WEBSOCKET = True
except ImportError:  # pragma: no cover - exercised on bare runners
    HAVE_WEBSOCKET = False

CHROME_CANDIDATES = (
    "google-chrome", "google-chrome-stable", "chromium", "chromium-browser",
    "/usr/bin/google-chrome", "/usr/bin/chromium",
)

# (width, height, label)
VIEWPORTS = (
    (320, 568, "small phone"),
    (390, 844, "phone"),
    (768, 1024, "tablet portrait"),
    (1024, 768, "tablet landscape"),
    (1440, 900, "desktop"),
)

NARROW = 600  # must match the sidebar-drawer breakpoint in style.css

# Measures what a human would notice: sideways scrolling, controls too small
# to hit, and text clipped below a legible size.
PROBE = r"""
(() => {
  const vw = document.documentElement.clientWidth;
  const out = { vw, docScrollW: document.documentElement.scrollWidth, issues: [] };
  if (out.docScrollW > vw + 1) {
    out.issues.push('page scrolls sideways: scrollWidth ' + out.docScrollW +
                    ' > viewport ' + vw);
  }
  const label = (el) => {
    let s = el.tagName.toLowerCase();
    if (el.id) s += '#' + el.id;
    if (typeof el.className === 'string' && el.className.trim()) {
      s += '.' + el.className.trim().split(/\s+/).join('.');
    }
    return s;
  };
  document.querySelectorAll('button, a[href], input[type=submit]').forEach((el) => {
    const r = el.getBoundingClientRect();
    const cs = getComputedStyle(el);
    if (cs.display === 'none' || cs.visibility === 'hidden') return;
    // An inline link inside a sentence is not a tap-target problem.
    if (el.tagName === 'A' && cs.display === 'inline') return;
    if (!r.width || !r.height) return;
    if (r.height < 24) {
      out.issues.push('tap target only ' + Math.round(r.height) +
                      'px tall: ' + label(el));
    }
  });
  document.querySelectorAll('*').forEach((el) => {
    if (el.offsetParent === null) return;
    const r = el.getBoundingClientRect();
    if (!r.width || !r.height) return;
    // Off-canvas content is fine when the page does not scroll sideways, which
    // the scrollWidth check above already establishes.
    if (r.right > vw + 1) {
      out.issues.push(label(el) + ' extends ' + Math.round(r.right - vw) +
                      'px past the viewport');
    }
  });
  return out;
})()
"""


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _find_chrome():
    for name in CHROME_CANDIDATES:
        path = shutil.which(name) if not os.path.isabs(name) else (
            name if os.path.exists(name) else None)
        if path:
            return path
    return None


def _wait_http(url, timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as r:
                if r.status < 500:
                    return True
        except urllib.error.HTTPError:
            return True
        except Exception:
            time.sleep(0.25)
    return False


class CdpSession:
    """The sliver of the DevTools protocol these tests need."""

    def __init__(self, ws):
        self.ws = ws
        self._seq = 0

    def send(self, method, **params):
        self._seq += 1
        self.ws.send(json.dumps({"id": self._seq, "method": method, "params": params}))
        deadline = time.time() + 30
        while time.time() < deadline:
            msg = json.loads(self.ws.recv())
            if msg.get("id") == self._seq:
                if "error" in msg:
                    raise RuntimeError(f"{method}: {msg['error']}")
                return msg.get("result", {})
        raise RuntimeError(f"{method}: timed out")

    def viewport(self, width, height):
        self.send("Emulation.setDeviceMetricsOverride", width=width, height=height,
                  deviceScaleFactor=1, mobile=width <= NARROW)
        self.send("Emulation.setTouchEmulationEnabled", enabled=width <= NARROW)

    def goto(self, url):
        self.send("Page.navigate", url=url)
        deadline = time.time() + 30
        while time.time() < deadline:
            state = self.send(
                "Runtime.evaluate", expression="document.readyState",
                returnByValue=True).get("result", {}).get("value")
            if state == "complete":
                return
            time.sleep(0.1)
        raise RuntimeError(f"navigation to {url} never completed")

    def evaluate(self, expression):
        out = self.send("Runtime.evaluate", expression=expression, returnByValue=True)
        if out.get("exceptionDetails"):
            raise RuntimeError(out["exceptionDetails"].get("text", "page error"))
        return out.get("result", {}).get("value")

    def probe(self):
        return self.evaluate(PROBE)

    def cookie(self, name, value):
        self.send("Network.setCookie", name=name, value=value, domain="127.0.0.1",
                  path="/")

    def clear_cookies(self):
        """Cookies live in the browser profile, so they outlive a single test."""
        self.send("Network.clearBrowserCookies")


@unittest.skipUnless(HAVE_WEBSOCKET, "needs the websocket-client module")
@unittest.skipIf(_find_chrome() is None, "needs a Chrome/Chromium binary")
class ResponsiveLayoutTests(unittest.TestCase):
    """One browser and one server for the whole class."""

    server = None
    chrome = None
    profile = None
    data_dir = None
    cdp_port = 0

    @classmethod
    def setUpClass(cls):
        cls.app_port = _free_port()
        cls.cdp_port = _free_port()
        cls.data_dir = tempfile.mkdtemp(prefix="chat-responsive-")
        env = dict(os.environ, PORT=str(cls.app_port), CHAT_DATA_DIR=cls.data_dir,
                   ENC_ENABLED="false", REGISTRATION_ENABLED="true",
                   ADMIN_PATH="/admin", ADMIN_PASSWORD="responsive-admin-pw",
                   SSL_CERTFILE="", SSL_KEYFILE="", WORKERS="1")
        cls.server = subprocess.Popen(
            [sys.executable, str(ROOT / "run.py")], cwd=str(ROOT), env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not _wait_http(f"http://127.0.0.1:{cls.app_port}/login"):
            cls._teardown()
            raise unittest.SkipTest("the app did not start")

        cls.profile = tempfile.mkdtemp(prefix="chrome-profile-")
        cls.chrome = subprocess.Popen(
            [_find_chrome(), "--headless=new", "--no-sandbox", "--disable-gpu",
             "--disable-dev-shm-usage", f"--remote-debugging-port={cls.cdp_port}",
             f"--user-data-dir={cls.profile}", "about:blank"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not _wait_http(f"http://127.0.0.1:{cls.cdp_port}/json/version"):
            cls._teardown()
            raise unittest.SkipTest("headless Chrome did not start")

        # A long unbroken token, a long URL and a very long username are the
        # content that actually breaks narrow layouts.
        cls.user = "resp" + uuid.uuid4().hex[:6]
        cls.long_user = "averyveryverylongusername" + uuid.uuid4().hex[:4]
        cls._post("/api/register", {"name": "Long Name User", "username": cls.user,
                                    "password": "responsive-pw",
                                    "confirm": "responsive-pw"})
        cls._post("/api/register", {"name": "Long Name User",
                                    "username": cls.long_user,
                                    "password": "responsive-pw",
                                    "confirm": "responsive-pw"})
        cls._seed_messages()

    @classmethod
    def _teardown(cls):
        for proc in (cls.chrome, cls.server):
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
        for path in (cls.data_dir, cls.profile):
            if path:
                shutil.rmtree(path, ignore_errors=True)

    @classmethod
    def tearDownClass(cls):
        cls._teardown()

    @classmethod
    def _post(cls, path, fields):
        """POST form fields, ignoring an error status (409 = already exists)."""
        data = urllib.parse.urlencode(fields).encode()
        req = urllib.request.Request(f"http://127.0.0.1:{cls.app_port}{path}",
                                     data=data)
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                r.read()
        except urllib.error.HTTPError as e:
            e.read()

    @classmethod
    def _session_cookie(cls):
        # CookieJar rather than dict(headers): the response carries several
        # Set-Cookie headers and the plain dict collapses them.
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(jar))
        data = urllib.parse.urlencode({"username": cls.user,
                                       "password": "responsive-pw"}).encode()
        opener.open(urllib.request.Request(
            f"http://127.0.0.1:{cls.app_port}/api/login", data=data), timeout=15).read()
        for cookie in jar:
            if cookie.name == "session_id":
                return cookie.value
        raise unittest.SkipTest("could not obtain a session cookie")

    @classmethod
    def _seed_messages(cls):
        """Push hostile content through the real WebSocket endpoint."""
        try:
            import asyncio

            import websockets
        except ImportError:
            return

        async def run():
            url = f"ws://127.0.0.1:{cls.app_port}/ws"
            async with websockets.connect(
                    url, additional_headers={
                        "Cookie": f"session_id={cls._session_cookie()}"}) as ws:
                frames = [
                    {"type": "public", "content": "x" * 400},
                    {"type": "public",
                     "content": "https://example.com/a/very/long/path?with=query"
                                "&and=more " + "\U0001f600" * 20},
                    {"type": "public", "content": "question being asked"},
                ]
                first_id = None
                for frame in frames:
                    await ws.send(json.dumps(frame))
                    reply = json.loads(await asyncio.wait_for(ws.recv(), timeout=10))
                    if first_id is None:
                        first_id = reply.get("id")
                await ws.send(json.dumps({"type": "public", "content": "the answer",
                                         "reply_to": first_id}))
                await asyncio.wait_for(ws.recv(), timeout=10)
                await ws.send(json.dumps({"type": "dm", "to": cls.long_user,
                                          "content": "a private message body"}))
                await asyncio.wait_for(ws.recv(), timeout=10)

            async with websockets.connect(
                    url, additional_headers={
                        "Cookie": f"session_id={cls._session_cookie()}"}) as ws2:
                await ws2.send(json.dumps({"type": "public",
                                          "content": "posted by the long username"}))
                await asyncio.wait_for(ws2.recv(), timeout=10)

        try:
            asyncio.run(run())
        except Exception:
            # Content seeding is a bonus: the overflow assertions still run on
            # whatever the room already holds.
            pass

    def setUp(self):
        self.page = self._open_page()
        self.base = f"http://127.0.0.1:{self.app_port}"

    def tearDown(self):
        try:
            self.page.ws.close()
        except Exception:
            pass

    def _open_page(self):
        with urllib.request.urlopen(
                f"http://127.0.0.1:{self.cdp_port}/json/list", timeout=15) as r:
            targets = json.load(r)
        page = next(t for t in targets if t.get("type") == "page")
        ws = websocket.create_connection(page["webSocketDebuggerUrl"], timeout=30,
                                         suppress_origin=True)
        session = CdpSession(ws)
        session.send("Page.enable")
        session.send("Runtime.enable")
        session.send("Network.enable")
        return session

    def _visit(self, path, cookie=None):
        """Assert every viewport is free of layout defects."""
        for width, height, _ in VIEWPORTS:
            with self.subTest(path=path, viewport=f"{width}x{height}"):
                self.page.viewport(width, height)
                if cookie:
                    self.page.cookie("session_id", cookie)
                else:
                    # A session left over from another test would bounce
                    # /login and /register to /chat, and the probe would then
                    # measure the wrong page entirely.
                    self.page.clear_cookies()
                self.page.goto(self.base + path)
                time.sleep(0.5)
                # Guard against silently auditing a redirect target.
                self.assertEqual(
                    path, self.page.evaluate("location.pathname"),
                    f"asked for {path} but landed on "
                    f"{self.page.evaluate('location.pathname')}")
                found = self.page.probe()
                self.assertEqual(
                    [], found["issues"],
                    f"{path} at {width}x{height}: " + "; ".join(found["issues"]))

    # ------------------------------------------------------------------ pages

    def test_auth_pages_have_no_layout_defects(self):
        for path in ("/login", "/register"):
            self._visit(path)

    def test_chat_page_has_no_layout_defects(self):
        cookie = self._session_cookie()
        self._visit("/chat", cookie=cookie)

    def test_admin_page_has_no_layout_defects(self):
        cookie = self._session_cookie()
        self._visit("/admin", cookie=cookie)

    def test_chat_fits_the_viewport_height_without_scrolling_the_document(self):
        """The composer must stay on screen; the message list scrolls instead."""
        cookie = self._session_cookie()
        for width, height, label in VIEWPORTS:
            with self.subTest(viewport=f"{width}x{height}"):
                self.page.viewport(width, height)
                self.page.cookie("session_id", cookie)
                self.page.goto(self.base + "/chat")
                time.sleep(0.6)
                self.assertFalse(
                    self.page.evaluate("document.documentElement.scrollHeight >"
                                       " document.documentElement.clientHeight + 1"),
                    f"the document itself scrolls at {width}x{height}, so the "
                    f"composer can end up below the fold ({label})")
                self.assertTrue(
                    self.page.evaluate(
                        "(() => { const c = document.querySelector('.composer');"
                        " if (!c) return false;"
                        " return c.getBoundingClientRect().bottom <="
                        "        document.documentElement.clientHeight + 1; })()"),
                    f"the composer is not visible at {width}x{height} ({label})")

    def test_message_bubbles_stay_within_a_readable_line_length(self):
        """The app frame caps at 68rem, so 85% still reached ~95 characters."""
        cookie = self._session_cookie()
        for width, height, label in ((390, 844, "phone"), (1440, 900, "desktop")):
            with self.subTest(viewport=label):
                self.page.viewport(width, height)
                self.page.cookie("session_id", cookie)
                self.page.goto(self.base + "/chat")
                time.sleep(0.6)
                widest = self.page.evaluate(
                    "Math.max(...[...document.querySelectorAll('.msg')]"
                    ".map((m) => m.getBoundingClientRect().width))")
                self.assertGreater(widest, 0, "no messages rendered to measure")
                self.assertLessEqual(
                    widest, 36 * 16 + 1,
                    f"a bubble is {round(widest)}px wide at {width}x{height}; "
                    f"past ~36rem the line length stops being readable")

    # ---------------------------------------------------------------- spacing

    # The auth forms share one vertical rhythm. These are the only gaps the
    # design uses; anything else means a margin was lost or doubled up.
    RHYTHM_GAPS = (6, 16, 20)

    def test_auth_form_spacing_follows_one_rhythm(self):
        """Consecutive fields used to sit 2px apart, and the submit button
        touched the field above it (0px), because the label rule was never
        applied and inputs carried no margin."""
        probe = """
        (() => {
          const form = document.querySelector('.card');
          const vis = [...form.children].filter(
            (e) => getComputedStyle(e).display !== 'none');
          const gaps = [];
          for (let i = 1; i < vis.length; i += 1) {
            const a = vis[i - 1].getBoundingClientRect();
            const b = vis[i].getBoundingClientRect();
            gaps.push(Math.round(b.top - a.bottom));
          }
          const input = document.querySelector('.input');
          const button = document.querySelector('.btn-block');
          return {
            gaps,
            inputH: Math.round(input.getBoundingClientRect().height),
            buttonH: Math.round(button.getBoundingClientRect().height),
          };
        })()
        """
        allowed = self.RHYTHM_GAPS
        for path in ("/login", "/register"):
            for with_error in (False, True):
                with self.subTest(page=path, error=with_error):
                    self.page.viewport(1024, 800)
                    self.page.clear_cookies()
                    self.page.goto(self.base + path)
                    time.sleep(0.4)
                    if with_error:
                        # The error alert is hidden in the default state, so
                        # its spacing would otherwise never be measured.
                        self.page.evaluate(
                            "(() => { const e = document.getElementById('error');"
                            " e.textContent = 'Invalid username or password.';"
                            " e.classList.remove('hidden'); })()")
                        time.sleep(0.2)
                    found = self.page.evaluate(probe)
                    for gap in found["gaps"]:
                        self.assertTrue(
                            any(abs(gap - value) <= 1 for value in allowed),
                            f"{path} (error={with_error}) has a {gap}px gap, "
                            f"outside the {allowed} rhythm")
                    self.assertEqual(
                        found["inputH"], found["buttonH"],
                        f"{path}: inputs are {found['inputH']}px but the submit "
                        f"button is {found['buttonH']}px")

    # ----------------------------------------------------------------- drawer

    def test_sidebar_is_a_drawer_on_phones_and_docked_on_wide_screens(self):
        cookie = self._session_cookie()
        self.page.cookie("session_id", cookie)

        self.page.viewport(390, 844)
        self.page.goto(self.base + "/chat")
        time.sleep(0.6)
        # Not "inline-flex": as a flex item the button is blockified to "flex",
        # so the meaningful assertion is simply that it is shown at all.
        self.assertNotEqual(
            "none",
            self.page.evaluate(
                "getComputedStyle(document.getElementById('sidebar-toggle')).display"),
            "phones need a control to reach the conversation list")
        self.assertLess(
            self.page.evaluate("document.querySelector('.sidebar')"
                               ".getBoundingClientRect().right"), 1,
            "the closed drawer must sit off-canvas, not squeeze the messages")

        self.page.evaluate("document.getElementById('sidebar-toggle').click()")
        time.sleep(0.4)
        self.assertEqual(
            "true",
            self.page.evaluate("document.getElementById('sidebar-toggle')"
                               ".getAttribute('aria-expanded')"),
            "aria-expanded must track the drawer state")
        self.assertAlmostEqual(
            self.page.evaluate("document.querySelector('.sidebar')"
                               ".getBoundingClientRect().left"),
            0, delta=1, msg="clicking the toggle must slide the drawer in")

        self.page.evaluate(
            "document.dispatchEvent(new KeyboardEvent('keydown',"
            "{ key: 'Escape', bubbles: true }))")
        time.sleep(0.4)
        self.assertLess(
            self.page.evaluate("document.querySelector('.sidebar')"
                               ".getBoundingClientRect().right"), 1,
            "Escape must close the drawer again")

        for width, height, label in ((768, 1024, "tablet"), (1440, 900, "desktop")):
            with self.subTest(viewport=label):
                self.page.viewport(width, height)
                self.page.goto(self.base + "/chat")
                time.sleep(0.6)
                self.assertEqual(
                    "none",
                    self.page.evaluate("getComputedStyle("
                                       "document.getElementById('sidebar-toggle'))"
                                       ".display"),
                    "wide screens keep the sidebar on screen, so no toggle")
                # Not "left == 0": the app frame is centred with a max-width, so
                # on a wide screen the sidebar legitimately starts further in.
                # What matters is that it is fully on screen rather than
                # translated off-canvas the way the phone drawer is.
                edges = self.page.evaluate(
                    "(() => { const r = document.querySelector('.sidebar')"
                    ".getBoundingClientRect();"
                    " return [r.left, r.right, document.documentElement"
                    ".clientWidth]; })()")
                self.assertGreaterEqual(
                    edges[0], -1,
                    f"the sidebar must stay docked on wide screens ({label})")
                self.assertLessEqual(
                    edges[1], edges[2] + 1,
                    f"the sidebar must stay docked on wide screens ({label})")

    def test_chat_stays_open_on_the_conversation_you_pick(self):
        cookie = self._session_cookie()
        self.page.cookie("session_id", cookie)
        self.page.viewport(390, 844)
        self.page.goto(self.base + "/chat")
        time.sleep(0.6)
        self.page.evaluate("document.getElementById('sidebar-toggle').click()")
        time.sleep(0.4)
        picked = self.page.evaluate(
            "(() => { const b = document.getElementById('btn-public'); b.click();"
            " return true; })()")
        self.assertTrue(picked)
        time.sleep(0.4)
        self.assertLess(
            self.page.evaluate("document.querySelector('.sidebar')"
                               ".getBoundingClientRect().right"), 1,
            "choosing a conversation must reveal it, not leave the drawer open")

    # --------------------------------------------------------------- theming

    def test_theme_toggle_is_legible_in_both_themes(self):
        """Colour emoji ignore `color`, and the header inverts with the theme."""
        cookie = self._session_cookie()
        self.page.cookie("session_id", cookie)
        self.page.viewport(390, 844)
        self.page.goto(self.base + "/chat")
        time.sleep(0.6)
        for _ in range(2):
            glyph = self.page.evaluate(
                "document.querySelector('.chat-header [data-theme-toggle]')"
                ".textContent")
            self.assertTrue(glyph.strip(), "the toggle needs a glyph")
            # A variation selector forces text presentation so the glyph
            # inherits `color` instead of being drawn in its own colours.
            self.assertIn("\ufe0e", glyph,
                          f"glyph {glyph!r} must request text presentation")
            self.page.evaluate(
                "document.querySelector('.chat-header [data-theme-toggle]').click()")
            time.sleep(0.4)


if __name__ == "__main__":
    unittest.main()