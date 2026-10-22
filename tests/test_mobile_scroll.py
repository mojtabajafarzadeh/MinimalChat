"""On a phone, only the message list scrolls.

The whole frame moving under the reader's thumb is the bug this pins. The
header and the composer are fixed furniture; the messages scroll between
them.

Why it happened, measured rather than assumed: the body was sized to
`100vh`, which on a phone is the viewport with the browser's toolbars HIDDEN
-- taller than what the reader can see. The document was therefore taller
than the screen, and since nothing set `overflow: hidden` on the root, the
document itself became a scroll container. Dragging scrolled the document,
so the header and the composer went with it.

That exact unit difference cannot be reproduced in headless Chrome, where
`100vh` always equals `innerHeight` because there is no browser chrome. So
the test reproduces the condition by its EFFECT -- the body taller than the
viewport -- and checks the thing that actually matters: the document must not
be a scroll container, and the frame must not move when the page is dragged.

Requires a Chrome/Chromium binary plus the `websocket-client` module, so it
skips on a bare CI runner instead of reporting a pass it did not earn.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
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

from test_responsive_layout import (CdpSession, _find_chrome, _free_port,
                                    _wait_http)

STATIC = ROOT / "app" / "static"


class ScrollContractTests(unittest.TestCase):
    """The stylesheet, read as source. No server, no browser."""

    css = (STATIC / "style.css").read_text(encoding="utf-8")

    def _rule(self, selector):
        """The declarations of one rule, by selector.

        Read from the source rather than from the computed style, so the
        assertion is about what the stylesheet says -- a computed style would
        depend on a browser being present, and this file's whole point is
        that the bug was invisible until a phone was involved.

        Comments are stripped first: this stylesheet explains itself at
        length, and a rule that only exists inside a comment would otherwise
        read as present.
        """
        css = re.sub(r"/\*.*?\*/", "", self.css, flags=re.S)
        out = []
        for m in re.finditer(r"([^{}]+)\{([^{}]*)\}", css):
            selectors = [s.strip() for s in m.group(1).split(",")]
            if selector in selectors:
                out.append(m.group(2))
        return "\n".join(out)

    def test_the_root_is_pinned_to_the_viewport(self):
        """`html` had no rule at all, so the document was the scroll container.

        It needs a height that is the viewport, `overflow: hidden` so the
        document cannot scroll, and `overscroll-behavior: none` so a drag
        that runs out of content does not pull the page.
        """
        rule = self._rule("html")
        self.assertNotEqual("", rule, "html has no rule, so the document is "
                                        "the scroll container")
        self.assertIn("overflow: hidden", rule,
                      "the document can scroll, so the whole frame moves")
        self.assertIn("overscroll-behavior: none", rule,
                      "a drag that runs out of content pulls the page")
        self.assertRegex(rule, r"height:\s*100%",
                         "the root has no height, so 100% of it is not the "
                         "viewport")

    def test_the_body_is_not_sized_by_a_viewport_unit(self):
        """`min-height: 100vh` was the bug.

        100vh is the viewport with the toolbars hidden -- taller than the
        screen on a phone. The body has to be the height of the root, which
        is the visible viewport.
        """
        rule = self._rule("body")
        self.assertNotIn("100vh", rule,
                         "the body is sized by 100vh, which on a phone is "
                         "taller than the visible area; that is what made the "
                         "document scrollable")
        self.assertIn("overflow: hidden", rule,
                      "the body can scroll independently of the root")

    def test_the_header_and_the_composer_do_not_shrink(self):
        """Fixed furniture. Without this, a long conversation squeezes the
        header and the composer instead of the list growing."""
        for selector in (".chat-header", ".composer"):
            with self.subTest(selector=selector):
                self.assertIn("flex-shrink: 0", self._rule(selector),
                              f"{selector} can be squeezed by flex shrinking")

    def test_the_message_list_is_the_only_scroll_container(self):
        """`overscroll-behavior: contain` on the list is what stops a drag
        that reaches the end of the messages from handing the gesture to the
        document -- which is what produced the rubber-band that dragged the
        whole page down."""
        self.assertIn("overscroll-behavior: contain", self._rule("#messages"),
                      "the message list hands the gesture on to the document")
        self.assertIn("overflow-y: auto", self._rule("#messages"),
                      "the message list is not a scroll container")

    def test_the_auth_pages_scroll_inside_their_own_box(self):
        """The root is now pinned, so a card taller than the screen has to be
        reachable some other way: the box that centres it scrolls."""
        rule = self._rule(".center")
        self.assertIn("overflow-y: auto", rule,
                      "a tall login form is now unreachable, because the "
                      "root no longer scrolls")

    def test_ios_does_not_zoom_into_the_inputs(self):
        """iOS zooms into any text input whose computed font-size is under
        16px when it gains focus. A PWA that zooms on every tap is broken in
        the truest sense: the whole app magnifies because of one field.

        The threshold is a hard Apple rule, so the guard checks the actual
        declared size. The inputs were 0.875rem (14px) and the fingerprint
        field 0.75rem (12px) -- both under it."""
        problems = []
        for m in re.finditer(
                r"([^{}]*input[^{}]*|[^{}]*textarea[^{}]*)\{([^{}]*)\}", self.css):
            selector = " ".join(m.group(1).split())
            font = re.search(r"font-size:\s*([^;]+)", m.group(2))
            if not font:
                continue
            size = font.group(1).strip()
            px = None
            if size.endswith("px"):
                px = float(size[:-2])
            elif size.endswith("rem"):
                px = float(size[:-3]) * 16
            if px is not None and px < 16:
                problems.append(f"{selector}: {size} ({px:.0f}px)")
        self.assertEqual([], problems,
                         "inputs under 16px make iOS zoom on tap: "
                         + "; ".join(problems))


@unittest.skipUnless(HAVE_WEBSOCKET, "needs the websocket-client module")
@unittest.skipIf(_find_chrome() is None, "needs a Chrome/Chromium binary")
class MobileScrollTests(unittest.TestCase):
    """A real browser, a real phone-sized viewport."""

    @classmethod
    def setUpClass(cls):
        cls.data_dir = tempfile.mkdtemp(prefix="chat-scroll-")
        cls.profile = tempfile.mkdtemp(prefix="chrome-scroll-")
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
        cls.cookie = cls._sign_in()

    @classmethod
    def _sign_in(cls):
        """A session cookie, so /chat renders instead of redirecting.

        The bug was reported on the chat page -- the one with a header, a
        message list and a composer -- so the tests have to look at that page
        and not at the login form.
        """
        import http.cookiejar
        import urllib.parse

        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(jar))
        opener.open(urllib.request.Request(
            cls.base + "/api/register",
            data=urllib.parse.urlencode({
                "name": "Scroll", "username": "scroller",
                "password": "scroll-pw", "confirm": "scroll-pw"}).encode()),
            timeout=15).read()
        opener.open(urllib.request.Request(
            cls.base + "/api/login",
            data=urllib.parse.urlencode({
                "username": "scroller", "password": "scroll-pw"}).encode()),
            timeout=15).read()
        for cookie in jar:
            if cookie.name == "session_id":
                return cookie.value
        raise unittest.SkipTest("no session cookie")

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

    def setUp(self):
        self.page = self._open_page()
        self.page.send("Emulation.setDeviceMetricsOverride", width=390,
                       height=844, deviceScaleFactor=3, mobile=True)
        self.page.send("Network.setCookie", name="session_id",
                       value=self.cookie, domain="127.0.0.1", path="/")

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
        return session

    def _state(self):
        return self.page.evaluate("""(() => {
          const de = document.documentElement;
          const l = document.getElementById('messages');
          const hdr = document.querySelector('.chat-header');
          const comp = document.querySelector('.composer');
          return {
            docScrollable: de.scrollHeight > de.clientHeight,
            gap: de.scrollHeight - de.clientHeight,
            headerTop: hdr ? hdr.getBoundingClientRect().top : null,
            composerTop: comp ? comp.getBoundingClientRect().top : null,
            listScrollable: l ? l.scrollHeight > l.clientHeight : false,
            scrollY: window.scrollY,
          };
        })()""")

    def test_the_document_never_becomes_a_scroll_container(self):
        """Even when the body is taller than the viewport -- the effect the
        phone's `100vh` produced -- the document must not scroll.

        A real element is used rather than a stylesheet override, so the
        stylesheet under test is the one being judged.
        """
        self.page.goto(self.base + "/chat")
        time.sleep(1.0)
        self.page.evaluate("""(() => {
          const d = document.createElement('div');
          d.id = 'tall';
          d.style.cssText = 'height:150px';
          document.body.appendChild(d);
          return 1;
        })()""")
        time.sleep(0.4)
        found = self._state()
        self.assertFalse(found["docScrollable"],
                         f"the document scrolls by {found['gap']}px, so the "
                         "header and the composer move with the drag")

    def test_the_frame_does_not_move_when_the_page_is_dragged(self):
        """The header and the composer keep their position; only the list
        scrolls."""
        self.page.goto(self.base + "/chat")
        time.sleep(1.0)
        # something to scroll
        self.page.evaluate("""(() => {
          const l = document.getElementById('messages');
          if (!l) return 0;
          for (let i = 0; i < 40; i++) {
            const d = document.createElement('div');
            d.className = 'msg';
            d.textContent = 'line ' + i;
            l.appendChild(d);
          }
          return 1;
        })()""")
        time.sleep(0.4)
        before = self._state()
        self.page.evaluate("window.scrollTo(0, 80); 'scrolled'")
        time.sleep(0.4)
        after = self._state()
        self.assertEqual(0, after["scrollY"],
                         "the document scrolled, so the whole frame moves")
        self.assertEqual(before["headerTop"], after["headerTop"],
                         "the header moved")
        self.assertEqual(before["composerTop"], after["composerTop"],
                         "the composer moved")

    def test_the_message_list_is_the_one_that_scrolls(self):
        """And it does scroll: a long conversation has to be readable."""
        self.page.goto(self.base + "/chat")
        time.sleep(1.0)
        self.page.evaluate("""(() => {
          const l = document.getElementById('messages');
          if (!l) return 0;
          for (let i = 0; i < 40; i++) {
            const d = document.createElement('div');
            d.className = 'msg';
            d.textContent = 'line ' + i;
            l.appendChild(d);
          }
          l.scrollTop = 120;
          return l.scrollTop;
        })()""")
        time.sleep(0.4)
        found = self._state()
        self.assertTrue(found["listScrollable"],
                        "the message list cannot scroll, so a long "
                        "conversation is unreachable")


if __name__ == "__main__":
    unittest.main()
