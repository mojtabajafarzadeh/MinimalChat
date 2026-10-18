"""Desktop notifications and the tab's unread count.

Both are page-level features, so the only honest way to check them is a real
browser against a real WebSocket: the count is a number in a title string, and
the notification is an object the page creates and throws away.

Two findings shaped how these tests observe that, and both were measured
rather than assumed (Chrome 154 over CDP):

- The browser emits no observable event for a notification. `Notification.enable`
  plus a real `new Notification(...)` produced zero `Notification.*` events, and
  `navigator.getNotifications` does not exist outside a service worker
  registration. So a test cannot watch a firing happen -- it has to record the
  constructor call. `RECORDER` below replaces `window.Notification` before any
  page script runs and keeps what it was handed.

- Permission is auto-denied in headless Chrome, so `requestPermission()` can
  never succeed there. `Browser.grantPermissions` grants it for one origin
  before navigation, which is how the granted case is reached at all.

The privacy property is checked structurally instead. A notification is drawn
by the OS on the lock screen and its history can sync between a user's
devices, so the text must stay generic -- no preview, no sender name. The tag
is what carries the conversation, and the tag is never displayed.

No service worker and no push: the channel keys live in sessionStorage, which a
service worker cannot read, so background delivery would mean moving message
bodies or a plaintext count out of the page. `NoBackgroundDeliveryTests` keeps
that ceiling pinned rather than leaving it to a comment.

Requires a Chrome/Chromium binary plus `websocket-client` and `websockets`,
so it skips on a bare CI runner instead of reporting a pass it did not earn.
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

try:
    from websockets.sync.client import connect as ws_connect

    HAVE_WEBSOCKETS = True
except ImportError:  # pragma: no cover - exercised on bare runners
    HAVE_WEBSOCKETS = False

from test_responsive_layout import CdpSession, _find_chrome, _free_port, _wait_http

# Replaces window.Notification before the page loads and records every call.
# Same-origin and installed through the protocol rather than a <script> tag,
# because `script-src 'self'` forbids the latter -- which is the very property
# that makes the recorder's job necessary.
RECORDER = """
(() => {
  const calls = [];
  window.__notif = {calls: calls, constructed: []};
  const Real = window.Notification;
  const permission = Real ? Real.permission : 'default';
  function Fake(title, opts) {
    calls.push({title: String(title), tag: (opts && opts.tag) || null,
                body: (opts && opts.body) || null, icon: (opts && opts.icon) || null});
    if (opts && opts.onclick) { this.onclick = opts.onclick; }
    window.__notif.constructed.push(this);
  }
  Fake.permission = permission;
  Fake.requestPermission = function () { return Promise.resolve(permission); };
  window.Notification = Fake;
})();
"""

# Everything the feature is allowed to show a user, in one read: the tab title,
# the bell's state, and the record of every notification raised.
STATE = """
(() => {
  const b = document.getElementById('notif-toggle');
  // Geometry, not `b.hidden`. The element is hidden through a class that is
  // `display:none !important`, so the property can read false while the button
  // is zero-width on screen; only the box tells the truth.
  const r = b ? b.getBoundingClientRect() : null;
  const cs = b ? getComputedStyle(b) : null;
  return {
    title: document.title,
    bellHidden: b ? b.hidden : null,
    bellDisplay: cs ? cs.display : null,
    bellWidth: r ? r.width : null,
    // What a user could actually click.
    bellHittable: !!(r && r.width > 0 && r.height > 0 && cs.display !== 'none'),
    bellPressed: b ? b.getAttribute('aria-pressed') : null,
    bellLabel: b ? b.getAttribute('aria-label') : null,
    bellGlyph: b ? b.textContent : null,
    notificationSupport: 'Notification' in window,
    calls: (window.__notif && window.__notif.calls) || [],
    permission: window.Notification ? window.Notification.permission : null,
    visible: document.visibilityState,
  };
})()
"""


@unittest.skipUnless(HAVE_WEBSOCKET, "needs the websocket-client module")
@unittest.skipUnless(HAVE_WEBSOCKETS, "needs the websockets module")
@unittest.skipIf(_find_chrome() is None, "needs a Chrome/Chromium binary")
class NotificationTests(unittest.TestCase):
    """Two real accounts, one real browser, one real socket between them."""

    alice = "alice" + os.urandom(3).hex()
    bob = "bob" + os.urandom(3).hex()
    # A third account nobody else touches. The tests share one database, so a
    # sender used elsewhere would already have a row by the time this runs --
    # and it is the only way to make a DM unread while a DM is on screen.
    carol = "carol" + os.urandom(3).hex()

    @classmethod
    def setUpClass(cls):
        cls.data_dir = tempfile.mkdtemp(prefix="chat-notif-")
        cls.profile = tempfile.mkdtemp(prefix="chrome-notif-")
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
        for username in (cls.alice, cls.bob, cls.carol):
            cls._post("/api/register", {"name": username.capitalize(),
                                       "username": username,
                                       "password": "notif-pw",
                                       "confirm": "notif-pw"})

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
                                         "password": "notif-pw"}).encode()),
            timeout=15).read()
        for cookie in jar:
            if cookie.name == "session_id":
                return cookie.value
        raise unittest.SkipTest(f"no session cookie for {username}")

    # ------------------------------------------------------------------ setup

    def setUp(self):
        # A fresh browser target per test, and closed again in tearDown. The
        # shared target is reused across the class in test_unread_badges.py,
        # which is fine there because no test changes browser-level state. A
        # notification grant is browser-level state: without a per-test target
        # a granted test would hand its grant to the next one, and a test that
        # freezes the page would freeze every test after it.
        self.page = self._open_page(grant=True)
        self.rival = self._new_target("about:blank")
        self.addCleanup(self._close_target, self.rival["id"])
        self.addCleanup(self._close_target, self.page.targetId)
        self.page.send("Emulation.setDeviceMetricsOverride", width=1280,
                       height=800, deviceScaleFactor=1, mobile=False)
        # Log in through the real form and let the browser keep the cookie.
        # Doing it over urllib per test would be a POST to /api/login from one
        # IP for every test in the class, and RATE_LOGIN_PER_MIN is 20 -- which
        # the earlier shape of this file hit, with the resulting 429 surfacing
        # as a confusing failure three tests away from its cause. The cookie
        # lives in the shared browser profile, so the first test to need it
        # pays and the rest find themselves already logged in.
        self.page.goto(self.base + "/login")
        # The check and the fill share one evaluate, on purpose. Separated, they
        # race: login.js redirects to /chat the moment it finds a session, so a
        # `#username` that existed a moment ago is gone by the next round trip.
        self.page.evaluate(
            "(() => {"
            " const u = document.getElementById('username');"
            " if (!u) return 'already-logged-in';"
            " u.value = %r;"
            " document.getElementById('password').value = 'notif-pw';"
            " document.getElementById('form')"
            "   .dispatchEvent(new Event('submit', {cancelable: true}));"
            " return 'submitted';"
            "})()" % self.alice)
        deadline = time.time() + 20
        while time.time() < deadline:
            if self.page.evaluate("location.pathname") == "/chat":
                break
            time.sleep(0.25)
        # A new target is foregrounded when it is created, but closing the
        # previous test's tabs changes that afterwards -- and a page that starts
        # backgrounded would look like a tab the user is not watching, which is
        # exactly what several of these tests need it not to be.
        self.show()
        self.page.on_new_document(RECORDER)
        self.page.goto(self.base + "/chat")
        time.sleep(1.5)
        self.assertEqual("/chat", self.page.evaluate("location.pathname"),
                         "the login did not take, so /chat redirected")
        self.assertTrue(self.page.evaluate("window.__notif !== undefined"),
                        "the recorder was not installed; every assertion "
                        "below would be reading an empty list it never filled")

    def tearDown(self):
        try:
            self.page.ws.close()
        except Exception:
            pass

    def _new_target(self, url="about:blank", cdp_port=None):
        """Open a new browser target on `cdp_port`, or the class-wide browser.

        `PUT /json/new` is the only verb the endpoint accepts; a GET is
        answered 405. This build has no --remote-allow-origins problem
        because the WebSocket is opened with suppress_origin.
        """
        req = urllib.request.Request(
            f"http://127.0.0.1:{cdp_port or self.cdp_port}/json/new?{url}",
            method="PUT")
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read().decode("utf-8"))


    def _close_target(self, target_id, cdp_port=None):
        try:
            urllib.request.urlopen(urllib.request.Request(
                f"http://127.0.0.1:{cdp_port or self.cdp_port}"
                f"/json/close/{target_id}"), timeout=15).read()
        except Exception:
            pass

    def _activate(self, target_id):
        urllib.request.urlopen(urllib.request.Request(
            f"http://127.0.0.1:{self.cdp_port}/json/activate/{target_id}"),
            timeout=15).read()

    def _open_page(self, grant=False, cdp_port=None):
        target = self._new_target(cdp_port=cdp_port)
        ws = websocket.create_connection(target["webSocketDebuggerUrl"], timeout=30,
                                         suppress_origin=True)
        session = CdpSession(ws)
        session.ws.settimeout(30)
        session.targetId = target["id"]
        session.send("Page.enable")
        session.send("Runtime.enable")
        session.send("Network.enable")
        # The auth pages carry no cache headers, so Chrome would otherwise
        # reuse a previous run's HTML.
        session.send("Network.setCacheDisabled", cacheDisabled=True)
        if grant:
            # Headless Chrome denies notifications unless it is told not to.
            session.send("Browser.grantPermissions",
                         origin=self.base, permissions=["notifications"])
        return session

    def clear_permission_override(self):
        """Drop the setUp grant so a lower-priority setting can apply.

        `Browser.grantPermissions` installs a permission *override* for the
        origin, and an override wins over `Browser.setPermission`: asking for
        "prompt" while a grant exists still reads 'granted'. So the grant is
        cleared with an empty list first.
        """
        self.page.send("Browser.grantPermissions",
                       origin=self.base, permissions=[])

    def state(self):
        found = self.page.evaluate(STATE)
        # Which conversation is open decides what counts as unread, so carry
        # it with every reading: a failure that omits it cannot be told apart
        # from a fixture that never moved.
        found["view"] = self.page.evaluate(
            "document.getElementById('view-title').textContent")
        return found

    def calls(self):
        return self.state()["calls"]

    @staticmethod
    def _read(session):
        """Read the feature's state from any session, not just self.page.

        A few tests deliberately drive a second target, where "the page" is not
        the one setUp made.
        """
        out = session.evaluate(STATE)
        out["view"] = session.evaluate(
            "document.getElementById('view-title').textContent")
        return out

    def _sign_in(self, session, cdp_port=None):
        """Give a session a session cookie, the way setUp gives self.page one."""
        session.send("Emulation.setDeviceMetricsOverride", width=1280,
                     height=800, deviceScaleFactor=1, mobile=False)
        session.send("Network.setCookie", name="session_id",
                     value=self._session_cookie(self.alice),
                     domain="127.0.0.1", path="/")

    def _page_for_permission(self, setting):
        """A signed-in page whose notification permission reads back as
        `setting`, without disturbing the one self.page already has.

        The grant installed by setUp is cleared first, because
        `Browser.grantPermissions` is an *override* and overrides win:
        setting "prompt" underneath one still reads 'granted'.

        Preferred: a brand-new browser context, which has never answered this
        site's prompt. Chrome in this environment answers "Not allowed" to
        Target.createBrowserContext, so the fallback sets the state through the
        protocol -- on its own target either way, because the permission lives
        on the profile and a shared one leaks between tests.
        """
        self.clear_permission_override()
        context = None
        try:
            context = self.page.send("Target.createBrowserContext")
        except RuntimeError:
            pass
        if context:
            page = self._open_page(
                browser_context_id=context["browserContextId"])
            self.addCleanup(self._dispose_context, context["browserContextId"])
        else:
            page = self._open_page()
            self.addCleanup(self._close_target, page.targetId)
        self._sign_in(page)
        page.send("Browser.setPermission",
                  permission={"name": "notifications"}, setting=setting)
        page.on_new_document(RECORDER)
        page.goto(self.base + "/chat")
        time.sleep(1.5)
        return page

    def _dispose_context(self, context_id):
        try:
            self.page.send("Target.disposeBrowserContext",
                           browserContextId=context_id)
        except Exception:
            pass

    def sender(self, username):
        """One WebSocket per sending account, for the whole test.

        `MAX_SOCKETS_PER_IP` is 20 and everything here shares 127.0.0.1, so a
        socket per bob_says() call would run the class out of sockets partway
        through -- which is what happened before this cached them.
        """
        self._senders = getattr(self, "_senders", {})
        if username not in self._senders:
            jar = http.cookiejar.CookieJar()
            opener = urllib.request.build_opener(
                urllib.request.HTTPCookieProcessor(jar))
            opener.open(urllib.request.Request(
                self.base + "/api/login",
                data=urllib.parse.urlencode({"username": username,
                                             "password": "notif-pw"}).encode()),
                timeout=15).read()
            cookie = next(c.value for c in jar if c.name == "session_id")
            sock = ws_connect(f"ws://127.0.0.1:{self.port}/ws",
                              additional_headers={"Cookie": f"session_id={cookie}"},
                              open_timeout=20)
            self.addCleanup(sock.close)
            self._senders[username] = sock
        return self._senders[username]

    def setUpSender(self):
        self.sender(self.bob)

    def bob_says(self, frames, sender=None):
        """Push frames from another account over a real WebSocket.

        Each one is acknowledged by the server's own echo before the next goes
        out, so a caller never has to guess how long the write took.
        """
        sock = self.sender(sender or self.bob)
        for frame in frames:
            sock.send(json.dumps(frame))
            sock.recv(timeout=15)
        # Stored and echoed, but the browser still needs a tick to paint what
        # the frame causes.
        time.sleep(0.6)

    def open_dm_with_bob(self):
        """Go through the real DM form rather than poking the view directly."""
        self.page.evaluate(
            "(() => { const i = document.getElementById('dm-input');"
            " i.value = %r; document.getElementById('dm-form')"
            ".dispatchEvent(new Event('submit', {cancelable: true})); })()"
            % self.bob)
        time.sleep(1.2)

    def look_elsewhere(self):
        """Move the view to the DM with bob.

        "Unread" means "for a conversation that is not on screen", so which
        conversation is open decides what counts. With public open, a public
        message renders and is never counted; with the DM with bob open, a DM
        from bob renders and is never counted. The DM with bob is the one view
        in which a public message *and* a DM from anyone else are both unread,
        which is what the arrival tests need.
        """
        self.open_dm_with_bob()
        self.assertIn(self.bob, self.page.evaluate(
            "document.getElementById('view-title').textContent"),
            "the view did not move, so nothing would be off screen")

    def hide(self):
        """Background the tab the way the browser actually does.

        Measured, not assumed: `Page.setWebLifecycleState('frozen')` stops
        JavaScript entirely -- the WebSocket handler that would deliver the
        message never runs, and the freeze then persists on the target for
        every test that follows. Activating a second, foreground tab gets the
        same `document.visibilityState === 'hidden'` while the page keeps
        running, which is the state this feature is actually written for.
        """
        self._activate(self.rival["id"])
        deadline = time.time() + 15
        while time.time() < deadline:
            if self.page.evaluate("document.visibilityState") == "hidden":
                break
            time.sleep(0.2)
        else:
            raise unittest.SkipTest("this Chrome would not report the tab as hidden")

    def show(self):
        self._activate(self.page.targetId)
        deadline = time.time() + 15
        while time.time() < deadline:
            if self.page.evaluate("document.visibilityState") == "visible":
                return
            time.sleep(0.2)
        raise unittest.SkipTest(
            "this Chrome would not bring the tab to the foreground, so "
            "visible and hidden could not be told apart")

    # ------------------------------------------------------------------ tests

    def test_the_tab_title_counts_what_the_badges_count(self):
        """The count and the badges come from one place, so they cannot
        disagree -- but only if the title is repainted on both transitions.

        "Unread" is defined by what is on screen, not by what arrives: a
        message for the conversation you are reading is rendered, never
        counted. So the count here follows the same rule."""
        self.setUpSender()
        start = self.state()["title"]
        self.assertFalse(start.startswith("("),
                         f"a fresh page load starts with no unread, got {start!r}")

        # Public is on screen: counted as read, so no count.
        self.bob_says([{"type": "public", "content": "on screen"}])
        self.assertEqual(start, self.state()["title"],
                         "a message you can already see moved the unread count")

        # Move to the DM, so public is off screen.
        self.open_dm_with_bob()
        self.bob_says([{"type": "public", "content": "one"}])
        self.assertTrue(self.state()["title"].startswith("(1)"),
                        f"expected a count in the title, got {self.state()['title']!r}")
        self.bob_says([{"type": "public", "content": "two"},
                       {"type": "public", "content": "three"}])
        self.assertTrue(self.state()["title"].startswith("(3)"),
                        f"counts must accumulate, got {self.state()['title']!r}")

        # Reading the conversation clears it.
        self.page.evaluate("document.getElementById('btn-public').click()")
        time.sleep(0.8)
        self.assertEqual(start, self.state()["title"],
                         "the count survived opening the conversation it counted")

    def test_the_count_covers_dm_and_public_messages_together(self):
        """Both conversation kinds feed the same total, so a title that only
        watched one of them would under-report. One DM from a third party plus
        two public messages, all of them off screen at once."""
        self.setUpSender()
        self.look_elsewhere()
        self.bob_says([{"type": "public", "content": "p1"},
                       {"type": "public", "content": "p2"}])
        self.bob_says([{"type": "dm", "to": self.alice, "content": "d1"}],
                      sender=self.carol)
        title = self.state()["title"]
        self.assertTrue(title.startswith("(3)"),
                        f"expected three unread in total, got {title!r}")

    def test_a_reload_starts_the_count_from_zero(self):
        """Nothing about the count is persisted, and that is the design: it
        answers "did something arrive while I was looking elsewhere", which is
        a question about this page load."""
        self.setUpSender()
        self.look_elsewhere()
        self.bob_says([{"type": "public", "content": "before reload"}])
        self.assertTrue(self.state()["title"].startswith("(1)"),
                        f"the message was not counted, so the reload proves "
                        f"nothing; title was {self.state()['title']!r}")

        self.page.goto(self.base + "/chat")
        time.sleep(1.5)
        self.assertFalse(self.state()["title"].startswith("("),
                         "the count outlived the page load it belongs to")

    def test_a_background_tab_is_notified_and_a_visible_one_is_not(self):
        """The distinction the feature exists for: a toast over a conversation
        you are already reading is noise, and the badge has already answered
        the "did something arrive" question."""
        self.setUpSender()
        found = self.state()
        self.assertEqual("granted", found["permission"],
                         "the grant did not take; this browser build may not "
                         "honour Browser.grantPermissions for this origin")
        self.assertEqual([], found["calls"])

        # Visible tab, off-screen conversation: counted, not announced.
        self.look_elsewhere()
        self.bob_says([{"type": "public", "content": "while watching"}])
        self.assertEqual([], self.calls(),
                         "a toast fired for a tab the user is looking at")
        self.assertTrue(self.state()["title"].startswith("(1)"),
                        "the badge should still have counted it, and an empty "
                        "count here means the fixture, not the feature")

        # Hidden tab, same situation: announced.
        self.hide()
        self.bob_says([{"type": "public", "content": "while away"}])
        found = self.calls()
        self.assertEqual(1, len(found),
                         f"expected exactly one notification, got {found}")
        self.assertEqual("New message", found[0]["title"])

    def test_a_dm_and_a_public_message_are_told_apart_by_the_tag_only(self):
        """The text is generic for both, so the tag is the only thing telling
        them apart -- and the tag is what a click resolves. It must never
        reach anything the user can read."""
        self.setUpSender()
        self.look_elsewhere()
        self.hide()
        self.bob_says([{"type": "dm", "to": self.alice, "content": "secret text"}],
                      sender=self.carol)
        self.bob_says([{"type": "public", "content": "also secret"}])
        found = self.calls()
        self.assertEqual(2, len(found),
                         f"expected two notifications, got {found}; "
                         f"view was {self.state()['view']!r}, "
                         f"title {self.state()['title']!r}")
        tags = [c["tag"] for c in found]
        self.assertNotEqual(tags[0], tags[1],
                            "a DM and a public message produced the same tag, "
                            "so a click could not tell which conversation to open")

    def test_a_burst_in_one_conversation_replaces_its_own_notification(self):
        """Same tag, so the OS coalesces them. Three notifications for three
        messages in one conversation is the behaviour a tag exists to prevent."""
        self.setUpSender()
        self.look_elsewhere()
        self.hide()
        self.bob_says([{"type": "public", "content": f"burst{i}"}
                       for i in range(3)])
        found = self.calls()
        self.assertEqual(3, len(found),
                         f"expected three firings, got {found}")
        self.assertEqual(1, len(set(c["tag"] for c in found)),
                         f"one conversation produced several tags, so the "
                         f"notifications would stack: {[c['tag'] for c in found]}")

    def test_no_notification_ever_carries_message_text(self):
        """The property behind the generic wording: a notification is drawn by
        the OS on the lock screen and its history can sync between a user's
        devices. So neither the message body nor the sender's name may appear
        in one -- checked by sending text the recorder can search for, in
        every field a notification can carry, including the tag."""
        self.setUpSender()
        self.look_elsewhere()
        self.hide()
        marker = "zq-secret-" + os.urandom(3).hex()
        self.bob_says([{"type": "dm", "to": self.alice, "content": marker}],
                      sender=self.carol)
        self.bob_says([{"type": "public", "content": marker}])
        found = self.calls()
        self.assertTrue(found, "nothing was notified, so nothing was checked")
        blob = json.dumps(found)
        self.assertNotIn(marker, blob,
                         f"the message text reached a notification: {found}")
        for call in found:
            self.assertIsNone(call["body"],
                              f"a notification carried a body: {call}")
            self.assertIsNone(call["icon"],
                              f"a notification carried an icon: {call}")
        # And the other party. The tag is not rendered, but it is metadata that
        # some platforms retain and hand to companion apps.
        self.assertNotIn(self.bob, blob,
                         f"the sender's name reached a notification: {found}")

    def test_the_notification_opens_the_conversation_it_announced(self):
        """A tag that says which conversation but cannot act on it is
        decoration. The recorded objects keep their onclick, so the handler can
        be invoked the way the browser does."""
        self.setUpSender()
        self.look_elsewhere()
        self.hide()
        self.bob_says([{"type": "dm", "to": self.alice, "content": "open me"}],
                      sender=self.carol)
        found = self.calls()
        self.assertEqual(1, len(found), f"expected one notification, got {found}")
        self.assertTrue(self.page.evaluate(
            "(window.__notif.constructed[0] || {}).onclick instanceof Function"),
            "the notification has no click handler, so a click does nothing")

        self.page.evaluate("window.__notif.constructed[0].onclick()")
        time.sleep(1.2)
        title = self.page.evaluate(
            "document.getElementById('view-title').textContent")
        self.assertIn(self.carol, title,
                      f"the click did not open the DM it announced; view is {title!r}")
        # The message it announced is now read, so the count follows.
        self.assertFalse(self.state()["title"].startswith("("),
                         "opening the announced conversation did not clear its count")

    def test_a_message_in_the_open_conversation_never_notifies(self):
        """markUnread is only reached for what is off screen, but the guard has
        to hold on its own: a toast for the message you are reading right now
        would be the loudest possible wrong answer."""
        self.setUpSender()
        # Public is open on arrival, which is the page's default view.
        self.assertEqual("Public Chat", self.page.evaluate(
            "document.getElementById('view-title').textContent"),
            "the fixture did not open on the public room, so this would be "
            "testing the off-screen path")
        self.bob_says([{"type": "public", "content": "right here"}])
        self.assertEqual([], self.calls(),
                         "a message in the open conversation raised a notification")

    def test_the_bell_appears_only_once_a_permission_can_be_granted(self):
        """Headless Chrome denies notifications, so the granted state is what
        makes the bell appear. A bell that is visible but cannot do anything is
        a dead control."""
        found = self.state()
        self.assertEqual("granted", found["permission"])
        self.assertTrue(found["bellHittable"],
                        "with permission granted the bell must be clickable, "
                        f"but its box is {found['bellWidth']} wide with "
                        f"display:{found['bellDisplay']}")
        self.assertEqual("true", found["bellPressed"],
                         "a granted permission should leave the bell pressed")
        self.assertIn("Turn off", found["bellLabel"],
                      "the bell's name should describe what it does now")

    def test_the_bell_is_reachable_before_the_permission_is_answered(self):
        """The state a local user is in on a first visit: nothing granted,
        nothing asked -- and the case the bell exists for, since asking is the
        whole point of it.

        It is also the case that broke. The code cleared the `hidden` property
        while the class `hidden` stayed on the element, and that class is
        `display:none !important`, so the button sat in the DOM at zero width
        and could not be clicked -- on every deployment that does not already
        hold a grant, which is every first visit anywhere. The test that shipped
        checked `element.hidden`, which read false the whole time, so it
        passed.

        Hence the box rather than the property: only the geometry says whether
        a control can be clicked.

        This needs a browser that has never seen the site. The class-wide Chrome
        has already had its prompt answered -- by an earlier test clicking the
        bell -- so it reports 'denied', and hiding the bell there is correct
        behaviour, not the bug. Only a fresh profile reads 'default'.
        """
        cdp_port = self._fresh_browser()
        base = self.base
        session = self._open_page(cdp_port=cdp_port)
        self.addCleanup(self._close_target, session.targetId, cdp_port)
        self._sign_in(session, cdp_port=cdp_port)
        session.on_new_document(RECORDER)
        session.goto(base + "/chat")
        time.sleep(2.0)

        found = self._read(session)
        self.assertEqual("/chat", session.evaluate("location.pathname"),
                         "the fresh browser is not signed in, so /chat "
                         "redirected and none of this measured the chat page")
        self.assertEqual("default", found["permission"],
                         "a profile that has never seen the site reports the "
                         "prompt as unanswered, not as denied")
        self.assertTrue(found["bellHittable"],
                        "before the permission is answered the bell is the "
                        f"only way to ask for it, so it must be clickable; "
                        f"instead its box was {found['bellWidth']} wide with "
                        f"display:{found['bellDisplay']}")
        self.assertEqual("false", found["bellPressed"])
        self.assertIn("Turn on", found["bellLabel"],
                      "a bell with nothing granted should offer to turn them on")

        # Clicking is what a user does, and it is what asks the browser.
        self.assertEqual("clicked", session.evaluate(
            "document.getElementById('notif-toggle').click(); 'clicked'"))
        time.sleep(1.0)
        found = self._read(session)
        self.assertEqual("default", found["permission"],
                         "headless cannot show a prompt, so the click cannot "
                         "have resolved anything but the un-asked state")
        self.assertTrue(found["bellHittable"],
                        "an unanswered prompt must leave the bell clickable, "
                        f"not in a half state; its box was {found['bellWidth']} "
                        f"wide with display:{found['bellDisplay']}")

        # And it must survive a second load, which is the path that lost it.
        session.goto(base + "/chat")
        time.sleep(1.5)
        self.assertTrue(self._read(session)["bellHittable"],
                        "the bell lost its box on the second page load")

    def _fresh_browser(self):
        """A second Chrome, on its own profile, and its debugging port.

        One browser per class is the norm here, but a notification prompt is
        answered once per profile and never forgotten: by the time this test
        runs, the shared profile has a decision recorded and reports 'denied'.
        A new profile is the only way to see what a first-time user sees.
        """
        profile = tempfile.mkdtemp(prefix="chrome-firstvisit-")
        port = _free_port()
        proc = subprocess.Popen(
            [_find_chrome(), "--headless=new", "--no-sandbox", "--disable-gpu",
             "--disable-dev-shm-usage", f"--remote-debugging-port={port}",
             f"--user-data-dir={profile}", "about:blank"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        def stop():
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
            shutil.rmtree(profile, ignore_errors=True)

        self.addCleanup(stop)
        if not _wait_http(f"http://127.0.0.1:{port}/json/version"):
            self.skipTest("a second headless Chrome did not start")
        return port

    def test_no_bell_appears_where_notifications_are_impossible(self):
        """A browser without Notification at all: an old Firefox, an in-app
        webview, a locked-down build. There the only defensible bell is none,
        because every click would do nothing.

        Not reachable by configuration -- Chrome always ships Notification --
        so the global is removed for the one page load rather than skipping a
        case nobody can observe. It has to be a delete, not a redefinition:
        `Notification` is an accessor on Window and a value assigned over it
        is replaced by the browser before the page's own script runs, which is
        what a getter here produced.
        """
        self.setUpSender()
        fresh = self._page_for_permission("granted")
        try:
            fresh.on_new_document("delete window.Notification;")
            fresh.goto(self.base + "/chat")
            time.sleep(1.5)
            found = self._read(fresh)
            self.assertFalse(found["notificationSupport"],
                             "Notification is still defined, so this measured "
                             "the supported case again")
            self.assertEqual("/chat", fresh.evaluate("location.pathname"))
            self.assertFalse(found["bellHittable"],
                            "the bell is clickable in a browser that has no "
                            "notifications, so it offers a dead control")
        finally:
            # The override is installed for every later load; undo it so it
            # cannot leak into the rest of the class.
            fresh.send("Page.removeScriptToEvaluateOnNewDocument",
                       identifier="1")

    def test_the_bell_disappears_once_the_permission_is_denied(self):
        """Nothing left to ask for. A visible toggle the user cannot move is a
        control that lies about what it can do."""
        self.setUpSender()
        self.clear_permission_override()
        self.page.send("Browser.setPermission",
                       permission={"name": "notifications"}, setting="denied")
        self.page.goto(self.base + "/chat")
        time.sleep(1.5)

        found = self.state()
        self.assertEqual("denied", found["permission"])
        self.assertFalse(found["bellHittable"],
                        "the bell is still clickable after the permission was "
                        "denied, so it offers a choice that cannot be made")

    def test_the_bell_is_readable_against_the_header_in_both_themes(self):
        """Measured, not asserted.

        The header is near-black in *both* themes, so a control that takes
        --foreground disappears in one of them -- and nothing about that shows
        in the DOM: the button is present, sized and clickable, it just paints
        nothing. The audit in test_responsive_layout.py would have caught it,
        except that it skips display:none controls and the bell ships hidden.

        So the bell is revealed here and measured with that suite's own probe,
        rather than a second copy of the contrast arithmetic drifting from it.
        """
        from test_responsive_layout import ResponsiveLayoutTests

        self.page.evaluate(
            "(() => { const b = document.getElementById('notif-toggle');"
            " b.classList.remove('hidden');"
            " b.textContent = '\\uD83D\\uDD14';"
            " return b.textContent;"
            "})()")
        time.sleep(0.3)

        for theme in ("light", "dark"):
            if self.page.evaluate(
                    "document.documentElement.getAttribute('data-theme')") != theme:
                self.page.evaluate(
                    "document.querySelector('[data-theme-toggle]').click()")
                time.sleep(0.4)
            probe = self.page.evaluate(
                ResponsiveLayoutTests.HEADER_CONTRAST_PROBE)
            self.assertEqual(theme, probe["theme"])
            rows = {r["el"]: r for r in probe["rows"]}
            self.assertIn("notif-toggle", rows,
                          "the revealed bell stopped being measurable, so this "
                          "audit would pass without looking at it")
            row = rows["notif-toggle"]
            with self.subTest(theme=theme):
                self.assertGreaterEqual(
                    row["contrast"], ResponsiveLayoutTests.MIN_HEADER_CONTRAST,
                    f"the bell ({row['text']!r}) in {theme} mode: "
                    f"{row['color']} on {row['bg']} over the header is only "
                    f"{row['contrast']}:1, so it is effectively invisible")

    def test_clicking_the_bell_turns_notifications_off_and_back_on(self):
        """It is a toggle, so it has to come back off -- and the round trip is
        observable in the permission state the recorder holds."""
        self.setUpSender()
        self.page.evaluate("document.getElementById('notif-toggle').click()")
        time.sleep(0.5)
        found = self.state()
        self.assertEqual("false", found["bellPressed"],
                         "clicking a pressed bell left it pressed")
        self.assertIn("Turn on", found["bellLabel"])

        # Now with the preference off, an arrival must not notify.
        self.look_elsewhere()
        self.hide()
        self.bob_says([{"type": "public", "content": "quiet please"}])
        self.assertEqual([], self.calls(),
                         "a notification fired after the user turned them off")
        # But the count still moved: the badge needs no permission, so switching
        # notifications off must not cost the unread signal.
        self.assertTrue(self.state()["title"].startswith("(1)"),
                        "the unread count stopped working with notifications off")


class BellButtonTests(unittest.TestCase):
    """The bell is the only way to ask for notifications, so it has to appear
    only when asking is possible and has to report the state it is in.

    Markup only: these read the file, so they need neither a server nor a
    browser -- unlike the class above, which they were once folded into by an
    edit that lost a class statement.
    """

    chat_html = (ROOT / "app" / "static" / "chat.html").read_text(encoding="utf-8")

    def test_the_bell_is_in_the_markup_and_hidden_until_it_can_be_used(self):
        """Shipped `hidden`. A bell that is visible but does nothing -- because
        the browser has no Notification support, or has already denied it --
        invites a click that cannot lead anywhere."""
        tag = self._bell_tag()
        self.assertIsNotNone(tag, "there is no #notif-toggle in the chat page")
        classes = re.search(r'class="([^"]*)"', tag).group(1).split()
        self.assertIn("hidden", classes,
                      "the bell must ship hidden, not visible-until-fixed; it "
                      "does nothing until a browser can grant permission")

    @classmethod
    def _bell_tag(cls):
        """The whole start tag of the bell, or None.

        Attributes are matched inside the tag rather than by a fixed order, so
        reordering them in the markup cannot quietly turn these guards into
        tests of the wrong thing.
        """
        m = re.search(r'<button\b[^>]*\bid="notif-toggle"[^>]*>', cls.chat_html)
        return m.group(0) if m else None

    def test_the_bell_is_a_button_with_a_state_it_can_report(self):
        """A div with a click handler would be invisible to a keyboard and to a
        screen reader; aria-pressed is what makes it a toggle rather than an
        action."""
        tag = self._bell_tag()
        self.assertIsNotNone(tag, "the bell is gone from the markup")
        self.assertIn('type="button"', tag,
                      "without it the bell submits whatever form it sits in")
        self.assertIn('aria-pressed="false"', tag,
                      "aria-pressed is what makes this a toggle rather than an "
                      "action, and it has to start at the resting state")
        self.assertIn('aria-label="Turn on desktop notifications"', tag,
                      "the bell needs a name before it is pressed")


class NoBackgroundDeliveryTests(unittest.TestCase):
    """What this feature is not.

    Background delivery is the obvious next request, and the reason it is not
    implemented is specific rather than incidental: the channel keys live in
    sessionStorage, which a service worker cannot read. So any notification
    raised with the tab closed would have to carry either a message body or a
    plaintext count out of the page, and the server would then have to know when
    each user is away. These pin the ceiling so it is a decision that has to be
    undone on purpose rather than a gap nobody notices.
    """

    @staticmethod
    def _js(name):
        return (ROOT / "app" / "static" / name).read_text(encoding="utf-8")

    def test_no_script_registers_a_service_worker(self):
        for name in ("app.js", "api.js", "enc.js", "identity.js", "theme.js",
                     "login.js", "register.js", "admin.js"):
            with self.subTest(file=name):
                text = self._js(name)
                self.assertNotIn("serviceWorker", text,
                                 f"{name} registers a service worker; that "
                                 "changes what the notification feature is")
                self.assertNotIn("PushManager", text,
                                 f"{name} touches push; that changes what the "
                                 "notification feature is")

    def test_nothing_scripts_a_push_subscription(self):
        """The web-push call has to be spelled out, not grepped for as "push":
        the first version of this guard matched Array.prototype.push and
        api.js's `queued.push(...)`, so it failed on the whole app and would
        have kept failing after push was gone. A word-boundary search for the
        two APIs that can only mean push avoids matching ordinary arrays."""
        for js in sorted((ROOT / "app" / "static").glob("*.js")):
            text = js.read_text(encoding="utf-8")
            with self.subTest(file=js.name):
                self.assertIsNone(re.search(r"\.pushManager\b", text),
                                  f"{js.name} touches PushManager")
                self.assertIsNone(re.search(r"\.subscribe\s*\(", text),
                                  f"{js.name} subscribes to a push service")
                self.assertIsNone(re.search(r"'push'|\"push\"", text),
                                  f"{js.name} names the push event type")

    def test_the_notification_text_carries_no_sender_and_no_preview(self):
        """Structural, so it holds whatever the copy becomes later. The
        recorder's job is to observe firings; this is the rule that makes an
        observed firing acceptable."""
        text = self._js("app.js")
        start = text.find("function notifyIncoming")
        self.assertNotEqual(-1, start, "notifyIncoming() is gone; the "
                                         "notification path has moved or been "
                                         "renamed and this guard needs to follow")
        end = text.find("\n  function ", start + 10)
        body = text[start:end if end != -1 else len(text)]
        # m.username / m.content do not exist in this function at all, so a
        # future edit cannot leak them into the title without failing here.
        self.assertNotIn("m.content", body)
        self.assertNotIn(".content", body,
                         "the notification path reads message content")
        self.assertNotIn("username +", body,
                         "the notification text is built from a username")
        for literal in ("'@'", '"@"'):
            self.assertNotIn(literal + " +", body,
                             "the notification text is prefixed with a handle")
        self.assertIn("tag:", body,
                      "the conversation must still be identified somewhere")

    def test_the_title_badge_is_a_count_and_never_the_text(self):
        """document.title is visible in the tab strip, in the window manager's
        task list, and in some window-switcher previews -- so it gets a number
        too, never a message."""
        text = self._js("app.js")
        start = text.find("function paintTitle")
        self.assertNotEqual(-1, start, "paintTitle() is gone")
        end = text.find("\n  function ", start + 10)
        body = text[start:end if end != -1 else len(text)]
        self.assertIn("unreadTotal", body,
                      "the title should show the unread total")
        self.assertNotIn("content", body,
                         "the title badge reaches for message content")


if __name__ == "__main__":
    unittest.main()
