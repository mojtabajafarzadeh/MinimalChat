"""Admin brute-force backoff (A-04) and password-strength reporting (I-03).

One credential guards every user and message in the database, and the sliding
window on admin_login only bounds the RATE of attempts -- an attacker who
spends them slowly gets an unbounded number of guesses, which is what makes
an online dictionary attack practical. The backoff below the window is what
bounds the total.

The two properties that matter, and that the tests below pin:

- the delay grows without bound (up to a cap) as failures accumulate, so a
  scripted run slows to nothing;
- the first few mistakes are FREE, because an operator who fat-fingers their
  own password must not be locked out of their own server. That is why the
  curve has a grace period, and it is the reason this is not simply
  "failures * step".
"""
import shutil
import sys
import time
import unittest
import unittest.mock
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app import admin, security

# (step, grace, maximum, half_life)
STRICT = (1.0, 5.0, 120.0, 300.0)
OFF = (0.0, 5.0, 120.0, 300.0)
NO_GRACE = (1.0, 0.0, 120.0, 300.0)


class BackoffBase(unittest.TestCase):
    def setUp(self):
        security.clear_admin_state()
        security.configure_admin_lockout(*STRICT)
        self.addCleanup(security.clear_admin_state)
        self.addCleanup(security.configure_admin_lockout, *STRICT)


class DelayCurveTests(BackoffBase):
    def test_no_failures_means_no_delay(self):
        self.assertEqual(security.admin_delay(0), 0.0)

    def test_the_first_few_mistakes_are_free(self):
        """A human typo must not produce a 429."""
        for fails in range(0, 6):
            with self.subTest(fails=fails):
                self.assertEqual(security.admin_delay(fails), 0.0,
                                 "an operator who mistypes is being locked out")

    def test_the_delay_grows_after_the_grace_period(self):
        delays = [security.admin_delay(f) for f in (6, 7, 8, 9, 10)]
        for earlier, later in zip(delays, delays[1:]):
            self.assertLess(earlier, later,
                            "the curve is flat, so the total is still unbounded")

    def test_the_curve_is_exponential_not_linear(self):
        """The property that actually bounds the total. With a linear curve an
        attacker pays a constant price per guess and simply guesses more."""
        self.assertGreater(security.admin_delay(20), 10 * security.admin_delay(6))

    def test_the_delay_is_capped(self):
        """An unbounded delay becomes an absurd Retry-After, and a lockout
        nobody can explain."""
        cap = STRICT[2]
        self.assertLessEqual(security.admin_delay(10 ** 9), cap)
        self.assertEqual(security.admin_delay(10 ** 9), cap)

    def test_a_huge_tally_does_not_overflow(self):
        """2 ** a huge exponent is an overflow waiting to happen; the exponent
        is clamped before it is used."""
        self.assertEqual(security.admin_delay(10 ** 300), STRICT[2])

    def test_zero_step_disables_the_backoff(self):
        """The documented escape hatch: window only."""
        security.configure_admin_lockout(*OFF)
        self.assertEqual(security.admin_delay(50), 0.0)

    def test_a_zero_grace_makes_every_failure_cost(self):
        security.configure_admin_lockout(*NO_GRACE)
        self.assertEqual(security.admin_delay(0), 0.0)
        self.assertEqual(security.admin_delay(3), 8.0)   # step * 2**3


class TallyTests(BackoffBase):
    def test_a_failure_is_recorded(self):
        security.register_admin_failure("k", now=100.0)
        self.assertAlmostEqual(security.admin_failures("k", now=100.0), 1.0)

    def test_failures_accumulate(self):
        for _ in range(4):
            security.register_admin_failure("k", now=100.0)
        self.assertAlmostEqual(security.admin_failures("k", now=100.0), 4.0)

    def test_tallies_are_per_key(self):
        security.register_admin_failure("a", now=100.0)
        self.assertEqual(security.admin_failures("b", now=100.0), 0.0)

    def test_the_tally_decays_so_nobody_is_locked_out(self):
        """An operator who walks away and comes back must get in."""
        for _ in range(12):
            security.register_admin_failure("k", now=100.0)
        self.assertGreater(security.admin_failures("k", now=100.0), 5.0)
        # One half-life later the tally is worth half as much.
        later = security.admin_failures("k", now=100.0 + STRICT[3])
        self.assertAlmostEqual(later, 6.0)
        # And it keeps fading: eight half-lives is under one failure, i.e. the
        # account is treated as never having been attacked.
        self.assertLess(security.admin_failures("k", now=100.0 + STRICT[3] * 8),
                        1.0)

    def test_a_correct_password_clears_the_tally(self):
        for _ in range(9):
            security.register_admin_failure("k", now=100.0)
        self.assertGreater(security.admin_failures("k", now=100.0), 0.0)
        security.clear_admin_failures("k")
        self.assertEqual(security.admin_failures("k", now=100.0), 0.0)
        self.assertEqual(security.admin_delay(0), 0.0)

    def test_a_clock_going_backwards_does_not_inflate_the_tally(self):
        """_decayed uses (now - last); a negative elapsed time would raise
        0.5 ** negative to a LARGER number and manufacture free failures that
        then decay into a real delay."""
        security.register_admin_failure("k", now=1000.0)
        self.assertLessEqual(security.admin_failures("k", now=900.0), 1.0,
                             "a backwards clock inflated the tally")


class PasswordStrengthTests(unittest.TestCase):
    """I-03: a weak configured password is reported, not accepted silently."""

    @staticmethod
    def _strength(password):
        with unittest.mock.patch.object(admin, "ADMIN_PASSWORD", password):
            return admin.password_strength()

    def test_a_long_mixed_password_passes(self):
        self.assertIsNone(self._strength("correct-horse-battery-1"))

    def test_a_short_password_is_reported(self):
        with self.subTest(password="abc"):
            self.assertIn("at least", self._strength("abc"))

    def test_a_long_single_class_password_is_reported(self):
        for password in ("abcdefghijklmnop", "1234567890123456"):
            with self.subTest(password=password):
                self.assertIsNotNone(self._strength(password))

    def test_long_enough_letters_plus_a_separator_passes(self):
        self.assertIsNone(self._strength("abcdefghijkl-mnop"))

    def test_no_configured_password_is_not_a_weakness(self):
        """The panel is simply off; that is a choice, not a finding."""
        self.assertIsNone(self._strength(""))

    def test_a_single_character_is_reported(self):
        self.assertIsNotNone(self._strength("x"))


class RouteBehaviourTests(BackoffBase):
    """The route itself, against a real server on a real socket.

    Deliberately NOT TestClient. That needs `httpx2`, which is not in
    requirements.txt, so on CI the import raised RuntimeError inside
    setUpClass and failed the whole suite. A stdlib-only client on a live
    subprocess is what every other test in this directory already does, and
    it also exercises the real middleware stack -- which matters here, since
    the backoff decision is made in the route, not in a middleware.
    """

    WINDOW_LIMIT = 1000

    @classmethod
    def setUpClass(cls):
        import os
        import subprocess
        import tempfile

        from test_responsive_layout import _free_port, _wait_http

        cls.data_dir = tempfile.mkdtemp(prefix="chat-lockout-")
        cls.port = _free_port()
        cls.base = f"http://127.0.0.1:{cls.port}"
        cls.server = subprocess.Popen(
            [sys.executable, str(ROOT / "run.py")], cwd=str(ROOT),
            env=dict(os.environ, PORT=str(cls.port),
                     CHAT_DATA_DIR=cls.data_dir, ENC_ENABLED="false",
                     REGISTRATION_ENABLED="true",
                     ADMIN_PASSWORD="a-long-admin-passphrase",
                     ADMIN_PATH="/admin",
                     RATE_ADMIN_LOGIN_PER_MIN=str(cls.WINDOW_LIMIT)),
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
            except Exception:
                proc.kill()
        path = getattr(cls, "data_dir", None)
        if path:
            shutil.rmtree(path, ignore_errors=True)

    @classmethod
    def tearDownClass(cls):
        cls._teardown()

    def setUp(self):
        super().setUp()
        # The sliding window lives in module-global state that outlives the
        # backoff, so it has to be reset explicitly or one test's burst
        # becomes the next test's first failure.
        security._hits.clear()

    def _login(self, password):
        """POST the panel login; returns (status_code, body, headers)."""
        import urllib.error
        import urllib.parse
        import urllib.request

        data = urllib.parse.urlencode({"password": password}).encode()
        req = urllib.request.Request(self.base + "/admin/api/login", data=data,
                                     method="POST")
        req.add_header("Content-Type",
                       "application/x-www-form-urlencoded")
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return r.status, r.read().decode(), r.headers
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(), e.headers

    def _status(self, password):
        return self._login(password)[0]

    def _error(self, password):
        import json

        status, body, _ = self._login(password)
        try:
            return json.loads(body).get("error", "")
        except ValueError:
            return body

    def _locked_out(self):
        return self._status("a-long-admin-passphrase") == 429

    def test_a_wrong_password_is_401_before_the_grace_period(self):
        for i in range(5):
            with self.subTest(attempt=i):
                self.assertEqual(self._status("wrong"), 401)

    def test_past_the_grace_period_it_is_429_with_retry_after(self):
        for _ in range(6):
            self._login("wrong")
        status, _, headers = self._login("wrong")
        self.assertEqual(status, 429)
        retry = int(headers["Retry-After"])
        self.assertGreaterEqual(retry, 1)
        self.assertLessEqual(retry, int(STRICT[2]))

    def test_the_correct_password_is_refused_while_backing_off(self):
        for _ in range(6):
            self._login("wrong")
        self.assertEqual(self._status("a-long-admin-passphrase"), 429)

    def test_waiting_it_out_lets_the_operator_back_in(self):
        """The escape hatch must exist, or this is a self-inflicted lockout.

        The tally decays with a 300s half-life, so a live server cannot be
        waited out inside a unit test. The decay itself is asserted as its own
        property in TallyTests; what is pinned here is the rule the route
        applies to a decayed value -- anything at or under the grace period is
        served normally -- by running the server with a tiny half-life, so the
        wait is a fraction of a second instead of five minutes."""
        import os
        import subprocess
        import tempfile

        from test_responsive_layout import _free_port, _wait_http

        data_dir = tempfile.mkdtemp(prefix="chat-lockout-decay-")
        port = _free_port()
        base = f"http://127.0.0.1:{port}"
        # Half-life 10s is the config floor; grace 5 means the tally has to fall
        # by more than half before the route stops refusing, so ~11s of
        # sleeping. Long enough to be real, short enough to be a test.
        proc = subprocess.Popen(
            [sys.executable, str(ROOT / "run.py")], cwd=str(ROOT),
            env=dict(os.environ, PORT=str(port), CHAT_DATA_DIR=data_dir,
                     ENC_ENABLED="false", REGISTRATION_ENABLED="true",
                     ADMIN_PASSWORD="a-long-admin-passphrase",
                     ADMIN_LOCKOUT_HALF_LIFE="10",
                     RATE_ADMIN_LOGIN_PER_MIN="1000"),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            if not _wait_http(base + "/login"):
                self.skipTest("the app did not start")
            import urllib.error
            import urllib.parse
            import urllib.request

            def attempt(password):
                data = urllib.parse.urlencode(
                    {"password": password}).encode()
                req = urllib.request.Request(base + "/admin/api/login",
                                             data=data, method="POST")
                try:
                    with urllib.request.urlopen(req, timeout=15) as r:
                        return r.status
                except urllib.error.HTTPError as e:
                    return e.code

            # grace is 5, so the first SIX failures are free and the seventh
            # is the first one refused.
            for i in range(6):
                self.assertEqual(attempt("wrong"), 401,
                                 f"failure {i + 1} of 6 should still be free")
            self.assertEqual(attempt("a-long-admin-passphrase"), 429,
                             "the backoff did not engage at all")

            # More than one half-life: the tally halves each time, so this is
            # the real escape hatch, not a reconfiguration.
            time.sleep(11)
            self.assertEqual(attempt("a-long-admin-passphrase"), 200,
                             "the operator was locked out permanently")
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except Exception:
                    proc.kill()
            shutil.rmtree(data_dir, ignore_errors=True)

    def test_a_correct_password_clears_the_tally(self):
        """Getting back in has to reset the slate, or the second mistake is
        punished as if the first had never been forgiven."""
        for _ in range(4):
            self._login("wrong")
        self.assertEqual(self._status("a-long-admin-passphrase"), 200)
        # If the success had not cleared the tally, the next few failures
        # would push straight past the 5-attempt grace.
        for i in range(5):
            with self.subTest(after_success=i):
                self.assertEqual(self._status("wrong"), 401,
                                 "the tally was not cleared by the success")

    def test_the_window_still_applies_when_the_backoff_is_off(self):
        """With ADMIN_LOCKOUT_STEP=0 the sliding window is the only guard, and
        it must still stop a fast run on its own. The server runs in a
        subprocess, so this drives the curve from a separate config instead of
        reconfiguring in-process state that the subprocess cannot see."""
        import os
        import shutil
        import subprocess
        import tempfile

        from test_responsive_layout import _free_port, _wait_http

        data_dir = tempfile.mkdtemp(prefix="chat-lockout-off-")
        port = _free_port()
        base = f"http://127.0.0.1:{port}"
        proc = subprocess.Popen(
            [sys.executable, str(ROOT / "run.py")], cwd=str(ROOT),
            env=dict(os.environ, PORT=str(port), CHAT_DATA_DIR=data_dir,
                     ENC_ENABLED="false", REGISTRATION_ENABLED="true",
                     ADMIN_PASSWORD="a-long-admin-passphrase",
                     ADMIN_LOCKOUT_STEP="0",
                     RATE_ADMIN_LOGIN_PER_MIN="5"),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            if not _wait_http(base + "/login"):
                self.skipTest("the app did not start")
            import urllib.error
            import urllib.parse
            import urllib.request

            codes = []
            for _ in range(8):
                data = urllib.parse.urlencode(
                    {"password": "wrong"}).encode()
                req = urllib.request.Request(base + "/admin/api/login",
                                             data=data, method="POST")
                try:
                    with urllib.request.urlopen(req, timeout=15) as r:
                        codes.append(r.status)
                except urllib.error.HTTPError as e:
                    codes.append(e.code)
            self.assertIn(429, codes,
                          "with the backoff off the sliding window must still "
                          f"stop a burst of 8 against a limit of 5; got {codes}")
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except Exception:
                    proc.kill()
            shutil.rmtree(data_dir, ignore_errors=True)

    def test_a_correct_password_from_a_clean_tally_is_accepted(self):
        """And the whole point: an operator who has not been attacking their
        own server gets in."""
        self.assertEqual(self._status("a-long-admin-passphrase"), 200)
        self.assertEqual(self._error("wrong"), "Invalid admin password.")


class LockoutConfigTests(unittest.TestCase):
    """The shipped curve, pinned in configuration.

    The unit tests above call configure_admin_lockout with their own values,
    so a change to the DEFAULTS in app/config.py would pass every one of them
    while making the product worse. This is the only thing standing between
    "a human typo locks the operator out" and a green suite -- it was written
    after that exact regression was injected and went unnoticed.
    """

    @staticmethod
    def _config(**env):
        from testsupport import settings_env

        with settings_env(**env):
            from app import config

            return config

    def test_the_default_curve_never_locks_out_a_typing_human(self):
        config = self._config()
        security.configure_admin_lockout(config.ADMIN_LOCKOUT_STEP,
                                         config.ADMIN_LOCKOUT_GRACE,
                                         config.ADMIN_LOCKOUT_MAX,
                                         config.ADMIN_LOCKOUT_HALF_LIFE)
        try:
            for fails in (1, 2, 3, 4, 5):
                with self.subTest(fails=fails):
                    self.assertEqual(
                        security.admin_delay(fails), 0.0,
                        f"the {fails}th mistake costs "
                        f"{security.admin_delay(fails)}s; an operator who "
                        "fat-fingers their own password gets a 429")
        finally:
            security.configure_admin_lockout(*STRICT)

    def test_the_default_curve_stops_a_scripted_run(self):
        config = self._config()
        security.configure_admin_lockout(config.ADMIN_LOCKOUT_STEP,
                                         config.ADMIN_LOCKOUT_GRACE,
                                         config.ADMIN_LOCKOUT_MAX,
                                         config.ADMIN_LOCKOUT_HALF_LIFE)
        try:
            # 15 straight wrong guesses, no wait honoured: the whole run has to
            # cost an attacker well over a minute.
            total = sum(security.admin_delay(f) for f in range(1, 16))
            self.assertGreater(total, 300.0,
                               "a dictionary run is still cheap")
            self.assertGreaterEqual(security.admin_delay(15),
                                    config.ADMIN_LOCKOUT_MAX / 2,
                                    "the curve tops out too low to matter")
        finally:
            security.configure_admin_lockout(*STRICT)

    def test_the_defaults_are_clamped_to_something_sane(self):
        """A typo in .env must not produce an hour-long lockout or an
        unbounded one."""
        config = self._config(ADMIN_LOCKOUT_MAX="999999",
                              ADMIN_LOCKOUT_STEP="-5",
                              ADMIN_LOCKOUT_GRACE="-1")
        self.assertLessEqual(config.ADMIN_LOCKOUT_MAX, 3600.0)
        self.assertGreaterEqual(config.ADMIN_LOCKOUT_STEP, 0.0)
        self.assertGreaterEqual(config.ADMIN_LOCKOUT_GRACE, 0.0)

    def test_a_non_numeric_value_falls_back_to_the_default(self):
        config = self._config(ADMIN_LOCKOUT_MAX="forever")
        self.assertEqual(config.ADMIN_LOCKOUT_MAX, 120.0)


if __name__ == "__main__":
    unittest.main()
