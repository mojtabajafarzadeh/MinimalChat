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
    """The route itself: the backoff is consulted, the window still applies,
    and the two cannot drift apart onto different keys."""

    WINDOW_LIMIT = 1000

    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient

        from testsupport import settings_env

        cls._env = settings_env(ENC_ENABLED="false", REGISTRATION_ENABLED="true",
                                ADMIN_PASSWORD="a-long-admin-passphrase",
                                ADMIN_PATH="/admin",
                                RATE_ADMIN_LOGIN_PER_MIN=str(cls.WINDOW_LIMIT))
        cls._env.__enter__()
        from app.main import app

        admin.apply_lockout_config()
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        cls._env.__exit__(None, None, None)

    def setUp(self):
        super().setUp()
        # The sliding window lives in module-global state that outlives the
        # backoff, so it has to be reset explicitly or one test's burst
        # becomes the next test's first failure.
        security._hits.clear()

    def _login(self, password):
        return self.client.post("/admin/api/login", data={"password": password})

    def _locked_out(self):
        return self._login("a-long-admin-passphrase").status_code == 429

    def test_a_wrong_password_is_401_before_the_grace_period(self):
        for i in range(5):
            with self.subTest(attempt=i):
                self.assertEqual(self._login("wrong").status_code, 401)

    def test_past_the_grace_period_it_is_429_with_retry_after(self):
        for _ in range(6):
            self._login("wrong")
        resp = self._login("wrong")
        self.assertEqual(resp.status_code, 429)
        retry = int(resp.headers["Retry-After"])
        self.assertGreaterEqual(retry, 1)
        self.assertLessEqual(retry, int(STRICT[2]))

    def test_the_correct_password_is_refused_while_backing_off(self):
        for _ in range(6):
            self._login("wrong")
        self.assertEqual(self._login("a-long-admin-passphrase").status_code, 429)

    def test_waiting_it_out_lets_the_operator_back_in(self):
        """The escape hatch must exist, or this is a self-inflicted lockout."""
        for _ in range(7):
            self._login("wrong")
        self.assertTrue(self._locked_out())
        # Age the tally past the grace instead of sleeping eight seconds.
        with security._lockouts_lock:
            key = next(iter(security._lockouts))
            fails, _ = security._lockouts[key]
            security._lockouts[key] = (fails * 0.01, time.monotonic())
        self.assertEqual(self._login("a-long-admin-passphrase").status_code, 200)

    def test_the_window_still_applies_when_the_backoff_is_off(self):
        """With ADMIN_LOCKOUT_STEP=0 the sliding window is the only guard, and
        it must still stop a fast run on its own."""
        security.configure_admin_lockout(*OFF)
        self.addCleanup(security.configure_admin_lockout, *STRICT)
        codes = [self._login("wrong").status_code
                 for _ in range(self.WINDOW_LIMIT + 2)]
        self.assertIn(429, codes,
                      "the sliding window stopped throttling; the backoff "
                      "cannot be the only guard")

    def test_the_two_limits_share_one_key(self):
        """Two keys would leave a source of unbounded attempts: the window
        would rate-limit key A while the backoff watched key B.

        The behavioural consequence: with the window spent, a caller that
        answers 429 from the WINDOW carries 'too many attempts' (a fixed
        Retry-After). With only the BACKOFF spent it carries 'too many failed
        attempts' and a Retry-After equal to the growing curve. Both 429s
        look identical from the outside, which is exactly why this asserts on
        the body instead of the status code.
        """
        import app.main as main
        from app.config import RATE_ADMIN_LOGIN_PER_MIN

        self.assertEqual(main.RATE_ADMIN_LOGIN_PER_MIN, self.WINDOW_LIMIT,
                         "the fixture's window limit and the app's disagree")

        for _ in range(6):
            self._login("wrong")
        backoff_only = self._login("wrong")
        self.assertIn("failed attempts", backoff_only.json()["error"])
        self.assertGreater(int(backoff_only.headers["Retry-After"]), 1,
                           "this is not the backoff's curve, it is the window")

        # Spend the window as well.
        for _ in range(self.WINDOW_LIMIT):
            self._login("wrong")
        both = self._login("wrong")
        self.assertEqual(both.json()["error"], "Too many attempts. Try again later.",
                         "the window is no longer the one refusing")

    def test_a_correct_password_after_the_backoff_is_a_200(self):
        """And the whole point: an operator who waits is let in."""
        self.assertEqual(self._login("a-long-admin-passphrase").status_code, 200)


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
