"""Tests must not break each other through sys.modules.

The CI failure this guards against was not in the app: `test_session_lifetime`
popped `app.config` out of sys.modules in tearDown and never put it back. The
next `from app import config` then bound a module that was *not* registered, so
that test's own `importlib.reload(config)` raised
`ImportError: module app.config not in sys.modules` -- attributed to an
unrelated test in a different file.

pytest hid it because collection order differs from `unittest discover`. So
these tests assert the invariant directly: after any test helper has run, the
app modules are still in sys.modules and still reloadable.
"""
import importlib
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from testsupport import reload_settings, settings_env

_APP_MODULES = ("app.config", "app.admin")


class SysModulesStaysConsistentTests(unittest.TestCase):
    def test_app_modules_are_registered_after_a_reload(self):
        reload_settings()
        for name in _APP_MODULES:
            with self.subTest(module=name):
                self.assertIn(
                    name, sys.modules,
                    f"{name} is missing from sys.modules after reload_settings")

    def test_a_reloaded_module_can_be_reloaded_again(self):
        """The exact CI failure: reload() on a module not in sys.modules."""
        reload_settings()
        for name in _APP_MODULES:
            with self.subTest(module=name):
                try:
                    importlib.reload(sys.modules[name])
                except ImportError as exc:
                    self.fail(
                        f"reload({name}) failed after reload_settings(): {exc}. "
                        "A module popped from sys.modules without being "
                        "re-registered breaks every later reload.")

    def test_from_app_import_works_after_a_reload(self):
        reload_settings()
        from app import config, admin          # noqa: F401
        self.assertIn(config.__name__, sys.modules)

    def test_the_parent_package_points_at_the_registered_module(self):
        """`from app import config` must not bind a detached module."""
        reload_settings()
        import app
        for name in _APP_MODULES:
            with self.subTest(module=name):
                bound = getattr(app, name.split(".")[-1])
                self.assertIs(
                    bound, sys.modules[name],
                    f"app.{name.split('.')[-1]} and sys.modules[{name}] are "
                    "different objects; a later reload() will fail")

    def test_settings_env_restores_the_environment(self):
        import os
        before = os.environ.get("ADMIN_PATH")
        with settings_env(ADMIN_PATH="/custom-panel"):
            self.assertEqual(
                sys.modules["app.config"].ADMIN_PATH, "/custom-panel")
        after = os.environ.get("ADMIN_PATH")
        self.assertEqual(
            before, after,
            "settings_env left ADMIN_PATH behind, so a later test would see it")

    def test_settings_env_leaves_the_modules_reloadable(self):
        with settings_env(ADMIN_PASSWORD="x"):
            pass
        for name in _APP_MODULES:
            with self.subTest(module=name):
                self.assertIn(name, sys.modules)
                importlib.reload(sys.modules[name])

    def test_a_bad_settings_value_does_not_corrupt_sys_modules(self):
        """An exception mid-reload must still leave things consistent."""
        with self.assertRaises(Exception):
            with settings_env(ADMIN_PATH="x"):
                raise RuntimeError("boom")
        for name in _APP_MODULES:
            with self.subTest(module=name):
                self.assertIn(name, sys.modules)
                importlib.reload(sys.modules[name])


if __name__ == "__main__":
    unittest.main()