"""Shared helper for tests that need app.settings to read a given environment.

`app.config` reads its settings into module constants at import time, so a
test that wants different values has to re-evaluate it. The obvious approach --
`sys.modules.pop(name)` then `importlib.import_module(name)` -- leaves a trap
behind: the parent package still holds the old module as an attribute, so a
later `from app import config` can bind a module object that is *not* in
`sys.modules`, and the next `importlib.reload(config)` raises
`ImportError: module app.config not in sys.modules`.

That failure lands on whichever unrelated test ran next, which is why it
surfaced under `unittest discover` and not under pytest.

`reload_settings()` keeps `sys.modules` self-consistent: the fresh module is
registered, and the parent package's attribute is rebound to it, so any later
`reload()` -- in this test or another -- has a module to work on.
"""
import importlib
import os
import sys

# Reloaded together because app.admin binds values from app.config at import.
_SETTINGS_MODULES = ("app.config", "app.admin")


def reload_settings(**env):
    """Re-evaluate app.config with `env` applied, and return it.

    The environment is left as the caller set it; use settings_env() when the
    change should be undone afterwards.
    """
    for key, value in env.items():
        os.environ[key] = value

    for name in _SETTINGS_MODULES:
        sys.modules.pop(name, None)

    config = importlib.import_module("app.config")
    # Re-register the sibling too, so admin sees the new config values.
    admin = importlib.import_module("app.admin")

    # The parent package still points at the discarded modules; rebind, or a
    # later `from app import config` hands out something reload() cannot use.
    import app
    app.config = config
    app.admin = admin
    return config


class settings_env:
    """`with settings_env(ADMIN_PASSWORD="x"): ...` -- restores on exit."""

    def __init__(self, **env):
        self.env = env
        self.saved = {}

    def __enter__(self):
        self.saved = {k: os.environ.get(k) for k in self.env}
        return reload_settings(**self.env)

    def __exit__(self, *exc):
        for key, value in self.saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        reload_settings()
        return False