"""PIP_INDEX_URL: which package index `run.py` installs from.

The install runs before the app package is importable, so run.py reads the
setting itself. What matters is that an unset value means PyPI (pip's own
default, achieved by omitting the flag entirely rather than passing an empty
one, which pip rejects), and that a value in .env is used as given.
"""
import builtins
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.config import _load_dotenv as config_load_dotenv

MIRROR = "https://mirror.example.invalid/artifactory/api/pypi/pip-virtual/simple"


def load_run_py():
    """Import run.py as a module without running main()."""
    spec = importlib.util.spec_from_file_location("run_under_test", ROOT / "run.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class PipIndexArgsTests(unittest.TestCase):
    """_pip_index_args() itself: precedence and the no-value case."""

    def setUp(self):
        self.mod = load_run_py()
        self.tmp = Path(tempfile.mkdtemp())
        self._saved = os.environ.pop("PIP_INDEX_URL", None)

    def tearDown(self):
        if self._saved is not None:
            os.environ["PIP_INDEX_URL"] = self._saved
        else:
            os.environ.pop("PIP_INDEX_URL", None)

    def _with_env_file(self, text):
        (self.tmp / ".env").write_text(text)
        self.mod.ROOT = self.tmp

    def test_unset_omits_the_flag_so_pip_uses_pypi(self):
        self._with_env_file("")
        self.assertEqual(self.mod._pip_index_args(), [])

    def test_a_value_in_the_env_file_is_used(self):
        self._with_env_file(f"PIP_INDEX_URL={MIRROR}\n")
        self.assertEqual(self.mod._pip_index_args(), ["--index-url", MIRROR])

    def test_a_blank_value_is_the_same_as_unset(self):
        for blank in ("PIP_INDEX_URL=\n", "PIP_INDEX_URL=   \n",
                      'PIP_INDEX_URL=""\n'):
            with self.subTest(value=blank):
                self._with_env_file(blank)
                self.assertEqual(self.mod._pip_index_args(), [])

    def test_a_real_env_var_wins_over_the_file(self):
        self._with_env_file("PIP_INDEX_URL=https://from-file.invalid/simple\n")
        os.environ["PIP_INDEX_URL"] = MIRROR
        self.assertEqual(self.mod._pip_index_args(), ["--index-url", MIRROR])

    def test_a_missing_env_file_is_not_an_error(self):
        self.mod.ROOT = Path(tempfile.mkdtemp())  # no .env here
        self.assertEqual(self.mod._pip_index_args(), [])

    def test_quoted_value_with_a_trailing_comment_keeps_only_the_url(self):
        """A '#' inside quotes is data, not a comment."""
        self._with_env_file(f'PIP_INDEX_URL="{MIRROR}"  # our mirror\n')
        self.assertEqual(self.mod._pip_index_args(), ["--index-url", MIRROR])


class EnsureDepsCommandTests(unittest.TestCase):
    """The command line ensure_deps() actually builds, with pip stubbed out."""

    def setUp(self):
        self.mod = load_run_py()
        self.tmp = Path(tempfile.mkdtemp())
        self._saved = os.environ.pop("PIP_INDEX_URL", None)
        self.recorded = {}
        self.mod.subprocess.check_call = (
            lambda cmd, *a, **k: self.recorded.setdefault("cmd", cmd))

    def tearDown(self):
        if self._saved is not None:
            os.environ["PIP_INDEX_URL"] = self._saved
        else:
            os.environ.pop("PIP_INDEX_URL", None)

    def _run_install(self, env_text):
        (self.tmp / ".env").write_text(env_text)
        self.mod.ROOT = self.tmp
        saved_import = builtins.__import__

        def blocked(name, *a, **k):
            if name.split(".")[0] in ("fastapi", "uvicorn", "cryptography"):
                raise ImportError(name)
            return saved_import(name, *a, **k)

        builtins.__import__ = blocked
        try:
            self.mod.ensure_deps()
        finally:
            builtins.__import__ = saved_import
        return self.recorded.get("cmd", [])

    def test_no_mirror_gives_a_plain_install_with_no_index_flag(self):
        cmd = self._run_install("")
        self.assertNotIn("--index-url", cmd)
        self.assertEqual(cmd[-1], str(self.tmp / "requirements.txt"))

    def test_a_mirror_is_passed_through_and_requirements_still_last(self):
        cmd = self._run_install(f"PIP_INDEX_URL={MIRROR}\n")
        self.assertIn("--index-url", cmd)
        self.assertEqual(cmd[cmd.index("--index-url") + 1], MIRROR)
        self.assertEqual(cmd[-1], str(self.tmp / "requirements.txt"))


class DotenvReaderTests(unittest.TestCase):
    """The shared reader run.py copies from config: quoting and comments."""

    def _parse(self, text):
        p = Path(tempfile.mkdtemp()) / ".env"
        p.write_text(text)
        return config_load_dotenv(p)

    def test_plain_value(self):
        self.assertEqual(self._parse("A=b\n"), {"A": "b"})

    def test_trailing_comment_outside_quotes_is_dropped(self):
        self.assertEqual(self._parse("A=b # note\n"), {"A": "b"})

    def test_hash_inside_quotes_is_kept(self):
        self.assertEqual(self._parse('A="a#b"\n'), {"A": "a#b"})

    def test_quoted_value_followed_by_a_comment(self):
        self.assertEqual(self._parse('A="b" # note\n'), {"A": "b"})

    def test_comments_and_blank_lines_are_skipped(self):
        self.assertEqual(self._parse("# c\n\nA=b\n"), {"A": "b"})

    def test_unterminated_quote_does_not_crash(self):
        self.assertEqual(self._parse('A="b\n'), {"A": "b"})


if __name__ == "__main__":
    unittest.main()