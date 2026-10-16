"""Docstrings must be valid.

Python treats a docstring as a string literal, so an unescaped backslash in
one is not an error -- it is silently interpreted as an escape, and
`\\q` becomes `\\q` with a DeprecationWarning that only shows up under
`-W error`. Two bugs of exactly this shape happened here:

- `_like_pattern`'s docstring said `?q=%`, where `%` followed the docstring's
  own quoting and produced "invalid escape sequence" on import.
- `esc()`'s comment used `title=\"' + esc(x) + '\"`, which is fine as a
  comment but would have been broken had it been a docstring.

Nothing caught either at the time. This module makes the class of mistake
loud and permanent: compile every source file with escape-sequence warnings
promoted to errors, exactly the way Python would at runtime.
"""
import py_compile
import tempfile
import unittest
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / "app"


def _py_files():
    return sorted(APP.rglob("*.py")) + [ROOT / "run.py"]


class DocstringAndStringTests(unittest.TestCase):
    def test_no_module_fails_to_compile_with_escape_warnings_as_errors(self):
        """Compile each file with SyntaxWarning promoted to an error.

        compile() reports the same "invalid escape sequence" that importing
        would, but without running the module or needing its dependencies.
        """
        offenders = []
        for path in _py_files():
            source = path.read_text(encoding="utf-8")
            with warnings.catch_warnings():
                warnings.simplefilter("error", SyntaxWarning)
                try:
                    compile(source, str(path), "exec")
                except SyntaxWarning as exc:
                    offenders.append(f"{path.relative_to(ROOT)}: {exc}")
                except SyntaxError as exc:
                    offenders.append(f"{path.relative_to(ROOT)}: {exc}")
        self.assertEqual(
            offenders, [],
            "these files carry an invalid escape sequence (most often an "
            "unescaped backslash in a docstring):\n  "
            + "\n  ".join(offenders))

    def test_every_module_imports_cleanly_under_strict_warnings(self):
        """The stricter end-to-end check: import the app package with
        warnings as errors, so any escape in a docstring raises."""
        offenders = []
        for name in ("app.config", "app.enc", "app.db", "app.auth",
                     "app.crypto", "app.security", "app.paths",
                     "app.websocket", "app.admin"):
            with warnings.catch_warnings():
                warnings.simplefilter("error", SyntaxWarning)
                try:
                    __import__(name)
                except SyntaxWarning as exc:
                    offenders.append(f"{name}: {exc}")
        self.assertEqual(offenders, [],
                         "modules raising SyntaxWarning on import: "
                         + "; ".join(offenders))

    def test_documented_patterns_are_escaped_or_reworded(self):
        """Spot-check the two sites that actually broke.

        Neither can be found by reading the docstring alone, because the
        damage happens during compilation, not at runtime.
        """
        main = (ROOT / "app" / "main.py").read_text(encoding="utf-8")
        self.assertIn("a bare `%` is a wildcard", main,
                      "the _like_pattern docstring lost its wording")
        # No bare backslash immediately before a quote inside a docstring.
        for path in _py_files():
            text = path.read_text(encoding="utf-8")
            for i, line in enumerate(text.splitlines(), 1):
                stripped = line.strip()
                if stripped.startswith(('"""', "'''")):
                    self.assertNotIn(
                        '\\"', stripped,
                        f"{path.name}:{i} has an escaped quote inside a "
                        "docstring opener")


class RegressionTests(unittest.TestCase):
    """Keep the concrete bugs that were fixed from coming back."""

    def test_the_dotenv_quoting_fix_is_present(self):
        """The `.env` parser mishandled `KEY=\"value\"  # comment`, passing
        the quotes through. Both parsers must find the closing quote first."""
        for rel in ("app/config.py", "run.py"):
            text = (ROOT / rel).read_text(encoding="utf-8")
            with self.subTest(file=rel):
                self.assertIn("end = val.find(quote, 1)", text,
                              f"{rel} lost the quoted-value fix")
                self.assertNotIn('val[0] == val[-1]', text,
                                 f"{rel} reverted to the quote-stripping "
                                 "that skipped the comment branch")

    def test_the_like_pattern_docstring_is_compilable(self):
        """The specific string that raised the warning, re-checked in
        isolation so the failure message points at the line.

        Compiles the *definition*, not a window cut out of the file: slicing
        mid-expression produces an unrelated SyntaxError (an unclosed `]`)
        and tells you nothing.
        """
        import ast
        src = (ROOT / "app" / "main.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        target = None
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "_like_pattern":
                target = node
                break
        self.assertIsNotNone(target, "_like_pattern is gone from main.py")

        segment = ast.get_source_segment(src, target)
        self.assertIsNotNone(segment, "could not extract _like_pattern")
        with warnings.catch_warnings():
            warnings.simplefilter("error", SyntaxWarning)
            try:
                compile(segment, "<_like_pattern>", "exec")
            except SyntaxWarning as exc:
                self.fail(f"_like_pattern raises {exc}")
            except SyntaxError as exc:
                self.fail(f"_like_pattern is not valid Python: {exc}")


if __name__ == "__main__":
    unittest.main()