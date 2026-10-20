"""The app has one name, and it is MChat.

A rename is the kind of change that is easy to half-do: the page titles get
updated and the manifest does not, or the launcher is renamed and the
installer still looks for the old one. Nothing crashes when that happens --
the build succeeds, the tests pass, and the app is simply called two
different things in two different places.

So the name is pinned here, in the places a user or an operator would see
it: the browser tab, the home-screen icon, the FastAPI title, the offline
bundle, and the launcher the installer links.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "app" / "static"

# The old name, in the spellings it appeared in. If one of these comes back,
# the rename was only half-done.
#
# "MinimalChat" is matched with a boundary, because one place is not the
# app's name: MinimalChat-AUDIT/ is the directory the security-review notes
# live in, it has that name on disk, and it is a working folder rather than
# a brand.
OLD_NAMES = ("Minimal Chat", "minimal chat", "chat-app",
             "Chat app running at")
OLD_CAMEL = re.compile(r"MinimalChat(?!-AUDIT)")


class DisplayNameTests(unittest.TestCase):
    """What a user sees."""

    def test_the_manifest_is_named_mchat(self):
        import json

        manifest = json.loads(
            (STATIC / "manifest.webmanifest").read_text(encoding="utf-8"))
        self.assertEqual("MChat", manifest.get("name"),
                         "the home-screen icon is labelled with the manifest's "
                         f"name, which is {manifest.get('name')!r}")
        self.assertTrue(manifest.get("short_name"),
                        "the manifest has no short name, so the home-screen "
                        "label would be the full one")

    def test_every_page_title_carries_the_name(self):
        for name in ("chat.html", "login.html", "register.html", "admin.html"):
            with self.subTest(page=name):
                html = (STATIC / name).read_text(encoding="utf-8")
                m = re.search(r"<title>([^<]*)</title>", html)
                self.assertIsNotNone(m, f"{name} has no title")
                self.assertIn("MChat", m.group(1),
                              f"the tab title is {m.group(1)!r}, which does "
                              "not name the app")

    def test_the_tab_title_after_a_message_keeps_the_name(self):
        """The unread count is prepended to the title, so the name has to
        survive that -- a title of "(3)" names nothing."""
        js = (STATIC / "app.js").read_text(encoding="utf-8")
        m = re.search(r"const BASE_TITLE = '([^']*)'", js)
        self.assertIsNotNone(m, "BASE_TITLE is gone; the tab title is built "
                                "somewhere else and this guard has to follow")
        self.assertIn("MChat", m.group(1),
                      f"the tab title is built from {m.group(1)!r}, which does "
                      "not name the app")

    def test_the_fastapi_title_names_the_app(self):
        main = (ROOT / "app" / "main.py").read_text(encoding="utf-8")
        self.assertIn('FastAPI(title="MChat"', main,
                      "the API's own title does not name the app")

    def test_the_startup_banner_names_the_app(self):
        run = (ROOT / "run.py").read_text(encoding="utf-8")
        self.assertIn("MChat running at", run,
                      "the first line an operator sees does not name the app")


class OperatorNameTests(unittest.TestCase):
    """What an operator sees: the bundle and the launcher."""

    def test_the_bundle_is_called_mchat(self):
        build = (ROOT / "packaging" / "build.py").read_text(encoding="utf-8")
        self.assertIn('"mchat-linux-x86_64.tar.gz"', build,
                      "the bundle is not called mchat")
        self.assertIn('STAGE = ROOT / "dist" / "mchat"', build,
                      "the staging directory is not called mchat")

    def test_the_launcher_is_called_mchat(self):
        self.assertTrue((ROOT / "packaging" / "templates" / "mchat").is_file(),
                        "there is no launcher called mchat")
        self.assertFalse(
            (ROOT / "packaging" / "templates" / "chat-app").exists(),
            "the old chat-app launcher is still there; the two would both be "
            "copied into the bundle and only one would be linked")

    def test_the_installer_links_the_launcher_under_its_new_name(self):
        """The link itself, not the name appearing somewhere in the file.

        An earlier version of this asserted that the string "$BIN_DIR/mchat"
        occurred anywhere in the script, which it does -- in the echo below
        the link -- so a launcher linked under the wrong name still passed it.
        """
        install = (ROOT / "packaging" / "templates" / "install.sh").read_text(
            encoding="utf-8")
        link = next((l for l in install.splitlines()
                     if l.strip().startswith("ln -sf")), None)
        self.assertIsNotNone(link, "the installer creates no symlink")
        self.assertIn('"$BIN_DIR/mchat"', link,
                      f"the launcher is linked under a different name: {link!r}")
        self.assertIn('"$DEST/mchat"', link,
                      f"the launcher links the wrong source: {link!r}")
        self.assertIn('.local/share/mchat', install,
                      "the installer does not install into a directory called "
                      "mchat")


class NoOldNameTests(unittest.TestCase):
    """Nothing anywhere still says the old name.

    Checked across the source rather than in a list of known places, because
    the half-done rename is exactly the case a list misses.
    """

    SKIP_DIRS = {".git", ".venv", "dist", "__pycache__", ".pytest_cache",
                 "MinimalChat-AUDIT", "lib", "data"}

    def _sources(self):
        # This file names the old name on purpose -- it is the list of things
        # that must not come back -- so it cannot scan itself.
        self_path = Path(__file__).resolve()
        for path in sorted(ROOT.rglob("*")):
            if not path.is_file():
                continue
            if path.resolve() == self_path:
                continue
            if any(part in self.SKIP_DIRS for part in path.parts):
                continue
            if path.suffix in (".png", ".jpg", ".gz", ".pyc", ".db",
                                ".pem", ".key", ".crt"):
                continue
            yield path

    def test_no_source_file_still_carries_the_old_name(self):
        offenders = []
        for path in self._sources():
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            for old in OLD_NAMES:
                if old in text:
                    offenders.append(f"{path.relative_to(ROOT)}: {old!r}")
            if OLD_CAMEL.search(text):
                offenders.append(f"{path.relative_to(ROOT)}: 'MinimalChat'")
        self.assertEqual([], offenders,
                         "the old name is still in: " + "; ".join(offenders))


if __name__ == "__main__":
    unittest.main()
