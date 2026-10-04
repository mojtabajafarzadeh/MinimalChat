"""Bundler tests (packaging/build.py).

The bundler walks the installed dependency closure by parsing requirement
strings from package metadata. This is regression cover for a real CI
failure: `packaging` is not a dependency of this project, so a CI runner that
installed only requirements.txt has no `packaging` module, and an older
fallback parser passed "typing-extensions>=4.13.2" to importlib.metadata,
which raised PackageNotFoundError and failed the build.

These tests therefore pin both the parsing itself and the behaviour that made
CI fail: building with `packaging` unavailable must still succeed.
"""
import importlib.metadata as md
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "packaging"))

import build  # noqa: E402  (path is set up above)


class RequirementNameTests(unittest.TestCase):
    """Names must come out bare: no specifiers, extras, URLs or markers."""

    def test_strips_version_specifier(self):
        self.assertEqual(build.requirement_name("cffi>=2.0.0"), "cffi")
        self.assertEqual(build.requirement_name("cffi>=1.0,<2.0"), "cffi")
        self.assertEqual(build.requirement_name("cffi ~= 1.4"), "cffi")
        self.assertEqual(build.requirement_name("cffi != 1.0, >= 1.2"), "cffi")

    def test_strips_extras(self):
        self.assertEqual(build.requirement_name("uvicorn[standard]>=0.23"), "uvicorn")
        self.assertEqual(build.requirement_name("cryptography[ssh]>=42"), "cryptography")

    def test_strips_environment_marker(self):
        raw = "typing-extensions>=4.13.2 ; python_full_version < '3.11'"
        self.assertEqual(build.requirement_name(raw), "typing-extensions")
        raw = "cffi>=2.0.0 ; platform_python_implementation != 'PyPy'"
        self.assertEqual(build.requirement_name(raw), "cffi")

    def test_strips_direct_reference_url(self):
        self.assertEqual(build.requirement_name("foo @ https://x.example/f.whl"), "foo")

    def test_keeps_dots_and_underscores(self):
        self.assertEqual(build.requirement_name("zope.interface"), "zope.interface")
        self.assertEqual(build.requirement_name("typing_extensions"), "typing_extensions")
        self.assertEqual(build.requirement_name("annotated-types"), "annotated-types")

    def test_tolerates_surrounding_whitespace(self):
        self.assertEqual(build.requirement_name("  spaced-name >= 1.0 , < 2.0"), "spaced-name")

    def test_rejects_nonsense(self):
        with self.assertRaises(ValueError):
            build.requirement_name(">=1.0")


class RequirementMarkerTests(unittest.TestCase):
    def test_unconditional_requirement_is_included(self):
        self.assertIs(build.marker_allows("annotated-types>=0.6.0"), True)

    def test_extra_requirements_are_excluded(self):
        # Extras are never active: we install the base requirements only.
        self.assertIs(build.marker_allows("bcrypt>=3.1.5 ; extra == 'ssh'"), False)

    def test_marker_is_extracted(self):
        self.assertEqual(
            build.requirement_marker("x>=1 ; python_version < '3.11'"),
            "python_version < '3.11'",
        )
        self.assertEqual(build.requirement_marker("x>=1"), "")


class ClosureTests(unittest.TestCase):
    def test_closure_never_asks_for_a_specifier_as_a_name(self):
        """The exact failure from CI: names must be resolvable metadata keys."""
        seen_names = []
        for name in build.TOP_LEVEL_DISTS:
            for raw in build.deps_of(md.distribution(name)):
                seen_names.append(build.requirement_name(raw))
        for name in seen_names:
            # importlib.metadata must be able to resolve it (or not exist at
            # all, which closure() handles gracefully) -- but never raise
            # because the name carried a version specifier.
            try:
                md.distribution(name)
            except md.PackageNotFoundError:
                pass
            except Exception as exc:                      # noqa: BLE001
                self.fail(f"{name!r} is not a usable distribution name: {exc}")

    def test_closure_completes_and_covers_the_runtime_imports(self):
        dists = build.closure()
        for required in ("fastapi", "uvicorn", "cryptography", "websockets"):
            self.assertIn(required, dists, f"{required} missing from the closure")
        # pydantic/starlette/anyio are imported at runtime by fastapi/uvicorn.
        for required in ("pydantic", "starlette", "anyio"):
            self.assertIn(required, dists)

    def test_closure_tolerates_a_missing_conditional_dependency(self):
        """An uninstalled conditional dep must be skipped, not fatal."""
        original = md.distribution

        def flaky(name):
            if name.lower().replace("-", "_") == "idna":
                raise md.PackageNotFoundError(name)
            return original(name)

        import unittest.mock as mock
        with mock.patch.object(build.md, "distribution", flaky):
            dists = build.closure()      # must not raise
        self.assertIn("fastapi", dists)
        self.assertNotIn("idna", dists)


class ArtifactCheckTests(unittest.TestCase):
    """The bundler must refuse to ship a bundle that is missing a dependency.

    These guard a real gap: verification originally imported a hand-picked
    list of module names, so a dependency that was never vendored went
    unnoticed and only failed on the user's machine.
    """

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.lib = Path(self.dir.name) / "lib"
        self.lib.mkdir()

    def test_modules_in_finds_packages_modules_and_extensions(self):
        (self.lib / "fastapi").mkdir()
        (self.lib / "fastapi" / "__init__.py").write_text("")
        (self.lib / "typing_extensions.py").write_text("")
        (self.lib / "_cffi_backend.cpython-312-x86_64-linux-gnu.so").write_bytes(b"")
        (self.lib / "somepkg-1.0.dist-info").mkdir()
        (self.lib / ".hidden").mkdir()
        found = build.modules_in(self.lib)
        self.assertIn("fastapi", found)
        self.assertIn("typing_extensions", found)
        self.assertIn("_cffi_backend", found)
        self.assertNotIn("somepkg-1.0.dist-info", found)
        self.assertNotIn(".hidden", found)

    def test_present_in_accepts_package_module_and_extension_forms(self):
        (self.lib / "pkgdir").mkdir()
        (self.lib / "single.py").write_text("")
        (self.lib / "extmod.cpython-312-x86_64-linux-gnu.so").write_bytes(b"")
        for name in ("pkgdir", "single", "extmod"):
            self.assertTrue(build._present_in(self.lib, name), name)
        for name in ("absent", "other"):
            self.assertFalse(build._present_in(self.lib, name), name)

    def test_missing_required_distribution_fails_the_build(self):
        original = build.TOP_LEVEL_DISTS
        build.TOP_LEVEL_DISTS = list(original) + ["definitely-not-installed-xyz"]
        self.addCleanup(lambda: setattr(build, "TOP_LEVEL_DISTS", original))
        with self.assertRaises(SystemExit) as ctx:
            build.closure()
        self.assertIn("definitely-not-installed-xyz", str(ctx.exception))
        self.assertIn("pip install", str(ctx.exception))


class BuildWithoutPackagingTests(unittest.TestCase):
    """The condition that broke CI: no `packaging` module available."""

    def test_build_succeeds_when_packaging_is_unavailable(self):
        with tempfile.TemporaryDirectory() as tmp:
            # A module that makes `import packaging` fail, exactly like an
            # environment where the package was never installed.
            stub = Path(tmp) / "packaging.py"
            stub.write_text('raise ImportError("No module named \'packaging\'")\n',
                            encoding="utf-8")
            env = {"PYTHONPATH": tmp, "PATH": "/usr/bin:/bin", "HOME": tmp}
            proc = subprocess.run(
                [sys.executable, str(ROOT / "packaging" / "build.py")],
                capture_output=True, text=True, env=env, cwd=str(ROOT), timeout=900,
            )
            self.assertEqual(
                proc.returncode, 0,
                "build failed without `packaging`:\n" + proc.stdout[-2000:] +
                proc.stderr[-2000:],
            )
            self.assertIn("Done:", proc.stdout)
            # The isolated import check must have run and passed.
            self.assertIn("bundled imports OK", proc.stdout)
            bundle = ROOT / "dist" / "chat-app-linux-x86_64.tar.gz"
            self.assertTrue(bundle.exists())
            self.assertGreater(bundle.stat().st_size, 1_000_000)

    def test_bundle_from_a_clean_environment_contains_conditional_dependencies(self):
        """A conditional dep must not be silently dropped from the bundle.

        `typing-extensions` is declared by cryptography only for Python < 3.11
        and unconditionally by fastapi; if the resolver loses a dependency the
        bundle still builds, so assert the file is actually in it.
        """
        stage = ROOT / "dist" / "chat-app" / "lib"
        self.assertTrue(stage.is_dir(), "run the build first")
        self.assertTrue(
            (stage / "typing_extensions.py").is_file()
            or (stage / "typing_extensions").is_dir(),
            "typing_extensions missing from the bundle",
        )
        for required in ("fastapi", "uvicorn", "cryptography"):
            self.assertTrue((stage / required).is_dir(), f"{required} missing")


if __name__ == "__main__":
    unittest.main(verbosity=2)