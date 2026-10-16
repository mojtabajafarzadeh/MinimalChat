"""Rate-limit keys behind a reverse proxy (I-01).

Without a trusted-proxy mode every user behind one proxy shares a single key,
so MAX_SOCKETS_PER_IP is a site-wide socket ceiling and the login limit is a
site-wide login rate. The fix is to believe X-Forwarded-For -- but only from a
peer that was configured as a proxy.

The dangerous half is the second condition. If the header were trusted from any
peer, a client could set it to whatever it liked and give every request a fresh
key, walking straight through every limit. These tests are mostly about that
not being possible.
"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.security import (
    client_ip,
    configure_trusted_proxies,
    is_trusted_proxy,
    trusted_proxies,
)
from testsupport import reload_settings, settings_env


class DirectConnectionTests(unittest.TestCase):
    """The default: no proxy configured, header must be ignored entirely."""

    def setUp(self):
        configure_trusted_proxies([])
        self.addCleanup(configure_trusted_proxies, [])

    def test_the_header_is_ignored_when_no_proxy_is_configured(self):
        self.assertEqual(client_ip("10.0.0.5", "1.2.3.4"), "10.0.0.5")

    def test_a_client_cannot_change_its_key_by_setting_the_header(self):
        """The whole point: without configuration, the header is noise."""
        for forged in ("1.2.3.4", "9.9.9.9, 8.8.8.8", "  ", "unknown"):
            with self.subTest(header=forged):
                self.assertEqual(client_ip("10.0.0.5", forged), "10.0.0.5")

    def test_a_missing_peer_falls_back(self):
        self.assertEqual(client_ip("", None), "unknown")


class TrustedProxyTests(unittest.TestCase):
    def setUp(self):
        configure_trusted_proxies(["127.0.0.1", "::1", "10.0.0.0/8"])
        self.addCleanup(configure_trusted_proxies, [])

    def test_the_list_is_configured(self):
        self.assertEqual(len(trusted_proxies()), 3)
        self.assertTrue(is_trusted_proxy("127.0.0.1"))
        self.assertTrue(is_trusted_proxy("10.1.2.3"))
        self.assertFalse(is_trusted_proxy("203.0.113.9"))

    def test_a_request_from_a_configured_proxy_is_believed(self):
        self.assertEqual(client_ip("127.0.0.1", "203.0.113.9"), "203.0.113.9")

    def test_a_request_from_a_configured_cidr_is_believed(self):
        self.assertEqual(client_ip("10.1.1.1", "203.0.113.9"), "203.0.113.9")

    def test_ipv6_loopback_is_believed(self):
        self.assertEqual(client_ip("::1", "203.0.113.9"), "203.0.113.9")

    # ------------------------------------------------------------- spoofing

    def test_an_unconfigured_peer_cannot_forge_the_header(self):
        """The critical case: the proxy is configured, but this request did
        not come from it, so the header is still noise."""
        self.assertEqual(
            client_ip("203.0.113.9", "1.2.3.4"),
            "203.0.113.9",
            "an untrusted peer could rewrite its own rate-limit key")

    def test_the_rightmost_untrusted_hop_wins(self):
        """A client can prepend anything; only the proxy-appended hop is
        real. Walking from the right is what makes this safe."""
        # Client forges a left-hand entry, proxy appends the truth.
        self.assertEqual(
            client_ip("127.0.0.1", "6.6.6.6, 203.0.113.9"),
            "203.0.113.9",
            "a forged leading hop was trusted over the proxy's own entry")

    def test_a_chain_of_configured_proxies_is_walked_through(self):
        """Two proxies: the rightmost untrusted entry is still the client."""
        self.assertEqual(
            client_ip("10.0.0.1", "198.51.100.7, 10.0.0.2"),
            "198.51.100.7")

    def test_when_every_hop_is_a_trusted_proxy_the_leftmost_is_used(self):
        self.assertEqual(client_ip("10.0.0.1", "10.0.0.2, 10.0.0.3"),
                         "10.0.0.2")

    def test_an_empty_header_falls_back_to_the_peer(self):
        self.assertEqual(client_ip("127.0.0.1", ""), "127.0.0.1")
        self.assertEqual(client_ip("127.0.0.1", "   "), "127.0.0.1")

    def test_garbage_in_the_header_does_not_crash(self):
        for junk in ("not-an-ip", "999.999.999.999", "1.2.3.4, junk"):
            with self.subTest(header=junk):
                result = client_ip("127.0.0.1", junk)
                self.assertIsInstance(result, str)
                self.assertTrue(result)


class ParsingTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(configure_trusted_proxies, [])

    def test_an_unparseable_entry_is_dropped_not_fatal(self):
        """A typo must not take the whole list down silently."""
        configure_trusted_proxies(["127.0.0.1", "not-a-cidr", "10.0.0.0/8"])
        self.assertTrue(is_trusted_proxy("127.0.0.1"))
        self.assertTrue(is_trusted_proxy("10.1.1.1"))
        self.assertFalse(is_trusted_proxy("203.0.113.9"))

    def test_an_empty_list_disables_the_feature(self):
        configure_trusted_proxies(["", "  "])
        self.assertEqual(trusted_proxies(), [])
        self.assertFalse(is_trusted_proxy("127.0.0.1"))

    def test_a_host_prefix_is_accepted(self):
        configure_trusted_proxies(["127.0.0.1/32"])
        self.assertTrue(is_trusted_proxy("127.0.0.1"))
        self.assertFalse(is_trusted_proxy("127.0.0.2"))


class ConfigWiringTests(unittest.TestCase):
    """The setting has to be read from the environment and applied."""

    def test_config_parses_a_comma_separated_list(self):
        with settings_env(TRUSTED_PROXY_CIDRS="127.0.0.1, 10.0.0.0/8 ,") as cfg:
            self.assertEqual(cfg.TRUSTED_PROXY_CIDRS,
                             ["127.0.0.1", "10.0.0.0/8"])

    def test_it_defaults_to_empty(self):
        from app import config
        self.assertIsInstance(config.TRUSTED_PROXY_CIDRS, list)
        configure_trusted_proxies(config.TRUSTED_PROXY_CIDRS)
        self.assertEqual(trusted_proxies(), [],
                         "X-Forwarded-For is trusted by default")

    def test_both_ip_helpers_go_through_the_shared_logic(self):
        """Parsed with ast, not by slicing text: a docstring contains blank
        lines, so slicing on '\\n\\n' truncates the body it is inspecting."""
        import ast
        src = (ROOT / "app" / "main.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        bodies = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name in (
                    "_client_ip", "_ws_ip"):
                bodies[node.name] = ast.get_source_segment(src, node) or ""
        self.assertEqual(set(bodies), {"_client_ip", "_ws_ip"},
                         "one of the IP helpers is gone")
        for name, body in bodies.items():
            with self.subTest(helper=name):
                self.assertIn("client_ip(", body,
                              f"{name} bypasses the shared proxy-aware helper")
                self.assertIn("x-forwarded-for", body)


if __name__ == "__main__":
    unittest.main()
