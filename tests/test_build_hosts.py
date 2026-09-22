import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.build_hosts import build, extract_domains, render_hosts


class ExtractDomainsTests(unittest.TestCase):
    def test_plain_domain_mode_accepts_only_domains(self):
        text = """
# comment
Example.COM
ads.example.com
||tracker.example.com^
@@||allowed.example.com^
https://bad.example/path
*.wild.example
localhost
127.0.0.1 local.example
"""
        self.assertEqual(
            extract_domains(text, "domains"),
            {"example.com", "ads.example.com"},
        )

    def test_hosts_mode_extracts_host_entries_and_normalizes(self):
        text = """
# comment
0.0.0.0 Ads.Example.COM
127.0.0.1 tracker.example.com # inline comment
0.0.0.0 one.example two.example
::1 ipv6.example
255.255.255.255 broad.example
plain.example
"""
        self.assertEqual(
            extract_domains(text, "hosts"),
            {"ads.example.com", "tracker.example.com", "one.example", "two.example"},
        )

    def test_rejects_invalid_or_local_domains(self):
        text = """
localhost
localhost.localdomain
bad_domain.example
-example.com
example-.com
foo..bar
192.168.1.1
example
xn--fiqs8s.example
"""
        self.assertEqual(
            extract_domains(text, "domains"),
            {"xn--fiqs8s.example"},
        )


class RenderHostsTests(unittest.TestCase):
    def test_render_hosts_deduplicates_and_sorts(self):
        result = render_hosts({"b.example", "a.example", "b.example"})
        self.assertEqual(
            result,
            "0.0.0.0 a.example\n0.0.0.0 b.example\n",
        )


class BuildTests(unittest.TestCase):
    def test_build_merges_three_source_modes_and_deduplicates(self):
        sources = [
            {"name": "anti-AD", "url": "https://example.test/a", "mode": "domains"},
            {"name": "AdRules", "url": "https://example.test/b", "mode": "domains"},
            {"name": "AWAvenue", "url": "https://example.test/c", "mode": "hosts"},
        ]
        payloads = {
            "https://example.test/a": "a.example\nshared.example\n",
            "https://example.test/b": "b.example\nshared.example\n||not-a-domain.example^\n",
            "https://example.test/c": "0.0.0.0 c.example\n127.0.0.1 shared.example\n",
        }
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source_path = root / "sources.json"
            output_path = root / "hosts.txt"
            source_path.write_text(json.dumps(sources), encoding="utf-8")
            with patch("scripts.build_hosts.download_text", side_effect=lambda url: payloads[url]):
                total, stats = build(source_path, output_path)

            self.assertEqual(total, 4)
            self.assertEqual(stats, [("anti-AD", 2), ("AdRules", 2), ("AWAvenue", 2)])
            body = output_path.read_text(encoding="utf-8")
            self.assertEqual(body.count("0.0.0.0 shared.example"), 1)
            self.assertIn("0.0.0.0 a.example", body)
            self.assertIn("0.0.0.0 b.example", body)
            self.assertIn("0.0.0.0 c.example", body)
            self.assertNotIn("not-a-domain.example", body)


if __name__ == "__main__":
    unittest.main()
