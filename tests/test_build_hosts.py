import json
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import Mock, patch

from scripts.build_hosts import build, download_text, extract_domains, render_hosts


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
        self.assertEqual(extract_domains(text, "domains"), {"example.com", "ads.example.com"})

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
        self.assertEqual(extract_domains(text, "domains"), {"xn--fiqs8s.example"})


class RenderHostsTests(unittest.TestCase):
    def test_dual_stack_round_trip_counts_each_domain_once(self):
        domains = {"a.example", "b.example"}
        self.assertEqual(extract_domains(render_hosts(domains), "hosts"), domains)
        self.assertEqual(extract_domains(":: ipv6.example\n", "hosts"), {"ipv6.example"})

    def test_render_hosts_deduplicates_and_sorts(self):
        result = render_hosts({"b.example", "a.example", "b.example"})
        self.assertEqual(result, "0.0.0.0 a.example\n:: a.example\n0.0.0.0 b.example\n:: b.example\n")


class DownloadTests(unittest.TestCase):
    @patch("scripts.build_hosts.time.sleep")
    @patch("scripts.build_hosts.urllib.request.urlopen")
    def test_download_retries_three_times_before_succeeding(self, urlopen, sleep):
        response = Mock()
        response.headers.get_content_charset.return_value = "utf-8"
        response.read.return_value = b"example.com\n"
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        urlopen.side_effect = [
            urllib.error.URLError("temporary 1"),
            urllib.error.URLError("temporary 2"),
            urllib.error.URLError("temporary 3"),
            response,
        ]

        self.assertEqual(download_text("https://example.test/list"), "example.com\n")
        self.assertEqual(urlopen.call_count, 4)
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [1, 3, 9])


class BuildTests(unittest.TestCase):
    def make_sources(self):
        return [
            {"name": "anti-AD", "url": "https://example.test/a", "mode": "domains", "min_domains": 1},
            {"name": "AdRules", "url": "https://example.test/b", "mode": "domains", "min_domains": 1},
            {"name": "AWAvenue", "url": "https://example.test/c", "mode": "hosts", "min_domains": 1},
        ]

    def test_build_merges_three_source_modes_and_deduplicates(self):
        sources = self.make_sources()
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

    def test_build_rejects_source_below_configured_minimum(self):
        sources = self.make_sources()
        sources[0]["min_domains"] = 3
        payloads = {
            "https://example.test/a": "a.example\nb.example\n",
            "https://example.test/b": "b.example\n",
            "https://example.test/c": "0.0.0.0 c.example\n",
        }
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source_path = root / "sources.json"
            output_path = root / "hosts.txt"
            source_path.write_text(json.dumps(sources), encoding="utf-8")
            with patch("scripts.build_hosts.download_text", side_effect=lambda url: payloads[url]):
                with self.assertRaisesRegex(RuntimeError, "anti-AD.*2.*minimum.*3"):
                    build(source_path, output_path)
            self.assertFalse(output_path.exists())

    def test_build_preserves_existing_output_when_total_drops_more_than_25_percent(self):
        sources = self.make_sources()
        payloads = {
            "https://example.test/a": "a.example\n",
            "https://example.test/b": "b.example\n",
            "https://example.test/c": "0.0.0.0 c.example\n",
        }
        existing = "".join(f"0.0.0.0 old-{index}.example\n" for index in range(5))
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source_path = root / "sources.json"
            output_path = root / "hosts.txt"
            source_path.write_text(json.dumps(sources), encoding="utf-8")
            output_path.write_text(existing, encoding="utf-8")
            with patch("scripts.build_hosts.download_text", side_effect=lambda url: payloads[url]):
                with self.assertRaisesRegex(RuntimeError, "decreased.*40.0%.*25%"):
                    build(source_path, output_path)
            self.assertEqual(output_path.read_text(encoding="utf-8"), existing)


if __name__ == "__main__":
    unittest.main()
