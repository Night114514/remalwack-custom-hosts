#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
import time
import urllib.request
from pathlib import Path

USER_AGENT = "remalwack-custom-hosts/1.0 (+GitHub Actions)"
BLOCK_IPS = {"0.0.0.0", "127.0.0.1"}
LOCAL_NAMES = {"localhost", "localhost.localdomain", "broadcasthost", "ip6-localhost", "ip6-loopback"}
LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)
RETRY_DELAYS = (1, 3, 9)
MAX_TOTAL_DROP_PERCENT = 25


def normalize_domain(value: str) -> str | None:
    domain = value.strip().lower().rstrip(".")
    if not domain or domain in LOCAL_NAMES or len(domain) > 253 or "." not in domain:
        return None
    if any(ch in domain for ch in ("/", "\\", "*", "^", "|", "@", "#", "?", ":")):
        return None
    try:
        ipaddress.ip_address(domain)
        return None
    except ValueError:
        pass
    labels = domain.split(".")
    if any(not LABEL_RE.fullmatch(label) for label in labels):
        return None
    return domain


def extract_domains(text: str, mode: str) -> set[str]:
    if mode not in {"domains", "hosts"}:
        raise ValueError(f"Unsupported source mode: {mode}")

    result: set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "!")):
            continue

        if mode == "domains":
            if any(c.isspace() for c in line):
                continue
            domain = normalize_domain(line)
            if domain:
                result.add(domain)
            continue

        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2 or parts[0] not in BLOCK_IPS:
            continue
        for candidate in parts[1:]:
            domain = normalize_domain(candidate)
            if domain:
                result.add(domain)

    return result


def render_hosts(domains: set[str]) -> str:
    return "".join(f"0.0.0.0 {domain}\n" for domain in sorted(domains))


def download_text(url: str, timeout: int = 45) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    for attempt in range(len(RETRY_DELAYS) + 1):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                charset = response.headers.get_content_charset() or "utf-8"
                return response.read().decode(charset, errors="strict")
        except OSError:
            if attempt == len(RETRY_DELAYS):
                raise
            time.sleep(RETRY_DELAYS[attempt])

    raise AssertionError("unreachable")


def load_sources(path: Path) -> list[dict[str, str | int]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list) or not data:
        raise ValueError("sources.json must contain a non-empty JSON array")
    for item in data:
        if not isinstance(item, dict) or not {"name", "url", "mode", "min_domains"} <= item.keys():
            raise ValueError("Each source requires name, url, mode and min_domains")
        if item["mode"] not in {"domains", "hosts"}:
            raise ValueError(f"Unsupported mode for {item['name']}: {item['mode']}")
        if not isinstance(item["min_domains"], int) or isinstance(item["min_domains"], bool) or item["min_domains"] < 1:
            raise ValueError(f"min_domains for {item['name']} must be a positive integer")
    return data


def build(sources_path: Path, output_path: Path) -> tuple[int, list[tuple[str, int]]]:
    sources = load_sources(sources_path)
    merged: set[str] = set()
    stats: list[tuple[str, int]] = []

    for source in sources:
        text = download_text(str(source["url"]))
        domains = extract_domains(text, str(source["mode"]))
        minimum = int(source["min_domains"])
        if len(domains) < minimum:
            raise RuntimeError(
                f"Source {source['name']} produced {len(domains):,} valid domains; "
                f"minimum is {minimum:,}"
            )
        stats.append((source["name"], len(domains)))
        merged.update(domains)

    if output_path.exists():
        previous_total = len(extract_domains(output_path.read_text(encoding="utf-8"), "hosts"))
        current_total = len(merged)
        if previous_total and current_total * 100 < previous_total * (100 - MAX_TOTAL_DROP_PERCENT):
            decrease = (previous_total - current_total) / previous_total * 100
            raise RuntimeError(
                f"Merged domain count decreased by {decrease:.1f}% "
                f"({previous_total:,} -> {current_total:,}), exceeding "
                f"{MAX_TOTAL_DROP_PERCENT}% safety limit"
            )

    header = [
        "# Re-Malwack custom hosts",
        "# Generated from exactly these upstream projects:",
    ]
    for source in sources:
        header.append(f"# - {source['name']}: {source['url']}")
    header.extend([
        "#",
        "# Format: 0.0.0.0 domain",
        "# Duplicate domains are removed and output is sorted.",
        "",
    ])
    output = "\n".join(header) + render_hosts(merged)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(output, encoding="utf-8", newline="\n")
    return len(merged), stats


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a strict hosts list for Re-Malwack")
    parser.add_argument("--sources", default="sources.json", type=Path)
    parser.add_argument("--output", default="hosts.txt", type=Path)
    args = parser.parse_args()

    try:
        total, stats = build(args.sources, args.output)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    for name, count in stats:
        print(f"{name}: {count:,} valid domains")
    print(f"Merged unique domains: {total:,}")
    print(f"Output: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
