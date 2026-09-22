# Re-Malwack Custom Hosts

A strict `hosts` list built for [Re-Malwack](https://github.com/ZG089/Re-Malwack) from exactly three upstream rule projects:

1. [privacy-protection-tools/anti-AD](https://github.com/privacy-protection-tools/anti-AD) — `anti-ad-domains.txt`
2. [Cats-Team/AdRules](https://github.com/Cats-Team/AdRules) — DNS `domain.txt`
3. [TG-Twilight/AWAvenue-Ads-Rule](https://github.com/TG-Twilight/AWAvenue-Ads-Rule) — official hosts output

## Output

`hosts.txt` is normalized to standard hosts syntax:

```text
0.0.0.0 example.com
:: example.com
```

Each domain has one IPv4 and one IPv6 blocking entry. Counts and safety thresholds refer to unique domains, not output lines. Re-Malwack must preserve IPv6 entries when importing the source for them to take effect.

The builder:

- accepts only bare domains from anti-AD and AdRules DNS output;
- accepts only `0.0.0.0` / `127.0.0.1` / `::` host entries from AWAvenue;
- rejects ABP syntax, URLs, wildcards, IP literals, localhost names and malformed hostnames;
- lowercases, sorts and de-duplicates all domains globally;
- retries transient download failures up to three times, waiting 1, 3 and 9 seconds;
- rejects an update if anti-AD has fewer than 50,000 valid domains, AdRules fewer than 100,000, or AWAvenue fewer than 300;
- preserves the current `hosts.txt` if the new merged total is more than 25% smaller.

All safety checks run before the output file is written, so a failed update leaves the last known-good list unchanged.

## Re-Malwack subscription

Use this URL directly as the Re-Malwack custom hosts source:

```text
https://raw.githubusercontent.com/Night114514/remalwack-custom-hosts/main/hosts.txt
```

## Automatic updates

GitHub Actions runs every day at **16:00 UTC / 00:00 Hong Kong time (UTC+8)**. It can also be run manually from **Actions → Update hosts → Run workflow**.

> GitHub scheduled workflows may occasionally start a few minutes later than the cron time during periods of high load; the configured schedule itself is exactly 00:00 Hong Kong time.

The first successful run creates `hosts.txt`. If the generated list has not changed on later runs, the workflow does not create a commit.

## Local build

Requires Python 3.11+ and no third-party packages.

```bash
python scripts/build_hosts.py
```

Run tests with:

```bash
PYTHONPATH=. python -m unittest discover -s tests -p 'test_*.py' -v
```

## Upstream licensing

The generated `hosts.txt` contains data derived from the upstream projects. Their respective licenses and upstream-source licensing terms continue to apply. In particular, Cats-Team notes that generated artifacts inherit the licenses of their respective upstream rule sources. Review the three upstream repositories before redistributing the generated list publicly.
