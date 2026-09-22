# Re-Malwack Custom Hosts

A strict `hosts` list built for [Re-Malwack](https://github.com/ZG089/Re-Malwack) from exactly three upstream rule projects:

1. [privacy-protection-tools/anti-AD](https://github.com/privacy-protection-tools/anti-AD) — `anti-ad-domains.txt`
2. [Cats-Team/AdRules](https://github.com/Cats-Team/AdRules) — DNS `domain.txt`
3. [TG-Twilight/AWAvenue-Ads-Rule](https://github.com/TG-Twilight/AWAvenue-Ads-Rule) — official hosts output

## Output

`hosts.txt` is normalized to standard hosts syntax:

```text
0.0.0.0 example.com
```

The builder:

- accepts only bare domains from anti-AD and AdRules DNS output;
- accepts only `0.0.0.0` / `127.0.0.1` host entries from AWAvenue;
- rejects ABP syntax, URLs, wildcards, IP literals, localhost names and malformed hostnames;
- lowercases, sorts and de-duplicates all domains globally;
- fails the build if any configured upstream unexpectedly produces zero valid domains.

## Re-Malwack subscription

After you create your GitHub repository and push these files, use this URL as the custom hosts source:

```text
https://raw.githubusercontent.com/<YOUR_GITHUB_USERNAME>/<YOUR_REPO_NAME>/main/hosts.txt
```

For example, if the repository is `username/remalwack-custom-hosts`:

```text
https://raw.githubusercontent.com/username/remalwack-custom-hosts/main/hosts.txt
```

## Automatic updates

GitHub Actions runs automatically after the initial push of the project files, then every day at **02:15 UTC / 10:15 Hong Kong time (UTC+8)**. It can also be run manually from **Actions → Update hosts → Run workflow**.

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
