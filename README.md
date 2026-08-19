# FeralAgents

This project is a lightweight, beginner-friendly secret scanner that catches hardcoded credentials before they ever leave your machine.

FeralAgents walks through your project files, flags things like AWS keys, GitHub tokens, private key headers, and hardcoded passwords, and can be wired into a Git pre-push hook to **block the push entirely** if anything suspicious is found. That way the secrets never make it to a remote repo in the first place.

## Why

Leaked credentials are one of the most common (and most avoidable) causes of real-world breaches. Most of the time it's not malicious, it can as well be an `.env` value pasted into code, a test API key left in a config file, or a password hardcoded "just for now" and forgotten. FeralAgents is a small, understandable tool built to catch exactly that, before it becomes a `git push`.

## Features
- 🔍 Scans only git-tracked files (via `git ls-files`), not the entire directory — gitignored files (like local test data) are never touched
- 🔑 Detects multiple secret types out of the box:
  - AWS access keys
  - GitHub personal access tokens
  - Private key headers (`-----BEGIN PRIVATE KEY-----`)
  - Hardcoded passwords / secrets (`password = "..."`, `secret = '...'`, etc.)
- Two layers of false-positive filtering:
  - A placeholder list (`changeme`, `your_password_here`, `example`, etc.)
  - **Shannon entropy filtering** — matched strings are scored for randomness, so predictable/fake-looking values (low entropy) are ignored while genuinely random-looking secrets (high entropy) are still flagged
-  Skips markdown files, so documentation examples don't trigger false alarms
-  Exits with a non-zero status code when a secret is found, so it can gate other tools (like Git)
- Includes a working pre-push Git hook that blocks pushes if secrets are detected

## Installation

FeralAgents has no dependencies beyond the Python standard library.

```bash
git clone https://github.com/saharaexecutiveoutcomes/feralagents.git
cd feralagents
```

Requires Python 3.

## Usage

Run the scanner from the root of any project you want to check:

```bash
python3 scanner.py
```

If secrets are found, you'll see output like:

```
[!] Possible AWS key in ./config.py (line 12): AKIAABCDEFGHIJKL1234
[!] Possible Hardcoded Password in ./settings.py (line 4): password = "hunter2"

[!] Secrets detected — push blocked.
```

The scanner exits with code `1` if any secrets are found, and `0` if the project is clean.

## Setting up the pre-push hook

To block pushes automatically whenever a secret is detected, add this to `.git/hooks/pre-push` in your repo and make it executable:

```bash
#!/bin/sh
python3 scanner.py
```

```bash
chmod +x .git/hooks/pre-push
```

Now any `git push` will run the scanner first — if it finds a secret, the push is blocked until the secret is removed.

## A note on entropy filtering

Entropy scoring works best on longer strings (like tokens). For short, key-like strings (~20 characters), fake and real values can score close together, so entropy filtering reduces noise but isn't a perfect signal — it's combined with the placeholder list rather than relied on alone.

## Roadmap

- [ ] Configurable pattern list (via a config file instead of editing `scanner.py` directly)
- [ ] Support for `.env` file scanning with dedicated patterns
- [ ] Allowlist/ignore file for known-safe paths
- [ ] Unit tests (`pytest`) covering detection and false-positive filtering
- [ ] GitHub Actions CI to run tests on every push
- [ ] Packaging as a pip-installable CLI tool

## About

FeralAgents was built as a hands-on learning project made by a student of diplomacy and humanities while transitioning into cybersecurity. Though AI/LLM assisting was used only as a means to learn, the lines were written and tested step by step manually rather than generated wholesale, as a way to actually learn Python and secure coding practices in the process.

The name of the project was in reference to the song Feral Agents by ROME. I deemed it fitting considering the actual purpose of the tool.
