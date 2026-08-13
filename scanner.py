
import os
import re
import sys

PLACEHOLDER_VALUES = {
    "changeme", "your_password_here", "password", "example",
    "xxxx", "placeholder", "todo", "redacted", "test", "1234"
}

patterns = [
    ("AWS key", r"AKIA[A-Z0-9]{16,}"),
    ("GitHub token", r"ghp_[A-Za-z0-9]{16,}"),
    ("Private Key", r"-----BEGIN PRIVATE KEY-----"),
    ("Hardcoded Password", r"(?i)(password|passwd|pwd|secret)\s*=\s*[\"'](.+)[\"']"),
]

found_secrets = False
for root, dirs, files in os.walk("."):
    if ".git" in dirs:
        dirs.remove(".git")
    for filename in files:
        if filename == "scanner.py":
            continue
        filepath = os.path.join(root, filename)
        with open(filepath, "r") as f:
            for number, line in enumerate(f, start=1):
                for label, pattern in patterns:
                    match = re.search(pattern, line)
                    if match:
                        if label == "Hardcoded Password":
                            value = match.group(2).lower()
                            if value in PLACEHOLDER_VALUES:
                                continue
                        print(f"[!] Possible {label} in {filepath} (line {number}): {match.group()}")
                        found_secrets = True
if found_secrets:
    print("\n[!] Secrets detected — push blocked.")
    sys.exit(1)
else:
    sys.exit(0)