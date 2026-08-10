import os
import re

patterns = [
    ("AWS key", r"AKIA[A-Z0-9]{16,}"),
    ("GitHub token", r"ghp_[A-Za-z0-9]{16,}"),
    ("Private Key", r"-----BEGIN PRIVATE KEY-----"),
]

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
                        print(f"[!] Possible {label} in {filepath} (line {number}): {match.group()}")