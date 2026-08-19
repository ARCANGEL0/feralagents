import re
import sys
import subprocess
import math
from collections import Counter

PLACEHOLDER_VALUES = {
    "changeme", "your_password_here", "password", "example",
    "xxxx", "placeholder", "todo", "redacted", "test", "1234"
}

ENTROPY_THRESHOLD = 4.0

def calculate_entropy(s):
    if not s:
        return 0

    counts = Counter(s)
    length = len(s)
    entropy = 0

    for char, count in counts.items():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy

patterns = [
    ("AWS key", r"AKIA[A-Z0-9]{16,}"),
    ("GitHub token", r"ghp_[A-Za-z0-9]{16,}"),
    ("Private Key", r"-----BEGIN PRIVATE KEY-----"),
    ("Hardcoded Password", r"(?i)(password|passwd|pwd|secret)\s*=\s*[\"'](.+)[\"']"),
]

result = subprocess.run(["git", "ls-files"], capture_output=True, text=True)
tracked_files = result.stdout.splitlines()
found_secrets = False

for filepath in tracked_files:
    if filepath.endswith("scanner.py") or filepath.endswith(".md"):
        continue

    with open(filepath, "r") as f:
        for number, line in enumerate(f, start=1):
            for label, pattern in patterns:
                match = re.search(pattern, line)
                if match:
                    if label == "Hardcoded Password":
                        value = match.group(2).lower()
                        if value in PLACEHOLDER_VALUES:
                            continue

                    entropy = calculate_entropy(match.group())
                    if entropy <= ENTROPY_THRESHOLD:
                        continue

                    print(f"[!] Possible {label} in {filepath} (line {number}): {match.group()}")
                    found_secrets = True

if found_secrets:
    print("\n[!] Secrets detected — push blocked.")
    sys.exit(1)
else:
    sys.exit(0)