import os
import re

aws_pattern = r"AKIA[A-Z0-9]{16,}"
github_pattern = r"ghp_[A-Za-z0-9]{16,}"

for root, dirs, files in os.walk("."):
    if ".git" in dirs:
        dirs.remove(".git")
    for filename in files:
        filepath = os.path.join(root, filename)
        with open(filepath, "r") as f:
            for number, line in enumerate(f, start=1):
                aws_match = re.search(aws_pattern, line)
                github_match = re.search(github_pattern, line)

                if aws_match:
                    print(f"[!] Possible AWS key in {filepath} (line {number}): {aws_match.group()}")
                elif github_match:
                    print(f"[!] Possible GitHub token in {filepath} (line {number}): {github_match.group()}")