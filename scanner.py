import re

aws_pattern = r"AKIA[A-Z0-9]{16,}"

with open("test_secrets.txt", "r") as f:
    for number, line in enumerate(f, start=1):
        match = re.search(aws_pattern, line)
        if match:
            print(f"[!] Possible AWS key found on line {number}: {match.group()}")
        else:
            print(f"{number}: {line.strip()}")