import re
import sys
import subprocess
import math
from collections import Counter
from modules.patterns import SECRET_PATTERNS
from modules.secret_context import SECRET_CONTEXT_PATTERN
from modules.secret_variable import SECRET_VARIABLE_PATTERN
from modules.non_secret_context import NEUTRAL_CONTEXT_PATTERN
from modules.whitelist import (
    load_whitelist,
    is_whitelisted,
    whitelist_value,
)

PLACEHOLDER_VALUES = {
    "changeme", "change_me",
    "change-me", "your_password",
    "your_password_here",
    "your_api_key", "your_api_key_here",
    "password",    "passwd",    "example",
    "example_password",    "placeholder",
    "redacted",    "replace_me",
    "replace-me",    "todo","test",
    "testing",    "xxxx",
    "xxxxxxxx",    "1234",
    "123456",    "null",
    "none",    "undefined",
}

ENTROPY_THRESHOLD = 4.0
MIN_LENGTH_FOR_ENTROPY_CHECK = 8

def calculate_entropy(s):
        # Entropy is useful for spotting random-looking strings,
    # but by itself it doesn't mean "secret". UUIDs and hashes
    # can have high entropy too. And it can be risky to single handlely treat every hash/UUID as secret and blocking push
    # a better treatment would treat them as suspicious or for a second revision but not treating as leaked secret
    if not s:
        return 0.0

    s = s.strip()

    if len(s) < 2:
        return 0.0

    counts = Counter(s)
    length = len(s)
    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy

def is_placeholder(value):
    value = value.strip().lower()
    if value in PLACEHOLDER_VALUES:
        return True
    # Things like ${API_KEY}, <PASSWORD> and {{TOKEN}} are
    # usually variable/template placeholders from previosuly declared variables, not real secrets.
    if (
        (value.startswith("${") and value.endswith("}"))
        or (value.startswith("<") and value.endswith(">"))
        or (value.startswith("{{") and value.endswith("}}"))
    ):
        return True

    return False


def is_binary(filepath): #refactor of that binary check previously added.
    try:
        with open(filepath, "rb") as f:
            chunk = f.read(8192)

        return b"\x00" in chunk

    except OSError:
        return True


def show_whitelist_prompt(filepath, line_number, value, entropy):
    print()
    print(
        f"[possible secret found] "
        f"{filepath}:{line_number} > {value}"
    )
    print(
        f"[!] Entropy: {entropy:.2f}"
    )
    print(
        "[!] User Approval Required. "
        "Whitelist this secret? (y/n)"
    )


def get_tracked_files(): #refactor #2 
    result = subprocess.run( ["git", "ls-files"], capture_output=True, text=True )
    if result.returncode != 0:
        print("[ERROR] Could not get Git tracked files.", file=sys.stderr)
        if result.stderr.strip():
            print(result.stderr.strip(), file=sys.stderr)
        return None
    return result.stdout.splitlines()

def ask_user(prompt):
    try:
        if sys.stdin.isatty():
            stream = sys.stdin
            owned = False
        else:
            stream = open("/dev/tty", "r")
            owned = True
    except OSError as exc:
        print("[!] No terminal input available, automatically blocking push", file=sys.stderr)
        return None
    try:
        sys.stderr.write(prompt)
        sys.stderr.flush()
        answer = stream.readline()
    finally:
        if owned:
            stream.close()
    if not answer:
        print("[!] No answer received. rejecting push!", file=sys.stderr)
        return None
    return answer.strip().lower()


def main():
    tracked_files = get_tracked_files()
    if tracked_files is None:
        # 2 means the scanner couldn't complete.
        return 2
    if not tracked_files:
        print("[OK] No Git-tracked files to scan.")
        return 0
    # Used by the entropy fallback to find quoted values.
    string_pattern = re.compile(
        r'''(?:"([^"\r\n]+)"|'([^'\r\n]+)'|`([^`\r\n]+)`)'''
    )
    # Load once and keep the set updated while scanning.
    whitelist = load_whitelist()
    detected_locations = []
    found_secrets = False
    scan_errors = False

    for filepath in tracked_files:
    
        if filepath.endswith("scanner.py"):
            continue
        if filepath.startswith("modules/"): # ignores its own modules and regex patterns
            continue
        if filepath.endswith(".md"):
            continue

        try:
            if is_binary(filepath):
                continue

        except OSError as exc:
            print(
                f"[ERROR] Could not inspect {filepath}: {exc}",
                file=sys.stderr,
            )
            scan_errors = True
            continue

        try:
            with open(
                filepath,
                "r",
                encoding="utf-8",
                errors="ignore",
            ) as f:
                #in here we start the loops for verification.
                for number, line in enumerate(f, start=1):

                    line_has_known_secret = False

                    # -----------------------------------
                    # | Provider pattern identification |
                    # -----------------------------------
                    # Known provider formats don't need entropy to confirm
                    # them. If the format matches, report it immediately.
                    for label, pattern in SECRET_PATTERNS:
                        match = pattern.search(line)

                        if not match:
                            continue

                        print(
                            f"[!] Possible {label} in "
                            f"{filepath} (line {number}): "
                            f"{match.group()}"
                        )

                        found_secrets = True
                        line_has_known_secret = True

                        detected_locations.append(
                            (filepath, number)
                        )

                    # Entropy is only the fallback if the hardcoded patterns are not detected, but as informed high entropy never necessarily means a secret,
                    # but its important to raise a suspicion tho
                    if line_has_known_secret:
                        continue
                    has_secret_context = SECRET_CONTEXT_PATTERN.search(line)
                    has_neutral_context = NEUTRAL_CONTEXT_PATTERN.search(line)
                    
                    if not has_secret_context and not has_neutral_context:
                        continue

                    secret_variable_matches = list(
                        SECRET_VARIABLE_PATTERN.finditer(line)
                    )
                    
                    if secret_variable_matches:
                        candidates = [
                            (match.group(2).strip(), True)
                            for match in secret_variable_matches
                        ]
                    else:
                        candidates = [
                            (
                                next(
                                    (
                                        group
                                        for group in match.groups()
                                        if group is not None
                                    ),
                                    "",
                                ).strip(),
                                False,
                            )
                            for match in string_pattern.finditer(line)
                        ]
                    
                    for value, is_secret_variable in candidates:
                    
                        if len(value) < MIN_LENGTH_FOR_ENTROPY_CHECK:
                            continue
                    
                        if is_placeholder(value):
                            continue
                    
                        if is_whitelisted(value, whitelist):
                            continue
                    
                        entropy = calculate_entropy(value)
                    
                        # Explicit secret assignments do not require high entropy.
                        if not is_secret_variable and entropy < ENTROPY_THRESHOLD:
                            continue
                    
                        show_whitelist_prompt(
                            filepath,
                            number,
                            value,
                            entropy,
                        )
                    
                        while True:
                            answer = ask_user("> ")
                            if answer is None:
                                print()
                                print("[!] No approval received.")
                                print("[!] Push blocked.")
                                return 1
                        
                            if answer in ("y", "yes"):
                                whitelist_value(
                                    value,
                                    whitelist,
                                )
                    
                                print(
                                    "[OK] Secret whitelisted. "
                                    "Continuing scan."
                                )
                                break
                    
                            if answer in ("n", "no"):
                                print()
                                print("[!] Secret rejected.")
                    
                                detected_locations.append(
                                    (filepath, number)
                                )
                    
                                print(
                                    "\n[!] Push blocked - secrets "
                                    "were found on:"
                                )
                    
                                for detected_filepath, detected_line in (
                                    detected_locations
                                ):
                                    print(
                                        f"- {detected_filepath}:"
                                        f"{detected_line}"
                                    )
                    
                                return 1
                    
                            print(
                                "[!] Please answer 'y' or 'n'."
                            )

                        # -----------------------------------
                        # | Last resource, find by entropy  |
                        # -----------------------------------
                        # IDs and hashes can also have high entropy.
                        # However, they can be considered a ''secret'' or not, certain codes will have hardcoded
                        # high entropy numbers like UUID or user ids etc etc.. but i suppose it is best
                        # to raise suspicion aswell, 

                        
                        show_whitelist_prompt(
                            filepath,
                            number,
                            value,
                            entropy,
                        )

                        while True:
                            answer = ask_user("> ")
                            
                            if answer is None:
                                print()
                                print(
                                    "[!] No approval received."
                                )
                                print(
                                    "[!] Push blocked."
                                )
                                return 1
                        
                            if answer in ("y", "yes"):
                                whitelist_value(
                                    value,
                                    whitelist,
                                )

                                print(
                                    "[OK] Secret whitelisted. "
                                    "Continuing scan."
                                )
                                break

                            if answer in ("n", "no"):
                                print()
                                print(
                                    "[!] Secret rejected."
                                )

                                detected_locations.append(
                                    (filepath, number)
                                )

                                print(
                                    "\n[!] Push blocked - secrets "
                                    "were found on:"
                                )

                                for detected_filepath, detected_line in (
                                    detected_locations
                                ):
                                    print(
                                        f"- {detected_filepath}:"
                                        f"{detected_line}"
                                    )

                                return 1

                            print(
                                "[!] Please answer 'y' or 'n'."
                            )

                        continue

        except OSError as exc:
            print(
                f"[ERROR] Could not read {filepath}: {exc}",
                file=sys.stderr,
            )
            scan_errors = True

    if scan_errors:
        print("\n[ERROR] Some files could not be scanned.")
        print("[ERROR] Push blocked because the scan was incomplete.")
        return 2

    if found_secrets:
        print("\n[!] Secrets detected — push blocked.")
        print("[!] Secrets were found on:")

        for filepath, number in detected_locations:
            print(f"- {filepath}:{number}")

        return 1

    print("[OK] No possible secrets detected.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
