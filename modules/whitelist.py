import hashlib
import json
from pathlib import Path

# That shannon entropy in scanner.py is a good idea honestly, but high entropy values can be legitimate hashes, IDs, test values, etc. etc...
# So to prevent false positives all the time, this module adds to a whitelist and ignores it on next scanner run
# We never store the original value in the whitelist but instead a sha256 fingerprint of it, as good security practice.
WHITELIST_FILE = Path(__file__).parent / "whitelist.json"
def encode(value):
    # SHA-256 is used as a fingerprint, not encryption.
    return hashlib.sha256(value.encode("utf-8")).hexdigest()

def load_whitelist():
    # No whitelist means nothing has been approved yet.
    if not WHITELIST_FILE.exists():
        return set()

    try:
        with open(WHITELIST_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)

        # A set gives us fast lookups when checking detected values.
        return set(data.get("values", []))

    except (OSError, json.JSONDecodeError):
        # If the whitelist can't be read, treat it as empty and ask again.
        return set()

def is_whitelisted(value, whitelist=None):
    if whitelist is None:
        whitelist = load_whitelist()

    return encode(value) in whitelist

def whitelist_value(value, whitelist=None):
    if whitelist is None:
        whitelist = load_whitelist()

    fingerprint = encode(value)

    if fingerprint in whitelist:
        return
     # Keep the in-memory whitelist updated so repeated values in the
      # same scan are also skipped.
    whitelist.add(fingerprint)

    WHITELIST_FILE.parent.mkdir(parents=True, exist_ok=True)
    # Sorting keeps whitelist.json deterministic and easier to maintain.
    with open(WHITELIST_FILE, "w", encoding="utf-8") as f:
        json.dump(
            {  "values": sorted(whitelist) },
            f, indent=4
        )
