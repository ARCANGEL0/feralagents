import re
# Things like IDs and hashes
NEUTRAL_CONTEXT_PATTERN = re.compile(
    r"""(?ix)\b(
        id|
        user[_-]?id|
        account[_-]?id|
        request[_-]?id|
        object[_-]?id|
        uuid|
        guid|
        hash|
        sha|
        sha1|
        sha224|
        sha256|
        sha384|
        sha512|
        md5|
        checksum|
        digest|
        etag|
        commit|
        revision
    )\b"""
)
