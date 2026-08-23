import re
# Used by the entropy check to give  values some context.
SECRET_CONTEXT_PATTERN = re.compile(
    r"""(?ix)\b(
        password|
        passwd|
        pwd|
        passphrase|
        secret|
        api[_-]?key|
        apikey|
        access[_-]?key|
        secret[_-]?key|
        auth[_-]?token|
        bearer[_-]?token|
        client[_-]?secret|
        client[_-]?key|
        private[_-]?key|
        signing[_-]?key|
        encryption[_-]?key|
        credential|
        credentials|
        token
    )\b"""
)
