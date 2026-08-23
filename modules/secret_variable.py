import re

# Detects values assigned to variables/fields that strongly indicate secrets. leik password = 12345.
SECRET_VARIABLE_PATTERN = re.compile(
    r"""(?ix)
    \b(
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
    )\b
    \s*(?:=|:)
    \s*
    ["'`]?
    ([^\s"'`,;]+)
    ["'`]?
    """
)
