import sys
sys.path.insert(0, '.')
from scanner import calculate_entropy


def test_empty_string_has_zero_entropy():
    assert calculate_entropy("") == 0


def test_repeated_characters_have_zero_entropy():
    assert calculate_entropy("aaaa") == 0


def test_varied_characters_have_higher_entropy():
    repeated = calculate_entropy("aaaa")
    varied = calculate_entropy("abcd")
    assert varied > repeated


def test_realistic_secret_clears_threshold():
    from scanner import ENTROPY_THRESHOLD
    token = "ghp_8f3kD9zQ1mLpX7vB2nR4tW6yE0sA5cH"
    assert calculate_entropy(token) > ENTROPY_THRESHOLD


def test_placeholder_stays_below_threshold():
    from scanner import ENTROPY_THRESHOLD
    placeholder = "changeme"
    assert calculate_entropy(placeholder) < ENTROPY_THRESHOLD