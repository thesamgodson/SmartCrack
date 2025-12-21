"""Hashcat-compatible rule engine for password mutation."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    """Immutable rule descriptor with name, hashcat code, and transform function."""

    name: str
    code: str
    fn: Callable[[str], str]


# ---------------------------------------------------------------------------
# Individual rule functions (pure)
# ---------------------------------------------------------------------------


def _lowercase(word: str) -> str:
    return word.lower()


def _uppercase(word: str) -> str:
    return word.upper()


def _capitalize(word: str) -> str:
    return word.capitalize()


def _toggle_case(word: str) -> str:
    return word.swapcase()


def _reverse(word: str) -> str:
    return word[::-1]


def _duplicate(word: str) -> str:
    return word + word


def _append_1(word: str) -> str:
    return word + "1"


def _append_123(word: str) -> str:
    return word + "123"


def _append_exclaim(word: str) -> str:
    return word + "!"


def _append_at(word: str) -> str:
    return word + "@"


def _prepend_1(word: str) -> str:
    return "1" + word


def _leet_basic(word: str) -> str:
    return word.translate(str.maketrans("aeio", "4310"))


def _leet_full(word: str) -> str:
    return word.translate(str.maketrans("aeioAEIOst", "@3!0@3!0$7"))


def _capitalize_append_1(word: str) -> str:
    return word.capitalize() + "1"


def _capitalize_append_2024(word: str) -> str:
    return word.capitalize() + "2024"


def _capitalize_append_2023(word: str) -> str:
    return word.capitalize() + "2023"


def _capitalize_append_2025(word: str) -> str:
    return word.capitalize() + "2025"


def _first3(word: str) -> str:
    return word[:3]


def _delete_last(word: str) -> str:
    return word[:-1]


def _rotate_left(word: str) -> str:
    if not word:
        return word
    return word[1:] + word[0]


def _rotate_right(word: str) -> str:
    if not word:
        return word
    return word[-1] + word[:-1]


def _toggle_at_0(word: str) -> str:
    if not word:
        return word
    first = word[0].upper() if word[0].islower() else word[0].lower()
    return first + word[1:]


# ---------------------------------------------------------------------------
# Rule instances
# ---------------------------------------------------------------------------

RULE_LOWERCASE = Rule("lowercase", "l", _lowercase)
RULE_UPPERCASE = Rule("uppercase", "u", _uppercase)
RULE_CAPITALIZE = Rule("capitalize", "c", _capitalize)
RULE_TOGGLE_CASE = Rule("toggle_case", "t", _toggle_case)
RULE_REVERSE = Rule("reverse", "r", _reverse)
RULE_DUPLICATE = Rule("duplicate", "d", _duplicate)
RULE_APPEND_1 = Rule("append_1", "$1", _append_1)
RULE_APPEND_123 = Rule("append_123", "$123", _append_123)
RULE_APPEND_EXCLAIM = Rule("append_exclaim", "$!", _append_exclaim)
RULE_APPEND_AT = Rule("append_at", "$@", _append_at)
RULE_PREPEND_1 = Rule("prepend_1", "^1", _prepend_1)
RULE_LEET_BASIC = Rule("leet_basic", "sa4se3si1so0", _leet_basic)
RULE_LEET_FULL = Rule("leet_full", "sa@se3si!so0ss$st7", _leet_full)
RULE_CAP_APPEND_1 = Rule("capitalize_append_1", "c$1", _capitalize_append_1)
RULE_CAP_APPEND_2024 = Rule("capitalize_append_year_2024", "c$2024", _capitalize_append_2024)
RULE_CAP_APPEND_2023 = Rule("capitalize_append_year_2023", "c$2023", _capitalize_append_2023)
RULE_CAP_APPEND_2025 = Rule("capitalize_append_year_2025", "c$2025", _capitalize_append_2025)
RULE_FIRST3 = Rule("first3", "[0:3]", _first3)
RULE_DELETE_LAST = Rule("delete_last", "]", _delete_last)
RULE_ROTATE_LEFT = Rule("rotate_left", "L", _rotate_left)
RULE_ROTATE_RIGHT = Rule("rotate_right", "R", _rotate_right)
RULE_TOGGLE_AT_0 = Rule("toggle_at_0", "T0", _toggle_at_0)

# ---------------------------------------------------------------------------
# Presets
# ---------------------------------------------------------------------------

QUICK_RULES: tuple[Rule, ...] = (
    RULE_LOWERCASE,
    RULE_UPPERCASE,
    RULE_CAPITALIZE,
    RULE_TOGGLE_CASE,
    RULE_REVERSE,
    RULE_DUPLICATE,
    RULE_APPEND_1,
    RULE_APPEND_EXCLAIM,
    RULE_LEET_BASIC,
    RULE_CAP_APPEND_1,
)

THOROUGH_RULES: tuple[Rule, ...] = (
    RULE_LOWERCASE,
    RULE_UPPERCASE,
    RULE_CAPITALIZE,
    RULE_TOGGLE_CASE,
    RULE_REVERSE,
    RULE_DUPLICATE,
    RULE_APPEND_1,
    RULE_APPEND_123,
    RULE_APPEND_EXCLAIM,
    RULE_APPEND_AT,
    RULE_PREPEND_1,
    RULE_LEET_BASIC,
    RULE_LEET_FULL,
    RULE_CAP_APPEND_1,
    RULE_CAP_APPEND_2024,
    RULE_CAP_APPEND_2023,
    RULE_CAP_APPEND_2025,
    RULE_FIRST3,
    RULE_DELETE_LAST,
    RULE_ROTATE_LEFT,
    RULE_ROTATE_RIGHT,
    RULE_TOGGLE_AT_0,
)

# ---------------------------------------------------------------------------
# Generator pipeline
# ---------------------------------------------------------------------------


def apply_rules(word: str, rules: tuple[Rule, ...]) -> Iterator[str]:
    """Yield the original word, then each rule-mutated variant.

    Args:
        word: The candidate word to mutate.
        rules: Ordered collection of rules to apply.

    Yields:
        The original word followed by one mutation per rule.
    """
    yield word
    for rule in rules:
        yield rule.fn(word)


def rule_candidates(
    source: Iterator[str],
    rules: tuple[Rule, ...],
) -> Iterator[str]:
    """Lazily yield every candidate produced by applying rules to each source word.

    For each word from *source*, yields the word itself followed by all
    rule mutations.  The pipeline is fully generator-based — nothing is
    materialised in memory.

    Args:
        source: Iterator of base candidate words.
        rules: Rules to apply to every word.

    Yields:
        Original words interleaved with their mutations.
    """
    for word in source:
        yield from apply_rules(word, rules)
