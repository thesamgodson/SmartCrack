"""Tests for the hashcat-compatible rule engine."""

from __future__ import annotations

import types
from collections.abc import Iterator

import pytest

from hashcrack.rules import (
    QUICK_RULES,
    RULE_APPEND_1,
    RULE_APPEND_123,
    RULE_APPEND_AT,
    RULE_APPEND_EXCLAIM,
    RULE_CAP_APPEND_1,
    RULE_CAP_APPEND_2023,
    RULE_CAP_APPEND_2024,
    RULE_CAP_APPEND_2025,
    RULE_CAPITALIZE,
    RULE_DELETE_LAST,
    RULE_DUPLICATE,
    RULE_FIRST3,
    RULE_LEET_BASIC,
    RULE_LEET_FULL,
    RULE_LOWERCASE,
    RULE_PREPEND_1,
    RULE_REVERSE,
    RULE_ROTATE_LEFT,
    RULE_ROTATE_RIGHT,
    RULE_TOGGLE_AT_0,
    RULE_TOGGLE_CASE,
    RULE_UPPERCASE,
    THOROUGH_RULES,
    Rule,
    apply_rules,
    rule_candidates,
)


# ---------------------------------------------------------------------------
# Individual rule transforms
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestIndividualRules:
    def test_lowercase(self) -> None:
        assert RULE_LOWERCASE.fn("PASSWORD") == "password"
        assert RULE_LOWERCASE.fn("Hello") == "hello"

    def test_uppercase(self) -> None:
        assert RULE_UPPERCASE.fn("password") == "PASSWORD"
        assert RULE_UPPERCASE.fn("Hello") == "HELLO"

    def test_capitalize(self) -> None:
        assert RULE_CAPITALIZE.fn("password") == "Password"
        assert RULE_CAPITALIZE.fn("PASSWORD") == "Password"

    def test_toggle_case(self) -> None:
        assert RULE_TOGGLE_CASE.fn("Hello") == "hELLO"
        assert RULE_TOGGLE_CASE.fn("hELLO") == "Hello"

    def test_reverse(self) -> None:
        assert RULE_REVERSE.fn("abc") == "cba"
        assert RULE_REVERSE.fn("password") == "drowssap"

    def test_duplicate(self) -> None:
        assert RULE_DUPLICATE.fn("abc") == "abcabc"
        assert RULE_DUPLICATE.fn("pass") == "passpass"

    def test_append_1(self) -> None:
        assert RULE_APPEND_1.fn("password") == "password1"

    def test_append_123(self) -> None:
        assert RULE_APPEND_123.fn("password") == "password123"

    def test_append_exclaim(self) -> None:
        assert RULE_APPEND_EXCLAIM.fn("password") == "password!"

    def test_append_at(self) -> None:
        assert RULE_APPEND_AT.fn("password") == "password@"

    def test_prepend_1(self) -> None:
        assert RULE_PREPEND_1.fn("password") == "1password"

    def test_leet_basic(self) -> None:
        assert RULE_LEET_BASIC.fn("apple") == "4ppl3"
        assert RULE_LEET_BASIC.fn("admin") == "4dm1n"

    def test_leet_full(self) -> None:
        result = RULE_LEET_FULL.fn("password")
        assert "@" in result or "3" in result or "0" in result

    def test_capitalize_append_1(self) -> None:
        assert RULE_CAP_APPEND_1.fn("password") == "Password1"

    def test_capitalize_append_2024(self) -> None:
        assert RULE_CAP_APPEND_2024.fn("spring") == "Spring2024"

    def test_capitalize_append_2023(self) -> None:
        assert RULE_CAP_APPEND_2023.fn("spring") == "Spring2023"

    def test_capitalize_append_2025(self) -> None:
        assert RULE_CAP_APPEND_2025.fn("spring") == "Spring2025"

    def test_first3(self) -> None:
        assert RULE_FIRST3.fn("password") == "pas"
        assert RULE_FIRST3.fn("ab") == "ab"  # shorter than 3

    def test_delete_last(self) -> None:
        assert RULE_DELETE_LAST.fn("password") == "passwor"
        assert RULE_DELETE_LAST.fn("ab") == "a"

    def test_rotate_left(self) -> None:
        assert RULE_ROTATE_LEFT.fn("abcd") == "bcda"

    def test_rotate_right(self) -> None:
        assert RULE_ROTATE_RIGHT.fn("abcd") == "dabc"

    def test_toggle_at_0(self) -> None:
        assert RULE_TOGGLE_AT_0.fn("password") == "Password"
        assert RULE_TOGGLE_AT_0.fn("Password") == "password"


# ---------------------------------------------------------------------------
# apply_rules
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestApplyRules:
    def test_yields_original_first(self) -> None:
        results = list(apply_rules("hello", QUICK_RULES))
        assert results[0] == "hello"

    def test_yields_original_plus_one_per_rule(self) -> None:
        rules = (RULE_LOWERCASE, RULE_UPPERCASE)
        results = list(apply_rules("Hello", rules))
        # original + 2 mutations
        assert len(results) == 3
        assert results[0] == "Hello"
        assert results[1] == "hello"
        assert results[2] == "HELLO"

    def test_empty_rules_yields_only_original(self) -> None:
        results = list(apply_rules("word", ()))
        assert results == ["word"]

    def test_returns_iterator(self) -> None:
        result = apply_rules("word", QUICK_RULES)
        assert hasattr(result, "__iter__") and hasattr(result, "__next__")


# ---------------------------------------------------------------------------
# rule_candidates
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRuleCandidates:
    def test_wraps_source_generator(self) -> None:
        source: Iterator[str] = iter(["apple", "banana"])
        rules = (RULE_UPPERCASE,)
        results = list(rule_candidates(source, rules))
        # apple, APPLE, banana, BANANA
        assert results == ["apple", "APPLE", "banana", "BANANA"]

    def test_empty_source(self) -> None:
        results = list(rule_candidates(iter([]), QUICK_RULES))
        assert results == []

    def test_empty_rules_yields_originals_only(self) -> None:
        source = iter(["one", "two"])
        results = list(rule_candidates(source, ()))
        assert results == ["one", "two"]

    def test_returns_generator(self) -> None:
        gen = rule_candidates(iter(["word"]), QUICK_RULES)
        assert isinstance(gen, types.GeneratorType)

    def test_lazy_does_not_materialise(self) -> None:
        """Consuming 0 items from the pipeline should not exhaust the source."""
        consumed: list[str] = []

        def tracking_source() -> Iterator[str]:
            for w in ["alpha", "beta", "gamma"]:
                consumed.append(w)
                yield w

        gen = rule_candidates(tracking_source(), QUICK_RULES)
        # Advance only one step — should only pull the first word from source
        next(gen)
        assert consumed == ["alpha"]


# ---------------------------------------------------------------------------
# Presets
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestPresets:
    def test_quick_rules_is_tuple(self) -> None:
        assert isinstance(QUICK_RULES, tuple)

    def test_quick_rules_has_ten_entries(self) -> None:
        assert len(QUICK_RULES) == 10

    def test_thorough_rules_is_tuple(self) -> None:
        assert isinstance(THOROUGH_RULES, tuple)

    def test_thorough_rules_has_twenty_two_entries(self) -> None:
        # 20 base rules + 2 extra year variants (2023, 2025) split from one spec entry
        assert len(THOROUGH_RULES) == 22

    def test_all_entries_are_rule_instances(self) -> None:
        for rule in THOROUGH_RULES:
            assert isinstance(rule, Rule)

    def test_quick_rules_subset_of_thorough(self) -> None:
        thorough_names = {r.name for r in THOROUGH_RULES}
        for rule in QUICK_RULES:
            assert rule.name in thorough_names


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestEdgeCases:
    def test_empty_word_rotate_left(self) -> None:
        assert RULE_ROTATE_LEFT.fn("") == ""

    def test_empty_word_rotate_right(self) -> None:
        assert RULE_ROTATE_RIGHT.fn("") == ""

    def test_empty_word_toggle_at_0(self) -> None:
        assert RULE_TOGGLE_AT_0.fn("") == ""

    def test_empty_word_apply_rules(self) -> None:
        results = list(apply_rules("", QUICK_RULES))
        # original empty string should be first
        assert results[0] == ""

    def test_single_char_rotate_left(self) -> None:
        assert RULE_ROTATE_LEFT.fn("a") == "a"

    def test_single_char_rotate_right(self) -> None:
        assert RULE_ROTATE_RIGHT.fn("a") == "a"

    def test_single_char_delete_last(self) -> None:
        assert RULE_DELETE_LAST.fn("a") == ""


# ---------------------------------------------------------------------------
# Unicode
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestUnicodeHandling:
    def test_uppercase_unicode(self) -> None:
        assert RULE_UPPERCASE.fn("héllo") == "HÉLLO"

    def test_lowercase_unicode(self) -> None:
        assert RULE_LOWERCASE.fn("HÉLLO") == "héllo"

    def test_reverse_unicode(self) -> None:
        assert RULE_REVERSE.fn("café") == "éfac"

    def test_append_unicode(self) -> None:
        assert RULE_APPEND_1.fn("café") == "café1"

    def test_rule_candidates_unicode(self) -> None:
        results = list(rule_candidates(iter(["über"]), (RULE_UPPERCASE,)))
        assert "über" in results
        assert "ÜBER" in results
