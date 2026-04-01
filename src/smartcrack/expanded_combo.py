"""Expanded combo engine — generates candidates from LLM-expanded profile knowledge.

Exhaustive: every token, every number, every separator, every combination.
Every pattern from breach research. No arbitrary limits.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from smartcrack.models import ExpandedProfile
from smartcrack.password_patterns import (
    PIN_PATTERNS,
    doubling_candidates,
    keyboard_walk_candidates,
    padding_candidates,
    position_leet_candidates,
    sandwich_candidates,
    year_range_numbers,
)

_LEET_MAP = {"a": "@", "e": "3", "o": "0", "s": "$", "i": "1", "t": "7"}
_LEET_MAP_ALT = {"a": "4", "e": "3", "o": "0", "s": "5", "i": "!", "t": "7"}
_VOWELS = re.compile(r"[aeiou]", re.IGNORECASE)

# Full separator set from breach research
_ALL_SEPARATORS = ("", "_", ".", "-", "@", "!", "#")


def generate_from_expanded(expanded: ExpandedProfile) -> Iterator[str]:
    """Generate password candidates from an LLM-expanded profile. Exhaustive."""
    seen: set[str] = set()
    mp = expanded.mutation_profile

    all_names = expanded.names + expanded.nicknames + expanded.phonetic_variants
    all_keywords = (
        expanded.keywords_direct + expanded.keywords_cultural
        + expanded.locale_slang + expanded.keywords_generational
    )
    all_tokens = all_names + all_keywords

    # Explode numbers + full date formats + year range
    birth_year = None
    if expanded.dates:
        for d in expanded.dates:
            if len(d) == 4 and d.isdigit():
                birth_year = int(d)
                break
    raw_numbers = expanded.dates + expanded.related_numbers
    # Date fragments with letters (jan1990, March90) go into tokens, not numbers
    date_tokens = tuple(d for d in raw_numbers if not d.isdigit() and len(d) >= 3)
    numeric_dates = tuple(d for d in raw_numbers if d.isdigit() or len(d) < 3)
    all_numbers = _explode_numbers(numeric_dates + year_range_numbers(birth_year))
    all_tokens = all_tokens + date_tokens

    # Merge separators: profile preference + full breach set
    raw_seps = mp.separator_preference or ()
    seps = tuple(dict.fromkeys(("",) + tuple(raw_seps) + _ALL_SEPARATORS))

    def _emit(candidate: str) -> Iterator[str]:
        if candidate and candidate not in seen:
            seen.add(candidate)
            yield candidate

    # =====================================================================
    # Phase 0 — high confidence seeds (LLM's best guesses, first)
    # =====================================================================
    for seed in expanded.high_confidence_seeds:
        yield from _emit(seed)

    # =====================================================================
    # Phase 1 — every token, every case variant
    # =====================================================================
    for token in all_tokens:
        for v in _case_variants(token):
            if len(v) >= 4:
                yield from _emit(v)

    # =====================================================================
    # Phase 2 — every token x every number x every separator (both orders)
    # =====================================================================
    for token in all_tokens:
        for num in all_numbers:
            for sep in seps:
                for v in _case_variants(token):
                    yield from _emit(f"{v}{sep}{num}")
                    yield from _emit(f"{num}{sep}{v}")

    # =====================================================================
    # Phase 3a — every name x every keyword x every separator (both orders)
    # =====================================================================
    for name in all_names:
        for kw in all_keywords:
            for sep in seps:
                for nv in _case_variants(name):
                    for kv in _case_variants(kw):
                        yield from _emit(f"{nv}{sep}{kv}")
                        yield from _emit(f"{kv}{sep}{nv}")

    # =====================================================================
    # Phase 3b — every keyword x every other keyword x every separator
    # =====================================================================
    for i, kw1 in enumerate(all_keywords):
        for kw2 in all_keywords[i + 1:]:
            for sep in seps:
                for v1 in _case_variants(kw1):
                    for v2 in _case_variants(kw2):
                        yield from _emit(f"{v1}{sep}{v2}")
                        yield from _emit(f"{v2}{sep}{v1}")

    # =====================================================================
    # Phase 4 — 3-token combos: name + keyword + number
    # =====================================================================
    for name in all_names:
        for kw in all_keywords:
            for num in all_numbers:
                for nv in (name, name.capitalize()):
                    for kv in (kw, kw.capitalize()):
                        yield from _emit(f"{nv}{kv}{num}")

    # =====================================================================
    # Phase 5 — every token x every number x every suffix
    # =====================================================================
    for token in all_tokens:
        for num in all_numbers:
            for suffix in mp.suffix_patterns:
                for v in _case_variants(token):
                    yield from _emit(f"{v}{num}{suffix}")

    # =====================================================================
    # Phase 6 — every token x every suffix
    # =====================================================================
    for token in all_tokens:
        for suffix in mp.suffix_patterns:
            for v in _case_variants(token):
                yield from _emit(f"{v}{suffix}")

    # =====================================================================
    # Phase 7 — append special chars to ALL existing token+number combos
    # =====================================================================
    short_suffixes = tuple(
        s for s in mp.suffix_patterns if len(s) <= 2 and not s.isalnum()
    )
    if not short_suffixes:
        short_suffixes = ("!",)
    snapshot = [c for c in seen if len(c) >= 6 and c[-1].isdigit()]
    for base in snapshot:
        for suffix in short_suffixes:
            yield from _emit(f"{base}{suffix}")

    # =====================================================================
    # Phase 8a — selective leet on ALL direct keywords (always runs)
    # =====================================================================
    for token in expanded.keywords_direct:
        for leet_variant in _selective_leet_variants(token):
            yield from _emit(leet_variant)
            for num in all_numbers:
                yield from _emit(f"{leet_variant}{num}")
            for suffix in mp.suffix_patterns:
                yield from _emit(f"{leet_variant}{suffix}")

    # =====================================================================
    # Phase 8b — full + selective leet on cultural + names (gated)
    # =====================================================================
    if mp.leet_likelihood in ("medium", "high"):
        leet_tokens = list(dict.fromkeys(
            list(expanded.keywords_cultural) + list(all_names)
        ))
        for token in leet_tokens:
            for leet_fn in (_apply_leet, _apply_leet_alt):
                leet = leet_fn(token)
                if leet != token:
                    yield from _emit(leet)
                    for num in all_numbers:
                        yield from _emit(f"{leet}{num}")
            for leet_variant in _selective_leet_variants(token):
                yield from _emit(leet_variant)
                for num in all_numbers:
                    yield from _emit(f"{leet_variant}{num}")

    # =====================================================================
    # Phase 8c — position-targeted leet on all tokens
    # =====================================================================
    for token in all_tokens:
        for variant in position_leet_candidates(token):
            yield from _emit(variant)
            for num in all_numbers:
                yield from _emit(f"{variant}{num}")

    # =====================================================================
    # Phase 9 — reversed tokens + numbers + separators
    # =====================================================================
    for token in all_tokens:
        rev = token[::-1]
        if len(rev) >= 4:
            yield from _emit(rev)
        for num in all_numbers:
            yield from _emit(f"{rev}{num}")
            for sep in seps:
                if sep:
                    yield from _emit(f"{rev}{sep}{num}")
        # Vowel-stripped
        stripped = _VOWELS.sub("", token)
        if stripped and stripped != token and len(stripped) >= 3:
            yield from _emit(stripped)
            for num in all_numbers:
                yield from _emit(f"{stripped}{num}")

    # =====================================================================
    # Phase 10 — initialisms + variants
    # =====================================================================
    if len(all_keywords) >= 3:
        initials = "".join(kw[0] for kw in all_keywords if kw)
        if len(initials) >= 3:
            yield from _emit(initials)
            yield from _emit(initials.upper())
            for num in all_numbers:
                yield from _emit(f"{initials}{num}")
                yield from _emit(f"{initials.upper()}{num}")

    # =====================================================================
    # Phase 11 — padding patterns on all tokens
    # =====================================================================
    for token in all_tokens:
        for v in _case_variants(token):
            for candidate in padding_candidates(v):
                yield from _emit(candidate)

    # =====================================================================
    # Phase 12 — sandwich/wrapping patterns
    # =====================================================================
    for token in all_tokens:
        for candidate in sandwich_candidates(token, all_numbers):
            yield from _emit(candidate)

    # =====================================================================
    # Phase 13 — word doubling variants
    # =====================================================================
    for token in all_tokens:
        for candidate in doubling_candidates(token):
            yield from _emit(candidate)

    # =====================================================================
    # Phase 14 — keyboard walks (no profile needed)
    # =====================================================================
    for walk in keyboard_walk_candidates():
        yield from _emit(walk)

    # =====================================================================
    # Phase 15 — PIN / numeric patterns
    # =====================================================================
    for pin in PIN_PATTERNS:
        yield from _emit(pin)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _explode_numbers(numbers: tuple[str, ...]) -> tuple[str, ...]:
    """Extract every meaningful numeric substring from each number."""
    result: set[str] = set()
    for num in numbers:
        result.add(num)
        digits_only = "".join(c for c in num if c.isdigit())
        if not digits_only:
            continue
        for length in range(1, min(len(digits_only), 5) + 1):
            for start in range(len(digits_only) - length + 1):
                sub = digits_only[start:start + length]
                result.add(sub)
                if len(sub) == 1:
                    result.add(f"0{sub}")
    return tuple(sorted(result))


def _case_variants(token: str) -> tuple[str, ...]:
    lower = token.lower()
    cap = token.capitalize()
    upper = token.upper()
    variants = [lower]
    if cap != lower:
        variants.append(cap)
    if upper != lower and upper != cap:
        variants.append(upper)
    return tuple(variants)


def _apply_leet(token: str) -> str:
    result = token.lower()
    for char, replacement in _LEET_MAP.items():
        result = result.replace(char, replacement)
    return result


def _apply_leet_alt(token: str) -> str:
    result = token.lower()
    for char, replacement in _LEET_MAP_ALT.items():
        result = result.replace(char, replacement)
    return result


def _selective_leet_variants(token: str) -> Iterator[str]:
    """Yield ALL partial leet combinations via power-set enumeration."""
    lower = token.lower()
    applicable: list[tuple[str, str]] = []
    seen_pairs: set[tuple[str, str]] = set()
    for leet_map in (_LEET_MAP, _LEET_MAP_ALT):
        for char, replacement in leet_map.items():
            if char in lower and (char, replacement) not in seen_pairs:
                seen_pairs.add((char, replacement))
                applicable.append((char, replacement))

    if not applicable:
        return

    if len(applicable) > 6:
        for char, replacement in applicable:
            variant = lower.replace(char, replacement)
            if variant != lower:
                yield variant
        return

    seen_variants: set[str] = set()
    for mask in range(1, 1 << len(applicable)):
        result = lower
        for bit_idx in range(len(applicable)):
            if mask & (1 << bit_idx):
                char, replacement = applicable[bit_idx]
                result = result.replace(char, replacement)
        if result != lower and result not in seen_variants:
            seen_variants.add(result)
            yield result
