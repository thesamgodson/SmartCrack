"""Password profiler — local rule-based candidate generator."""

from __future__ import annotations

from typing import Iterator

from smartcrack.models import TargetProfile

_SEPARATORS = ("", "_", ".")
_COMMON_SUFFIXES = ("123", "1", "!", "@", "1!", "123!", "2024", "2023", "!")
_MIN_LENGTH = 6


def _name_variations(name: str) -> list[str]:
    """Return lower, upper, capitalized, and first-3 variants for a name."""
    if not name:
        return []
    return [
        name.lower(),
        name.upper(),
        name.capitalize(),
        name[:3].lower(),
        name[:3].upper(),
    ]


def _date_variations(date_str: str) -> list[str]:
    """Return common date substrings from a date string (YYYY-MM-DD or similar)."""
    if not date_str:
        return []

    digits = "".join(ch for ch in date_str if ch.isdigit())
    variants: list[str] = []

    if len(digits) >= 8:
        year = digits[:4]
        month = digits[4:6]
        day = digits[6:8]
        variants += [
            digits,          # full numeric: YYYYMMDD
            year,            # year: YYYY
            year[2:],        # 2-digit year: YY
            day + month,     # day+month: DDMM
            month + year,    # month+year: MMYYYY
        ]
    elif len(digits) == 4:
        variants += [digits, digits[2:]]
    else:
        variants.append(digits)

    return [v for v in variants if v]


def _collect_names(profile: TargetProfile) -> list[str]:
    """Return non-empty name fields from profile."""
    name_fields = [
        profile.first_name,
        profile.last_name,
        profile.nickname,
        profile.partner_name,
        profile.child_name,
        profile.pet_name,
    ]
    return [n for n in name_fields if n]


def _collect_dates(profile: TargetProfile) -> list[str]:
    """Return non-empty date fields from profile."""
    date_fields = [profile.birthdate, profile.partner_birthdate]
    return [d for d in date_fields if d]


def _collect_numbers(profile: TargetProfile) -> list[str]:
    """Return special numbers from profile."""
    return list(profile.special_numbers)


def _meets_min_length(candidate: str) -> bool:
    return len(candidate) >= _MIN_LENGTH


def _combine(left: str, right: str, sep: str) -> str:
    return f"{left}{sep}{right}"


class LocalProfiler:
    """Rule-based password candidate generator. Requires no external API."""

    @property
    def requires_api(self) -> bool:
        return False

    def generate(self, profile: TargetProfile) -> Iterator[str]:
        """Yield password candidates derived from the target profile."""
        seen: set[str] = set()

        def emit(candidate: str) -> Iterator[str]:
            if _meets_min_length(candidate) and candidate not in seen:
                seen.add(candidate)
                yield candidate

        names = _collect_names(profile)
        dates = _collect_dates(profile)
        numbers = _collect_numbers(profile)
        keywords = list(profile.keywords)

        all_name_vars = [var for name in names for var in _name_variations(name)]
        all_date_vars = [var for d in dates for var in _date_variations(d)]
        all_number_vars = numbers + list(_COMMON_SUFFIXES)

        # Raw name variations
        for var in all_name_vars:
            yield from emit(var)

        # Raw keywords
        for kw in keywords:
            yield from emit(kw)
            yield from emit(kw.lower())
            yield from emit(kw.capitalize())

        # name + date
        for name_var in all_name_vars:
            for date_var in all_date_vars:
                for sep in _SEPARATORS:
                    yield from emit(_combine(name_var, date_var, sep))
                    yield from emit(_combine(date_var, name_var, sep))

        # name + number
        for name_var in all_name_vars:
            for num in all_number_vars:
                for sep in _SEPARATORS:
                    yield from emit(_combine(name_var, num, sep))

        # name + name combinations
        for i, var_a in enumerate(all_name_vars):
            for var_b in all_name_vars[i + 1:]:
                for sep in _SEPARATORS:
                    yield from emit(_combine(var_a, var_b, sep))

        # keyword + number
        for kw in keywords:
            for num in all_number_vars:
                for sep in _SEPARATORS:
                    yield from emit(_combine(kw.lower(), num, sep))

        # date + number
        for date_var in all_date_vars:
            for num in all_number_vars:
                for sep in _SEPARATORS:
                    yield from emit(_combine(date_var, num, sep))


