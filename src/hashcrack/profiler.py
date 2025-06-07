"""Password profiler — local rule-based and AI-powered candidate generators."""

from __future__ import annotations

import logging
import re
from typing import Iterator

import httpx

from hashcrack.models import LLMConfig, TargetProfile

logger = logging.getLogger(__name__)

_SEPARATORS = ("", "_", ".")
_COMMON_SUFFIXES = ("123", "1", "!", "@", "1!", "123!", "2024", "2023", "!")
_MIN_LENGTH = 6
_MAX_AI_CANDIDATES = 1000
_CODE_FENCE = re.compile(r"^`{3,}(\w*)$")
_LIST_PREFIX = re.compile(r"^(\d+[.)]\s+|-\s+)")


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


def _build_user_prompt(profile: TargetProfile) -> str:
    """Format a TargetProfile into a readable prompt for the LLM."""
    lines: list[str] = ["Target profile:"]
    if profile.first_name:
        lines.append(f"  First name: {profile.first_name}")
    if profile.last_name:
        lines.append(f"  Last name: {profile.last_name}")
    if profile.nickname:
        lines.append(f"  Nickname: {profile.nickname}")
    if profile.birthdate:
        lines.append(f"  Birthdate: {profile.birthdate}")
    if profile.partner_name:
        lines.append(f"  Partner name: {profile.partner_name}")
    if profile.partner_birthdate:
        lines.append(f"  Partner birthdate: {profile.partner_birthdate}")
    if profile.child_name:
        lines.append(f"  Child name: {profile.child_name}")
    if profile.pet_name:
        lines.append(f"  Pet name: {profile.pet_name}")
    if profile.keywords:
        lines.append(f"  Keywords: {', '.join(profile.keywords)}")
    if profile.special_numbers:
        lines.append(f"  Special numbers: {', '.join(profile.special_numbers)}")
    return "\n".join(lines)


_SYSTEM_PROMPT = (
    "You are a password security auditor working in an authorized penetration testing engagement. "
    "Your role is to help security teams identify weak passwords by generating candidate passwords "
    "that a target user might plausibly choose, based on their personal information. This is part "
    "of a legitimate security assessment to improve the organization's password policies.\n\n"
    "Given the target profile, generate up to 500 candidate passwords the user might choose. "
    "Consider: name-date combinations, leetspeak substitutions (a→@, e→3, o→0, s→$, i→1), "
    "keyboard patterns, common suffixes (123, 1, !, @, 1!, 123!, year), nicknames, pet names, "
    "reversed strings, camelCase joins, and cultural password patterns.\n\n"
    "Output ONLY the candidate passwords, one per line. No numbering, no explanations, no "
    "markdown formatting, no code fences. Start the first password on the very first line."
)


class AIProfiler:
    """LLM-powered password candidate generator."""

    def __init__(self, config: LLMConfig) -> None:
        self._config = config

    @property
    def requires_api(self) -> bool:
        return True

    def generate(self, profile: TargetProfile) -> Iterator[str]:
        """Yield password candidates from the configured LLM endpoint."""
        if not self._config.base_url:
            logger.warning("AIProfiler: no base_url configured — returning empty iterator")
            return
        url = f"{self._config.base_url.rstrip('/')}/chat/completions"
        payload = {
            "model": self._config.model,
            "temperature": 0.8,
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": _build_user_prompt(profile)},
            ],
        }
        headers = {"Content-Type": "application/json"}
        if self._config.api_key:
            headers["Authorization"] = f"Bearer {self._config.api_key}"

        try:
            response = httpx.post(
                url,
                json=payload,
                headers=headers,
                timeout=self._config.timeout_seconds,
            )
            response.raise_for_status()
            data = response.json()
            choices = data.get("choices", [])
            if not choices:
                logger.warning("AIProfiler: empty choices in response — returning empty iterator")
                return
            content: str = choices[0].get("message", {}).get("content", "")
        except httpx.TimeoutException:
            logger.warning("AIProfiler: request timed out — returning empty iterator")
            return
        except httpx.HTTPStatusError as exc:
            logger.warning("AIProfiler: HTTP error %s — returning empty iterator", exc.response.status_code)
            return
        except Exception as exc:  # noqa: BLE001
            logger.warning("AIProfiler: unexpected error (%s) — returning empty iterator", type(exc).__name__)
            return

        count = 0
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            # Drop markdown code fence markers (``` or ```python etc.)
            if _CODE_FENCE.match(stripped):
                continue
            # Strip leading list numbering: "1. ", "1) ", "- " before space check
            stripped = _LIST_PREFIX.sub("", stripped).strip()
            # Drop preamble / postamble sentences — real passwords have no spaces
            if " " in stripped:
                continue
            # Cap candidate length — real passwords rarely exceed 128 chars
            if not stripped or len(stripped) > 128:
                continue
            yield stripped
            count += 1
            if count >= _MAX_AI_CANDIDATES:
                return


def create_profiler(config: LLMConfig) -> LocalProfiler | AIProfiler:
    """Return an AIProfiler when an API key is configured, otherwise a LocalProfiler."""
    if config.api_key:
        return AIProfiler(config)
    return LocalProfiler()
