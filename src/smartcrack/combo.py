"""AI-weighted combo attack — combine two wordlists with intelligent ordering."""

from __future__ import annotations

import logging
import re
from collections.abc import Iterator
from pathlib import Path

import httpx

from smartcrack.models import LLMConfig, TargetProfile

logger = logging.getLogger(__name__)

_CODE_FENCE = re.compile(r"^`{3,}(\w*)$")
_LIST_PREFIX = re.compile(r"^(\d+[.)]\s+|-\s+)")
_DEFAULT_SEPARATORS: tuple[str, ...] = ("",)
_PROFILE_SEPARATORS: tuple[str, ...] = ("", "_", ".", "!")
_MAX_AI_COMBOS = 500


def combo_candidates(
    path1: Path,
    path2: Path,
    separators: tuple[str, ...] = _DEFAULT_SEPARATORS,
    max_length: int = 64,
) -> Iterator[str]:
    words2: list[str] = []
    with open(path2, "r", encoding="iso-8859-1") as f2:
        for line in f2:
            stripped = line.rstrip("\n\r")
            if stripped:
                words2.append(stripped)

    with open(path1, "r", encoding="iso-8859-1") as f1:
        for line in f1:
            w1 = line.rstrip("\n\r")
            if not w1:
                continue
            for sep in separators:
                for w2 in words2:
                    candidate = f"{w1}{sep}{w2}"
                    if len(candidate) <= max_length:
                        yield candidate


def _collect_profile_tokens(profile: TargetProfile) -> list[str]:
    tokens: list[str] = []
    for field_val in (
        profile.first_name, profile.last_name, profile.nickname,
        profile.partner_name, profile.child_name, profile.pet_name,
    ):
        if field_val:
            tokens.append(field_val)
            tokens.append(field_val.lower())
            tokens.append(field_val.capitalize())
    for kw in profile.keywords:
        if kw:
            tokens.append(kw)
            tokens.append(kw.lower())
    for num in profile.special_numbers:
        if num:
            tokens.append(num)
    return tokens


def profile_combo_candidates(
    profile: TargetProfile,
    separators: tuple[str, ...] = _PROFILE_SEPARATORS,
) -> Iterator[str]:
    tokens = _collect_profile_tokens(profile)
    if not tokens:
        return

    seen: set[str] = set()
    for i, t1 in enumerate(tokens):
        for j, t2 in enumerate(tokens):
            if i == j:
                continue
            for sep in separators:
                candidate = f"{t1}{sep}{t2}"
                if candidate not in seen:
                    seen.add(candidate)
                    yield candidate


_COMBO_SYSTEM_PROMPT = (
    "You are a password security auditor for authorized penetration testing. "
    "Given two sets of words, generate the most likely password combinations "
    "a user might choose by combining one word from each set. Consider: "
    "direct concatenation, separator variations (_, ., !, -), case mixing, "
    "number substitutions, and common password patterns.\n\n"
    "Output ONLY the candidate passwords, one per line. No numbering, no "
    "explanations, no markdown formatting, no code fences."
)


def ai_ranked_combos(
    words1: list[str],
    words2: list[str],
    llm_config: LLMConfig,
    top_n: int = _MAX_AI_COMBOS,
) -> list[str]:
    sample1 = words1[:100]
    sample2 = words2[:100]

    user_prompt = (
        f"Word set 1:\n{chr(10).join(sample1)}\n\n"
        f"Word set 2:\n{chr(10).join(sample2)}\n\n"
        f"Generate the top {top_n} most likely password combinations."
    )

    url = f"{llm_config.base_url.rstrip('/')}/chat/completions"
    payload = {
        "model": llm_config.model,
        "temperature": 0.8,
        "messages": [
            {"role": "system", "content": _COMBO_SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
    }
    headers = {"Content-Type": "application/json"}
    if llm_config.api_key:
        headers["Authorization"] = f"Bearer {llm_config.api_key}"

    try:
        response = httpx.post(
            url,
            json=payload,
            headers=headers,
            timeout=llm_config.timeout_seconds,
        )
        response.raise_for_status()
        data = response.json()
        choices = data.get("choices", [])
        if not choices:
            return []
        content: str = choices[0].get("message", {}).get("content", "")
    except httpx.TimeoutException:
        logger.warning("ai_ranked_combos: request timed out")
        return []
    except httpx.HTTPStatusError as exc:
        logger.warning("ai_ranked_combos: HTTP error %s", exc.response.status_code)
        return []
    except Exception as exc:  # noqa: BLE001
        logger.warning("ai_ranked_combos: unexpected error (%s)", type(exc).__name__)
        return []

    results: list[str] = []
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if _CODE_FENCE.match(stripped):
            continue
        stripped = _LIST_PREFIX.sub("", stripped).strip()
        if " " in stripped:
            continue
        if not stripped or len(stripped) > 128:
            continue
        results.append(stripped)
        if len(results) >= top_n:
            break

    return results
