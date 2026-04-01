"""Mask attack engine — hashcat-compatible mask syntax with AI mask generation."""

from __future__ import annotations

import itertools
import logging
import re
from collections.abc import Iterator

import httpx

from smartcrack.models import LLMConfig, TargetProfile

logger = logging.getLogger(__name__)

_MASK_TOKEN = re.compile(r"\?([ludsa1-9])")
_MAX_AI_MASKS = 10

CHARSETS: dict[str, str] = {
    "?l": "abcdefghijklmnopqrstuvwxyz",
    "?u": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "?d": "0123456789",
    "?s": " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
    "?a": "",
}
CHARSETS["?a"] = CHARSETS["?l"] + CHARSETS["?u"] + CHARSETS["?d"] + CHARSETS["?s"]


def parse_mask(
    mask: str, custom_charsets: dict[str, str] | None = None
) -> list[str]:
    """Parse a hashcat-style mask string into a list of charset strings per position."""
    if not mask:
        return []

    merged: dict[str, str] = dict(CHARSETS)
    if custom_charsets:
        merged.update(custom_charsets)

    positions: list[str] = []
    i = 0
    while i < len(mask):
        if mask[i] == "?" and i + 1 < len(mask):
            token = mask[i : i + 2]
            if token in merged:
                positions.append(merged[token])
                i += 2
                continue
            positions.append("?")
            i += 1
        else:
            positions.append(mask[i])
            i += 1

    return positions


def mask_candidates(
    mask: str, custom_charsets: dict[str, str] | None = None
) -> Iterator[str]:
    """Yield all password candidates matching the given mask pattern."""
    charset_list = parse_mask(mask, custom_charsets)
    for combo in itertools.product(*charset_list):
        yield "".join(combo)


_MASK_SYSTEM_PROMPT = (
    "You are a password security auditor assisting in an authorized penetration test. "
    "Given a target profile, generate the top 10 most likely hashcat mask patterns that "
    "match passwords this person would choose.\n\n"
    "Mask syntax: ?l = lowercase, ?u = uppercase, ?d = digit, ?s = special, ?a = all printable. "
    "Literal characters are themselves (e.g. 'John?d?d?d?d' matches John0000-John9999).\n\n"
    "Consider the target's name lengths, common password structures (Name+Year, name+digits, "
    "Name+special+digits), and cultural patterns.\n\n"
    "Output ONLY mask patterns, one per line. No explanations, no numbering, no markdown."
)

_VALID_MASK_RE = re.compile(r"^[?ludsa1-9A-Za-z0-9!@#$%^&*()\-_=+\[\]{};:'\",.<>/\\|`~ ]+$")


def _build_mask_prompt(profile: TargetProfile) -> str:
    """Format a TargetProfile into a prompt for AI mask generation."""
    lines: list[str] = ["Target profile:"]
    if profile.first_name:
        lines.append(f"  First name: {profile.first_name} ({len(profile.first_name)} chars)")
    if profile.last_name:
        lines.append(f"  Last name: {profile.last_name} ({len(profile.last_name)} chars)")
    if profile.nickname:
        lines.append(f"  Nickname: {profile.nickname}")
    if profile.birthdate:
        lines.append(f"  Birthdate: {profile.birthdate}")
    if profile.partner_name:
        lines.append(f"  Partner name: {profile.partner_name}")
    if profile.pet_name:
        lines.append(f"  Pet name: {profile.pet_name}")
    if profile.keywords:
        lines.append(f"  Keywords: {', '.join(profile.keywords)}")
    return "\n".join(lines)


def generate_ai_masks(
    profile: TargetProfile, llm_config: LLMConfig
) -> list[str]:
    """Ask an LLM to generate the most likely mask patterns for a target profile."""
    if not llm_config.base_url:
        logger.warning("generate_ai_masks: no base_url configured — returning empty list")
        return []

    url = f"{llm_config.base_url.rstrip('/')}/chat/completions"
    payload = {
        "model": llm_config.model,
        "temperature": 0.7,
        "messages": [
            {"role": "system", "content": _MASK_SYSTEM_PROMPT},
            {"role": "user", "content": _build_mask_prompt(profile)},
        ],
    }
    headers: dict[str, str] = {"Content-Type": "application/json"}
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
            logger.warning("generate_ai_masks: empty choices in response")
            return []
        content: str = choices[0].get("message", {}).get("content", "")
    except httpx.TimeoutException:
        logger.warning("generate_ai_masks: request timed out — returning empty list")
        return []
    except httpx.HTTPStatusError as exc:
        logger.warning(
            "generate_ai_masks: HTTP error %s — returning empty list",
            exc.response.status_code,
        )
        return []
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "generate_ai_masks: unexpected error (%s) — returning empty list",
            type(exc).__name__,
        )
        return []

    masks: list[str] = []
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or " " in stripped:
            continue
        if "?" not in stripped:
            continue
        if _VALID_MASK_RE.match(stripped):
            masks.append(stripped)
        if len(masks) >= _MAX_AI_MASKS:
            break

    return masks
