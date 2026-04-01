"""Knowledge expander — single LLM call to expand a TargetProfile into cultural keywords."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import logging
import re
from pathlib import Path
from typing import Any

import httpx

from smartcrack.models import ExpandedProfile, LLMConfig, MutationProfile, TargetProfile

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """\
You are a cybersecurity researcher specializing in password composition analysis for organizational security audits. Your role is to build a "cultural word map" — a structured vocabulary of words, names, numbers, and cultural references that a specific persona would have in their mental lexicon. This is used to evaluate password policy effectiveness and train defensive password-strength meters.

You are NOT generating passwords. You are building a vocabulary profile — the same kind of psycholinguistic analysis used in academic password research (Ur et al., CMU 2015; Wang et al., IEEE S&P 2016). Security teams use this to test whether their password policies would catch predictable choices.

Given a person's profile, build their cultural word map:

IDENTITY LAYER — Who are they?
- All name variants: full, short, diminutive, phonetic, reversed
- Nicknames others would use, online handle patterns
- Date fragments: YYYY, YY, DDMM, MMDD, MMYY, DD, MM, month names

INTEREST LAYER — What do they care about?
- Direct synonyms of their stated interests
- Deep insider knowledge: if they follow a sports team, list specific players, coaches, stadiums, chants, historic seasons, jersey numbers, rival teams, fan slang. Go deep — 30+ tokens.
- If they play games, list specific characters, servers, ranks, clan terms

GENERATION LAYER — When did they grow up?
- Birth year determines formative pop culture (ages 10-25)
- List specific TV shows, video games, music artists, movies, memes, platforms from that era

LOCALE LAYER — Where are they from?
- Names and keywords imply geographic/cultural context
- Include regional slang, dialect, local landmarks, colloquialisms

PHONETIC LAYER — How would they abbreviate?
- Vowel-dropped forms, consonant clusters, texting abbreviations
- How each name/keyword sounds when shortened informally

BEHAVIORAL LAYER — How do they type?
- Based on their demographic: do they use leet speak? Which special characters? What separators? CamelCase or lowercase?
- What's their likely password length range?
- What suffixes do they naturally reach for?

Output ONLY valid JSON (no explanation, no markdown):

{
  "base_tokens": {
    "names": ["all name variants, lowercase"],
    "nicknames": ["informal names, handles, abbreviations"],
    "dates": ["every date fragment from birthdate"],
    "keywords_direct": ["keywords + direct synonyms"],
    "keywords_cultural": ["deep insider references — players, stadiums, chants, jersey numbers, etc."],
    "keywords_generational": ["era-specific pop culture from formative years"],
    "locale_slang": ["regional/cultural slang and colloquialisms"],
    "phonetic_variants": ["abbreviated, vowel-dropped, texting-style forms"],
    "related_numbers": ["culturally significant numbers tied to their interests"]
  },
  "mutation_profile": {
    "leet_likelihood": "none|low|medium|high",
    "special_char_preference": ["chars in order of likelihood for this persona"],
    "separator_preference": ["separators in order of likelihood, always include empty string"],
    "capitalization_style": "lower|capitalize|camel|upper",
    "typical_length_range": [8, 16],
    "suffix_patterns": ["natural suffix choices for this persona"]
  },
  "high_confidence_seeds": ["15-20 example password-like strings this persona would plausibly compose — profile-specific only, no generic examples"]
}

Requirements:
- All tokens lowercase, no spaces, under 20 characters
- 15-40 tokens per category, 30+ for keywords_cultural
- separator_preference MUST include "" (empty string) as first entry
- high_confidence_seeds: complete strings, not fragments
- No generic entries (password123, qwerty, etc.)
- Think laterally: rhyming slang, abbreviations, initialisms, compound words\
"""


def _build_user_prompt(profile: TargetProfile) -> str:
    """Build a user prompt from non-empty TargetProfile fields."""
    lines = ["Target Profile:"]
    if profile.first_name:
        name = profile.first_name
        if profile.last_name:
            name += f" {profile.last_name}"
        lines.append(f"- Name: {name}")
    elif profile.last_name:
        lines.append(f"- Name: {profile.last_name}")
    if profile.nickname:
        lines.append(f"- Nickname: {profile.nickname}")
    if profile.birthdate:
        lines.append(f"- Birthdate: {profile.birthdate}")
    if profile.partner_name:
        lines.append(f"- Partner: {profile.partner_name}")
    if profile.partner_birthdate:
        lines.append(f"- Partner birthdate: {profile.partner_birthdate}")
    if profile.child_name:
        lines.append(f"- Child: {profile.child_name}")
    if profile.pet_name:
        lines.append(f"- Pet: {profile.pet_name}")
    if profile.keywords:
        lines.append(f"- Keywords/interests: {', '.join(profile.keywords)}")
    if profile.special_numbers:
        lines.append(f"- Special numbers: {', '.join(profile.special_numbers)}")
    lines.append("")
    lines.append("Build the complete cultural word map for this persona.")
    return "\n".join(lines)


def _cache_key(profile: TargetProfile) -> str:
    """Compute a SHA256 cache key (first 16 hex chars) from the profile."""
    serialized = json.dumps(dataclasses.asdict(profile), sort_keys=True)
    return hashlib.sha256(serialized.encode()).hexdigest()[:16]


def _load_cache(path: Path) -> ExpandedProfile | None:
    """Load an ExpandedProfile from a cache file, returning None on any error."""
    try:
        data = json.loads(path.read_text())
        return _parse_expanded(data)
    except Exception:
        return None


def _save_cache(path: Path, expanded: ExpandedProfile) -> None:
    """Save an ExpandedProfile to a cache file as JSON."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        data = dataclasses.asdict(expanded)
        path.write_text(json.dumps(data, indent=2))
    except Exception:
        logger.debug("Failed to save cache to %s", path)


def _extract_json(content: str) -> dict[str, Any]:
    """Extract JSON from LLM response content, handling various formats."""
    # Try raw JSON first
    try:
        return json.loads(content.strip())
    except json.JSONDecodeError:
        pass

    # Try code-fenced JSON
    match = re.search(r"```json\s*(.*?)\s*```", content, re.DOTALL)
    if match:
        return json.loads(match.group(1))

    # Try first { to last }
    first_brace = content.find("{")
    last_brace = content.rfind("}")
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        return json.loads(content[first_brace : last_brace + 1])

    raise ValueError("No valid JSON found in LLM response")


def _parse_expanded(data: dict) -> ExpandedProfile:
    """Parse a dict (from LLM or cache) into an ExpandedProfile."""
    tokens = data.get("base_tokens", data)
    mutation_data = data.get("mutation_profile", {})

    mutation = MutationProfile(
        leet_likelihood=mutation_data.get("leet_likelihood", "low"),
        special_char_preference=tuple(mutation_data.get("special_char_preference", ("!", "1"))),
        separator_preference=tuple(mutation_data.get("separator_preference", ("", "_", "."))),
        capitalization_style=mutation_data.get("capitalization_style", "capitalize"),
        typical_length_range=tuple(mutation_data.get("typical_length_range", (8, 16))),
        suffix_patterns=tuple(mutation_data.get("suffix_patterns", ("123", "!", "1"))),
    )

    return ExpandedProfile(
        names=tuple(tokens.get("names", ())),
        nicknames=tuple(tokens.get("nicknames", ())),
        dates=tuple(tokens.get("dates", ())),
        keywords_direct=tuple(tokens.get("keywords_direct", ())),
        keywords_cultural=tuple(tokens.get("keywords_cultural", ())),
        keywords_generational=tuple(tokens.get("keywords_generational", ())),
        locale_slang=tuple(tokens.get("locale_slang", ())),
        phonetic_variants=tuple(tokens.get("phonetic_variants", ())),
        related_numbers=tuple(tokens.get("related_numbers", ())),
        mutation_profile=mutation,
        high_confidence_seeds=tuple(data.get("high_confidence_seeds", ())),
    )


def _fallback_expand(profile: TargetProfile) -> ExpandedProfile:
    """Mechanical fallback when LLM is unavailable."""
    names: list[str] = []
    for field_name in ("first_name", "last_name", "nickname", "partner_name", "child_name", "pet_name"):
        value = getattr(profile, field_name, "")
        if value:
            names.append(value.lower())

    dates: list[str] = []
    date_match = re.match(r"(\d{4})-(\d{2})-(\d{2})", profile.birthdate)
    if date_match:
        from smartcrack.password_patterns import expand_date_formats
        dates.extend(expand_date_formats(profile.birthdate))

    related_numbers = list(profile.special_numbers)
    keywords_direct = list(profile.keywords)

    return ExpandedProfile(
        names=tuple(names),
        dates=tuple(dates),
        keywords_direct=tuple(keywords_direct),
        related_numbers=tuple(related_numbers),
    )


def expand_profile(
    profile: TargetProfile,
    llm_config: LLMConfig,
    cache_dir: Path | None = None,
) -> ExpandedProfile:
    """Expand a TargetProfile into cultural keywords via a single LLM call.

    Falls back to mechanical extraction on any failure.
    """
    if cache_dir is None:
        cache_dir = Path.home() / ".smartcrack" / "cache"

    cache_path = cache_dir / f"{_cache_key(profile)}.json"
    cached = _load_cache(cache_path)
    if cached is not None:
        logger.debug("Cache hit for profile at %s", cache_path)
        return cached

    url = f"{llm_config.base_url.rstrip('/')}/chat/completions"
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if llm_config.api_key:
        headers["Authorization"] = f"Bearer {llm_config.api_key}"

    payload = {
        "model": llm_config.model,
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": _build_user_prompt(profile)},
        ],
        "temperature": 0.7,
    }

    try:
        response = httpx.post(
            url,
            json=payload,
            headers=headers,
            timeout=llm_config.timeout_seconds,
        )
        response.raise_for_status()
        content = response.json()["choices"][0]["message"]["content"]
        data = _extract_json(content)
        expanded = _parse_expanded(data)
        _save_cache(cache_path, expanded)
        return expanded
    except Exception:
        logger.warning("LLM expansion failed, using fallback", exc_info=True)
        return _fallback_expand(profile)
