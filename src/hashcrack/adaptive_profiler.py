"""Multi-round adaptive AI profiling with chain-of-thought reasoning."""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Iterator

import httpx

from hashcrack.models import LLMConfig, TargetProfile

logger = logging.getLogger(__name__)

_CONFIDENCE_RE = re.compile(r"^\[([0-9.]+)\]\s*(.+)$")
_MAX_CANDIDATES_PER_ROUND = 500

_SYSTEM_PROMPT_ROUND_0 = """You are a password research assistant for authorized penetration testing.
Given a target profile, generate likely passwords. Think step by step:
1. Analyze the person's likely password psychology based on their demographics
2. Consider common patterns: name+year, pet+numbers, partner+date
3. Think about their profession/interests for technical passwords
4. Generate passwords with confidence scores [0.0-1.0]

Format each line as: [confidence] password
Example: [0.9] john1990
Only output password lines, no other text except a brief reasoning paragraph first."""

_SYSTEM_PROMPT_ROUND_N = """You are a password research assistant for authorized penetration testing.
Previous rounds failed with these candidates: {failed}
The target profile is the same. Think about what patterns you HAVEN'T tried:
1. What assumptions were wrong in previous rounds?
2. What password creation strategies haven't been explored?
3. Consider: passphrases, keyboard patterns, reversed names, phonetic spellings

Generate a NEW set of candidates — do NOT repeat failed ones.
Format: [confidence] password"""


@dataclass(frozen=True)
class ProfileRound:
    """Result of a single profiling round."""

    round_num: int
    candidates: list[str]
    reasoning: str
    confidence_scores: dict[str, float] = field(default_factory=dict)


class AdaptiveProfiler:
    """Multi-round AI profiler that adapts based on failed attempts."""

    def __init__(self, config: LLMConfig, max_rounds: int = 3) -> None:
        self._config = config
        self.max_rounds = max_rounds
        self._history: list[ProfileRound] = []

    @property
    def history(self) -> list[ProfileRound]:
        return list(self._history)

    def generate_round(
        self,
        profile: TargetProfile,
        failed_candidates: list[str],
        round_num: int,
    ) -> ProfileRound:
        """Generate candidates for a single round."""
        if round_num == 0:
            system_prompt = _SYSTEM_PROMPT_ROUND_0
        else:
            failed_sample = failed_candidates[-100:]
            system_prompt = _SYSTEM_PROMPT_ROUND_N.format(
                failed=", ".join(failed_sample)
            )

        user_prompt = _build_profile_prompt(profile)

        response = httpx.post(
            f"{self._config.base_url}/chat/completions",
            headers={"Authorization": f"Bearer {self._config.api_key}"},
            json={
                "model": self._config.model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "temperature": min(0.8 + (round_num * 0.1), 1.5),
                "max_tokens": 4096,
            },
            timeout=self._config.timeout_seconds,
        )
        response.raise_for_status()

        content = response.json()["choices"][0]["message"]["content"]
        return _parse_round_response(content, round_num)

    def generate_all_rounds(
        self,
        profile: TargetProfile,
    ) -> Iterator[ProfileRound]:
        """Run all rounds, yielding results."""
        all_failed: list[str] = []

        for round_num in range(self.max_rounds):
            try:
                result = self.generate_round(profile, all_failed, round_num)
                self._history.append(result)
                yield result
                all_failed.extend(result.candidates)
            except Exception as e:
                logger.warning("Round %d failed: %s", round_num, e)
                break


def _build_profile_prompt(profile: TargetProfile) -> str:
    """Build user prompt from profile fields."""
    parts: list[str] = []
    if profile.first_name:
        parts.append(f"First name: {profile.first_name}")
    if profile.last_name:
        parts.append(f"Last name: {profile.last_name}")
    if profile.nickname:
        parts.append(f"Nickname: {profile.nickname}")
    if profile.birthdate:
        parts.append(f"Birthdate: {profile.birthdate}")
    if profile.partner_name:
        parts.append(f"Partner: {profile.partner_name}")
    if profile.partner_birthdate:
        parts.append(f"Partner birthdate: {profile.partner_birthdate}")
    if profile.child_name:
        parts.append(f"Child: {profile.child_name}")
    if profile.pet_name:
        parts.append(f"Pet: {profile.pet_name}")
    if profile.keywords:
        parts.append(f"Keywords: {', '.join(profile.keywords)}")
    if profile.special_numbers:
        parts.append(f"Numbers: {', '.join(profile.special_numbers)}")
    return "\n".join(parts) if parts else "No profile information provided."


def _parse_round_response(content: str, round_num: int) -> ProfileRound:
    """Parse LLM response into a ProfileRound with confidence scores."""
    lines = content.strip().splitlines()
    candidates: list[str] = []
    scores: dict[str, float] = {}
    reasoning_lines: list[str] = []
    in_reasoning = True

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        match = _CONFIDENCE_RE.match(stripped)
        if match:
            in_reasoning = False
            score = float(match.group(1))
            password = match.group(2).strip()
            if password and len(password) <= 128:
                candidates.append(password)
                scores[password] = min(score, 1.0)
        elif in_reasoning:
            reasoning_lines.append(stripped)
        else:
            cleaned = stripped.lstrip("0123456789.-) ")
            if cleaned and " " not in cleaned and len(cleaned) <= 128:
                candidates.append(cleaned)
                scores[cleaned] = 0.5

    # If no confidence-formatted lines were found, treat all reasoning lines as
    # plain password candidates (LLM responded without [score] prefixes).
    if not candidates and reasoning_lines:
        for token in reasoning_lines:
            cleaned = token.lstrip("0123456789.-) ")
            if cleaned and " " not in cleaned and len(cleaned) <= 128:
                candidates.append(cleaned)
                scores[cleaned] = 0.5
        reasoning_lines = []

    candidates.sort(key=lambda c: scores.get(c, 0.5), reverse=True)
    candidates = candidates[:_MAX_CANDIDATES_PER_ROUND]

    return ProfileRound(
        round_num=round_num,
        candidates=candidates,
        reasoning="\n".join(reasoning_lines),
        confidence_scores=scores,
    )
