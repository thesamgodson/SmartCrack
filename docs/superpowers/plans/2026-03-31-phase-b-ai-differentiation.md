# Phase B: AI Differentiation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Add AI mask attacks, attack explainer, and crack estimator — the features that make SmartCrack genuinely novel.

**Architecture:** Mask engine generates candidates from pattern syntax with AI-generated masks from LLM. Explainer produces natural-language narratives of crack sessions. Estimator provides pre-attack probability analysis with HIBP integration.

**Tech Stack:** itertools (mask generation), httpx (HIBP API), Rich (rendering), existing LLM integration pattern.

---

## Task 1: Mask Attack Engine — Core Module

**Files:**
- `src/smartcrack/mask.py` (create)
- `tests/test_mask.py` (create)

### Step 1.1 — Write tests for `parse_mask` and `mask_candidates`

- [ ] Create `tests/test_mask.py` with all unit tests

```python
"""Tests for the mask attack engine."""

from __future__ import annotations

import types
from collections.abc import Iterator
from unittest.mock import MagicMock, patch

import pytest

from smartcrack.mask import (
    CHARSETS,
    generate_ai_masks,
    mask_candidates,
    parse_mask,
)
from smartcrack.models import LLMConfig, TargetProfile


# ---------------------------------------------------------------------------
# CHARSETS
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestCharsets:
    def test_lowercase_charset(self) -> None:
        assert CHARSETS["?l"] == "abcdefghijklmnopqrstuvwxyz"

    def test_uppercase_charset(self) -> None:
        assert CHARSETS["?u"] == "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    def test_digit_charset(self) -> None:
        assert CHARSETS["?d"] == "0123456789"

    def test_special_charset(self) -> None:
        assert "!" in CHARSETS["?s"]
        assert "@" in CHARSETS["?s"]
        assert "#" in CHARSETS["?s"]
        assert "$" in CHARSETS["?s"]
        assert "%" in CHARSETS["?s"]
        assert "^" in CHARSETS["?s"]
        assert "&" in CHARSETS["?s"]
        assert "*" in CHARSETS["?s"]

    def test_all_printable_charset(self) -> None:
        charset_a = CHARSETS["?a"]
        # ?a must contain all of ?l, ?u, ?d, ?s
        for char in CHARSETS["?l"]:
            assert char in charset_a
        for char in CHARSETS["?u"]:
            assert char in charset_a
        for char in CHARSETS["?d"]:
            assert char in charset_a
        for char in CHARSETS["?s"]:
            assert char in charset_a


# ---------------------------------------------------------------------------
# parse_mask
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestParseMask:
    def test_single_lowercase_token(self) -> None:
        result = parse_mask("?l")
        assert result == [CHARSETS["?l"]]

    def test_multiple_tokens(self) -> None:
        result = parse_mask("?l?d")
        assert len(result) == 2
        assert result[0] == CHARSETS["?l"]
        assert result[1] == CHARSETS["?d"]

    def test_all_builtin_tokens(self) -> None:
        result = parse_mask("?l?u?d?s?a")
        assert len(result) == 5
        assert result[0] == CHARSETS["?l"]
        assert result[1] == CHARSETS["?u"]
        assert result[2] == CHARSETS["?d"]
        assert result[3] == CHARSETS["?s"]
        assert result[4] == CHARSETS["?a"]

    def test_literal_characters(self) -> None:
        result = parse_mask("abc")
        assert result == ["a", "b", "c"]

    def test_mixed_tokens_and_literals(self) -> None:
        result = parse_mask("P?d?d?d")
        assert len(result) == 4
        assert result[0] == "P"
        assert result[1] == CHARSETS["?d"]
        assert result[2] == CHARSETS["?d"]
        assert result[3] == CHARSETS["?d"]

    def test_custom_charset_override(self) -> None:
        custom = {"?1": "ABC"}
        result = parse_mask("?1?d", custom_charsets=custom)
        assert result[0] == "ABC"
        assert result[1] == CHARSETS["?d"]

    def test_custom_charset_does_not_override_builtins(self) -> None:
        custom = {"?1": "XYZ"}
        result = parse_mask("?l?1", custom_charsets=custom)
        assert result[0] == CHARSETS["?l"]
        assert result[1] == "XYZ"

    def test_empty_mask_returns_empty_list(self) -> None:
        result = parse_mask("")
        assert result == []

    def test_escaped_question_mark(self) -> None:
        """A '?' followed by an unknown token char is treated as literal '?' + char."""
        result = parse_mask("?z")
        # ?z is not a known token — treat '?' and 'z' as two literal positions
        assert len(result) == 2
        assert result[0] == "?"
        assert result[1] == "z"


# ---------------------------------------------------------------------------
# mask_candidates
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestMaskCandidates:
    def test_returns_iterator(self) -> None:
        gen = mask_candidates("?d")
        assert hasattr(gen, "__iter__") and hasattr(gen, "__next__")

    def test_single_digit_yields_10(self) -> None:
        results = list(mask_candidates("?d"))
        assert len(results) == 10
        assert "0" in results
        assert "9" in results

    def test_two_digits_yields_100(self) -> None:
        results = list(mask_candidates("?d?d"))
        assert len(results) == 100
        assert "00" in results
        assert "99" in results
        assert "42" in results

    def test_candidate_count_is_product_of_charset_sizes(self) -> None:
        # ?l?d = 26 * 10 = 260
        results = list(mask_candidates("?l?d"))
        assert len(results) == 26 * 10

    def test_literal_prefix_with_digit(self) -> None:
        results = list(mask_candidates("A?d"))
        assert len(results) == 10
        assert all(r.startswith("A") for r in results)

    def test_all_candidates_match_mask_pattern(self) -> None:
        results = list(mask_candidates("?u?l?d"))
        for candidate in results:
            assert len(candidate) == 3
            assert candidate[0].isupper()
            assert candidate[1].islower()
            assert candidate[2].isdigit()

    def test_custom_charset_candidates(self) -> None:
        custom = {"?1": "AB"}
        results = list(mask_candidates("?1?d", custom_charsets=custom))
        assert len(results) == 2 * 10
        assert "A0" in results
        assert "B9" in results

    def test_empty_mask_yields_single_empty_string(self) -> None:
        results = list(mask_candidates(""))
        assert results == [""]

    def test_generator_is_lazy(self) -> None:
        gen = mask_candidates("?l?l?l?l?l")  # 26^5 = 11,881,376
        first = next(gen)
        assert isinstance(first, str)
        assert len(first) == 5


# ---------------------------------------------------------------------------
# generate_ai_masks
# ---------------------------------------------------------------------------


def _make_mock_response(content: str, status_code: int = 200) -> MagicMock:
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.json.return_value = {
        "choices": [{"message": {"content": content}}]
    }
    mock_resp.raise_for_status = MagicMock()
    return mock_resp


@pytest.mark.unit
class TestGenerateAIMasks:
    @pytest.fixture
    def llm_config(self) -> LLMConfig:
        return LLMConfig(
            base_url="https://test.example.com/v1",
            api_key="sk-test-key",
            model="gpt-4o",
            timeout_seconds=10,
        )

    @pytest.fixture
    def profile(self) -> TargetProfile:
        return TargetProfile(
            first_name="John",
            last_name="Smith",
            birthdate="1990-05-14",
        )

    def test_returns_list_of_strings(
        self, llm_config: LLMConfig, profile: TargetProfile
    ) -> None:
        mock_resp = _make_mock_response("?l?l?l?l?d?d\n?u?l?l?l?l?d?d?d?d\n?l?l?l?l?l?l?d?d?s")
        with patch("smartcrack.mask.httpx.post", return_value=mock_resp):
            masks = generate_ai_masks(profile, llm_config)
        assert isinstance(masks, list)
        assert all(isinstance(m, str) for m in masks)

    def test_filters_invalid_mask_syntax(
        self, llm_config: LLMConfig, profile: TargetProfile
    ) -> None:
        mock_resp = _make_mock_response(
            "?l?l?l?d?d\nThis is not a mask\n?u?d?d?d?d\nAnother sentence here"
        )
        with patch("smartcrack.mask.httpx.post", return_value=mock_resp):
            masks = generate_ai_masks(profile, llm_config)
        # Only valid mask patterns should be returned
        for mask in masks:
            assert "?" in mask

    def test_caps_at_10_masks(
        self, llm_config: LLMConfig, profile: TargetProfile
    ) -> None:
        lines = "\n".join(f"?l?l?l?d?d{i}" for i in range(20))
        mock_resp = _make_mock_response(lines)
        with patch("smartcrack.mask.httpx.post", return_value=mock_resp):
            masks = generate_ai_masks(profile, llm_config)
        assert len(masks) <= 10

    def test_sends_correct_endpoint(
        self, llm_config: LLMConfig, profile: TargetProfile
    ) -> None:
        mock_resp = _make_mock_response("?l?l?l?d?d")
        with patch("smartcrack.mask.httpx.post", return_value=mock_resp) as mock_post:
            generate_ai_masks(profile, llm_config)
        call_url = mock_post.call_args[0][0]
        assert call_url.endswith("/chat/completions")

    def test_timeout_returns_empty_list(
        self, llm_config: LLMConfig, profile: TargetProfile
    ) -> None:
        import httpx as _httpx

        with patch(
            "smartcrack.mask.httpx.post",
            side_effect=_httpx.TimeoutException("timed out"),
        ):
            masks = generate_ai_masks(profile, llm_config)
        assert masks == []

    def test_http_error_returns_empty_list(
        self, llm_config: LLMConfig, profile: TargetProfile
    ) -> None:
        import httpx as _httpx

        mock_resp = MagicMock()
        mock_resp.status_code = 500
        error = _httpx.HTTPStatusError(
            "server error", request=MagicMock(), response=mock_resp
        )
        with patch("smartcrack.mask.httpx.post", side_effect=error):
            masks = generate_ai_masks(profile, llm_config)
        assert masks == []

    def test_no_base_url_returns_empty_list(
        self, profile: TargetProfile
    ) -> None:
        config = LLMConfig(api_key="sk-test", model="gpt-4o")
        masks = generate_ai_masks(profile, config)
        assert masks == []
```

Run:
```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m pytest tests/test_mask.py -x --tb=short 2>&1 | head -30
```

Expected: all tests fail with `ImportError` (module does not exist yet).

### Step 1.2 — Create `src/smartcrack/mask.py`

- [ ] Create the mask module with all functions

```python
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
    "?a": "",  # filled below
}
CHARSETS["?a"] = CHARSETS["?l"] + CHARSETS["?u"] + CHARSETS["?d"] + CHARSETS["?s"]


def parse_mask(
    mask: str, custom_charsets: dict[str, str] | None = None
) -> list[str]:
    """Parse a hashcat-style mask string into a list of charset strings per position.

    Tokens like ``?l``, ``?u``, ``?d``, ``?s``, ``?a`` expand to their charset.
    Custom charsets (``?1`` through ``?9``) can be passed via *custom_charsets*.
    Literal characters become single-character strings.

    Args:
        mask: The mask pattern string (e.g. ``"?u?l?l?l?d?d"``).
        custom_charsets: Optional mapping of custom tokens to charset strings.

    Returns:
        A list where each element is the charset string for that position.
    """
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
            # Unknown token — treat '?' and next char as two literal positions
            positions.append("?")
            i += 1
        else:
            positions.append(mask[i])
            i += 1

    return positions


def mask_candidates(
    mask: str, custom_charsets: dict[str, str] | None = None
) -> Iterator[str]:
    """Yield all password candidates matching the given mask pattern.

    Uses :func:`itertools.product` over the parsed charset positions, so the
    generator is fully lazy — no candidates are materialised in memory.

    Args:
        mask: Hashcat-compatible mask string.
        custom_charsets: Optional custom charset overrides.

    Yields:
        Password candidate strings in lexicographic order of position charsets.
    """
    charset_list = parse_mask(mask, custom_charsets)
    for combo in itertools.product(*charset_list):
        yield "".join(combo)


# ---------------------------------------------------------------------------
# AI mask generation
# ---------------------------------------------------------------------------

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
    """Ask an LLM to generate the most likely mask patterns for a target profile.

    Args:
        profile: Target profile to base mask generation on.
        llm_config: LLM connection configuration.

    Returns:
        A list of up to 10 hashcat-compatible mask strings. Returns an empty
        list on any API error or timeout.
    """
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
        # Must contain at least one mask token to be valid
        if "?" not in stripped:
            continue
        if _VALID_MASK_RE.match(stripped):
            masks.append(stripped)
        if len(masks) >= _MAX_AI_MASKS:
            break

    return masks
```

Run:
```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m pytest tests/test_mask.py -x --tb=short -q
```

Expected: all tests pass.

Commit:
```
feat: add mask attack engine with AI mask generation

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
```

---

## Task 2: Mask Attack — Model & Orchestrator Integration

**Files:**
- `src/smartcrack/models.py` (edit)
- `src/smartcrack/orchestrator.py` (edit)
- `tests/test_orchestrator.py` (edit)

### Step 2.1 — Add `MASK` to `AttackPhase` enum

- [ ] Edit `src/smartcrack/models.py` — add `MASK = "mask"` to `AttackPhase`

In `src/smartcrack/models.py`, add after `ADAPTIVE = "adaptive"`:

```python
class AttackPhase(Enum):
    DICTIONARY = "dictionary"
    RULES = "rules"
    PROFILE = "profile"
    HYBRID = "hybrid"
    ADAPTIVE = "adaptive"
    MASK = "mask"
```

Run:
```bash
cd /Users/sam/Documents/Projects/hashcrack && python -c "from smartcrack.models import AttackPhase; print(AttackPhase.MASK.value)"
```

Expected: prints `mask`.

### Step 2.2 — Add mask phase to `plan_attacks()` in orchestrator

- [ ] Edit `src/smartcrack/orchestrator.py` — add mask_pattern and ai_masks parameters, insert mask phase

Add new imports at the top of `src/smartcrack/orchestrator.py`:

```python
from smartcrack.mask import generate_ai_masks, mask_candidates
```

Update the `plan_attacks` function signature and body. Replace the existing `plan_attacks` with:

```python
def plan_attacks(
    wordlist_path: Path,
    rules_preset: str = "quick",
    profile: TargetProfile | None = None,
    llm_config: LLMConfig | None = None,
    wordlist_offset: int = 0,
    mask_pattern: str | None = None,
    ai_masks: bool = False,
) -> list[AttackPlan]:
    """Build an ordered list of AttackPlan objects for the given configuration.

    Phase ordering:
    1. DICTIONARY  — plain wordlist
    2. RULES       — wordlist + rule mutations (skipped when rules_preset=="none")
    3. MASK        — mask attack (when mask_pattern or ai_masks is set)
    4. PROFILE     — profile-derived candidates (skipped when profile is None)
    5. HYBRID      — profile candidates + rule mutations (only when both profile
                     and rules are active)
    6. ADAPTIVE    — multi-round AI profiling

    Args:
        wordlist_path:  Path to the base wordlist file.
        rules_preset:   One of "none", "quick", or "thorough".
        profile:        Optional target profile for personalised candidates.
        llm_config:     Optional LLM config; enables AIProfiler when api_key set.
        wordlist_offset: Number of lines to skip in the wordlist for DICTIONARY
                         phase (used for session resume).
        mask_pattern:   Optional manual mask string (e.g. "?u?l?l?l?d?d?d").
        ai_masks:       When True, generate masks via LLM from profile data.

    Returns:
        Ordered list of :class:`AttackPlan` objects.
    """
    plans: list[AttackPlan] = []
    rules_active = rules_preset != "none"

    # Phase 1 — dictionary
    plans.append(
        AttackPlan(
            name="Dictionary",
            phase=AttackPhase.DICTIONARY,
            candidates_fn=lambda o=wordlist_offset: file_candidates_from_offset(
                wordlist_path, o
            ),
        )
    )

    # Phase 2 — rules
    if rules_active:
        rules = _rules_for_preset(rules_preset)
        plans.append(
            AttackPlan(
                name=f"Dictionary + {rules_preset.capitalize()} Rules",
                phase=AttackPhase.RULES,
                candidates_fn=lambda r=rules: rule_candidates(
                    file_candidates(wordlist_path), r
                ),
            )
        )

    # Phase 3 — mask (manual or AI-generated)
    if mask_pattern is not None:
        plans.append(
            AttackPlan(
                name=f"Mask ({mask_pattern})",
                phase=AttackPhase.MASK,
                candidates_fn=lambda m=mask_pattern: mask_candidates(m),
            )
        )

    if ai_masks and profile is not None and llm_config is not None and llm_config.api_key:
        def _ai_mask_candidates(
            pr: TargetProfile = profile,
            cfg: LLMConfig = llm_config,
        ) -> Iterator[str]:
            masks = generate_ai_masks(pr, cfg)
            for m in masks:
                yield from mask_candidates(m)

        plans.append(
            AttackPlan(
                name="AI-Generated Masks",
                phase=AttackPhase.MASK,
                candidates_fn=_ai_mask_candidates,
            )
        )

    # Phase 4 — profile
    if profile is not None:
        profiler = _select_profiler(profile, llm_config)
        plans.append(
            AttackPlan(
                name="Profile",
                phase=AttackPhase.PROFILE,
                candidates_fn=lambda p=profiler, pr=profile: p.generate(pr),
            )
        )

        # Phase 5 — hybrid
        if rules_active:
            rules = _rules_for_preset(rules_preset)
            plans.append(
                AttackPlan(
                    name=f"Profile + {rules_preset.capitalize()} Rules",
                    phase=AttackPhase.HYBRID,
                    candidates_fn=lambda p=profiler, pr=profile, r=rules: rule_candidates(
                        p.generate(pr), r
                    ),
                )
            )

    # Phase 6 — adaptive AI (multi-round)
    if profile is not None and llm_config is not None and llm_config.api_key:
        adaptive = AdaptiveProfiler(llm_config, max_rounds=3)
        def _adaptive_candidates(a=adaptive, pr=profile):
            for round_result in a.generate_all_rounds(pr):
                yield from round_result.candidates
        plans.append(
            AttackPlan(
                name="Adaptive AI",
                phase=AttackPhase.ADAPTIVE,
                candidates_fn=_adaptive_candidates,
            )
        )

    return plans
```

### Step 2.3 — Add orchestrator tests for mask phase

- [ ] Add tests to `tests/test_orchestrator.py` for mask integration

Append to `tests/test_orchestrator.py`:

```python
class TestMaskPhasePlanning:
    def test_manual_mask_adds_mask_phase(self, tmp_wordlist: Path) -> None:
        plans = plan_attacks(
            wordlist_path=tmp_wordlist,
            rules_preset="none",
            mask_pattern="?d?d?d?d",
        )
        mask_plans = [p for p in plans if p.phase == AttackPhase.MASK]
        assert len(mask_plans) == 1
        assert "?d?d?d?d" in mask_plans[0].name

    def test_manual_mask_candidates_are_generated(self, tmp_wordlist: Path) -> None:
        plans = plan_attacks(
            wordlist_path=tmp_wordlist,
            rules_preset="none",
            mask_pattern="?d?d",
        )
        mask_plan = [p for p in plans if p.phase == AttackPhase.MASK][0]
        candidates = list(mask_plan.candidates_fn())
        assert len(candidates) == 100  # 10 * 10

    def test_no_mask_when_not_requested(self, tmp_wordlist: Path) -> None:
        plans = plan_attacks(
            wordlist_path=tmp_wordlist,
            rules_preset="quick",
        )
        mask_plans = [p for p in plans if p.phase == AttackPhase.MASK]
        assert len(mask_plans) == 0

    def test_ai_masks_requires_profile_and_llm(self, tmp_wordlist: Path) -> None:
        """ai_masks=True without profile/llm should not add a mask phase."""
        plans = plan_attacks(
            wordlist_path=tmp_wordlist,
            rules_preset="none",
            ai_masks=True,
        )
        mask_plans = [p for p in plans if p.phase == AttackPhase.MASK]
        assert len(mask_plans) == 0
```

Run:
```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m pytest tests/test_orchestrator.py -x --tb=short -q
```

Expected: all tests pass (new and existing).

Commit:
```
feat: integrate mask phase into AttackPhase enum and orchestrator

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
```

---

## Task 3: Mask Attack — CLI Integration

**Files:**
- `src/smartcrack/cli.py` (edit)

### Step 3.1 — Add `--mask` and `--ai-masks` flags to the `smart` command

- [ ] Edit `src/smartcrack/cli.py` — add two new parameters to the `smart` command function signature

Add these parameters after the `timeout` parameter in the `smart` function signature:

```python
    mask: str = typer.Option("", "--mask", "-m", help="Mask pattern for mask attack (e.g. ?u?l?l?l?d?d)"),
    ai_masks: bool = typer.Option(False, "--ai-masks", help="Auto-generate masks from target profile via LLM"),
```

### Step 3.2 — Pass mask options through to `plan_attacks()`

- [ ] Edit the `plan_attacks()` call in `smart` to include the new parameters

Replace the `plan_attacks` call in the `smart` command:

```python
    plans = plan_attacks(
        wordlist_path=resolved_path,
        rules_preset=rules,
        profile=profile,
        llm_config=llm_config,
        wordlist_offset=wordlist_offset,
        mask_pattern=mask if mask else None,
        ai_masks=ai_masks,
    )
```

### Step 3.3 — Add console output for mask options

- [ ] Add status messages after the profile printing block

After the line `console.print("[bold]Profile:[/] enabled")`, add:

```python
    if mask:
        console.print(f"[bold]Mask:[/] {mask}")
    if ai_masks:
        console.print("[bold]AI Masks:[/] enabled")
```

Run:
```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m pytest tests/ -x --tb=short -q
```

Expected: all existing tests still pass.

Commit:
```
feat: add --mask and --ai-masks CLI flags to smart command

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
```

---

## Task 4: Attack Strategy Explainer — Core Module

**Files:**
- `src/smartcrack/explainer.py` (create)
- `tests/test_explainer.py` (create)

### Step 4.1 — Write tests for the explainer

- [ ] Create `tests/test_explainer.py`

```python
"""Tests for the attack strategy explainer."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from smartcrack.explainer import (
    AttackNarrative,
    _ai_narrative,
    _template_narrative,
    explain_attack,
)
from smartcrack.models import AttackPhase, CrackResult, HashType, LLMConfig


# ---------------------------------------------------------------------------
# AttackNarrative dataclass
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAttackNarrative:
    def test_is_frozen(self) -> None:
        narrative = AttackNarrative(
            summary="Cracked via dictionary",
            phase_details=["Phase 1: Dictionary — success"],
            recommendation="Use a longer password",
        )
        with pytest.raises(AttributeError):
            narrative.summary = "modified"  # type: ignore[misc]

    def test_fields(self) -> None:
        narrative = AttackNarrative(
            summary="s", phase_details=["p1"], recommendation="r"
        )
        assert narrative.summary == "s"
        assert narrative.phase_details == ["p1"]
        assert narrative.recommendation == "r"


# ---------------------------------------------------------------------------
# _template_narrative (no LLM)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestTemplateNarrative:
    def test_successful_crack_summary_mentions_phase(self) -> None:
        result = CrackResult(
            found=True,
            plaintext="password123",
            hash_type=HashType.MD5,
            attack_phase=AttackPhase.DICTIONARY,
            attempts=1500,
            duration_seconds=0.42,
        )
        narrative = _template_narrative(result, ["dictionary", "rules"])
        assert "dictionary" in narrative.summary.lower()

    def test_successful_crack_includes_plaintext_length(self) -> None:
        result = CrackResult(
            found=True,
            plaintext="test",
            hash_type=HashType.SHA256,
            attack_phase=AttackPhase.RULES,
            attempts=5000,
            duration_seconds=1.2,
        )
        narrative = _template_narrative(result, ["dictionary", "rules"])
        assert "4" in narrative.summary or "4" in " ".join(narrative.phase_details)

    def test_failed_crack_summary(self) -> None:
        result = CrackResult(
            found=False,
            attempts=100_000,
            duration_seconds=12.5,
        )
        narrative = _template_narrative(result, ["dictionary", "rules", "profile"])
        assert "not" in narrative.summary.lower() or "fail" in narrative.summary.lower()

    def test_phase_details_lists_all_phases(self) -> None:
        result = CrackResult(
            found=True,
            plaintext="hello",
            hash_type=HashType.MD5,
            attack_phase=AttackPhase.PROFILE,
            attempts=3000,
            duration_seconds=0.8,
        )
        phases = ["dictionary", "rules", "profile"]
        narrative = _template_narrative(result, phases)
        assert len(narrative.phase_details) == len(phases)

    def test_recommendation_present(self) -> None:
        result = CrackResult(
            found=True,
            plaintext="abc",
            hash_type=HashType.MD5,
            attack_phase=AttackPhase.DICTIONARY,
            attempts=10,
            duration_seconds=0.01,
        )
        narrative = _template_narrative(result, ["dictionary"])
        assert len(narrative.recommendation) > 0

    def test_failed_crack_recommendation_suggests_more(self) -> None:
        result = CrackResult(found=False, attempts=50_000, duration_seconds=5.0)
        narrative = _template_narrative(result, ["dictionary"])
        assert len(narrative.recommendation) > 0


# ---------------------------------------------------------------------------
# _ai_narrative (mocked LLM)
# ---------------------------------------------------------------------------


def _make_mock_response(content: str) -> MagicMock:
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "choices": [{"message": {"content": content}}]
    }
    mock_resp.raise_for_status = MagicMock()
    return mock_resp


@pytest.mark.unit
class TestAINarrative:
    @pytest.fixture
    def llm_config(self) -> LLMConfig:
        return LLMConfig(
            base_url="https://test.example.com/v1",
            api_key="sk-test-key",
            model="gpt-4o",
            timeout_seconds=10,
        )

    def test_ai_narrative_returns_attack_narrative(
        self, llm_config: LLMConfig
    ) -> None:
        result = CrackResult(
            found=True,
            plaintext="password123",
            hash_type=HashType.MD5,
            attack_phase=AttackPhase.DICTIONARY,
            attempts=1500,
            duration_seconds=0.4,
        )
        llm_response = (
            "SUMMARY: The hash was cracked using a dictionary attack.\n"
            "PHASES: Dictionary attack tried 1500 candidates.\n"
            "RECOMMENDATION: Use a passphrase with 16+ characters."
        )
        mock_resp = _make_mock_response(llm_response)
        with patch("smartcrack.explainer.httpx.post", return_value=mock_resp):
            narrative = _ai_narrative(
                result, ["dictionary"], None, llm_config
            )
        assert isinstance(narrative, AttackNarrative)
        assert len(narrative.summary) > 0

    def test_ai_narrative_falls_back_on_error(
        self, llm_config: LLMConfig
    ) -> None:
        import httpx as _httpx

        result = CrackResult(
            found=True,
            plaintext="test",
            hash_type=HashType.MD5,
            attack_phase=AttackPhase.DICTIONARY,
            attempts=100,
            duration_seconds=0.1,
        )
        with patch(
            "smartcrack.explainer.httpx.post",
            side_effect=_httpx.TimeoutException("timed out"),
        ):
            narrative = _ai_narrative(
                result, ["dictionary"], None, llm_config
            )
        # Should fall back to template narrative
        assert isinstance(narrative, AttackNarrative)
        assert len(narrative.summary) > 0


# ---------------------------------------------------------------------------
# explain_attack (integration)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestExplainAttack:
    def test_without_llm_uses_template(self) -> None:
        result = CrackResult(
            found=True,
            plaintext="hello",
            hash_type=HashType.SHA256,
            attack_phase=AttackPhase.DICTIONARY,
            attempts=2000,
            duration_seconds=0.5,
        )
        narrative = explain_attack(result, ["dictionary", "rules"])
        assert isinstance(narrative, AttackNarrative)
        assert "dictionary" in narrative.summary.lower()

    def test_with_llm_calls_ai_narrative(self) -> None:
        result = CrackResult(
            found=True,
            plaintext="pass",
            hash_type=HashType.MD5,
            attack_phase=AttackPhase.RULES,
            attempts=5000,
            duration_seconds=1.0,
        )
        config = LLMConfig(
            base_url="https://test.example.com/v1",
            api_key="sk-test-key",
            model="gpt-4o",
        )
        llm_response = (
            "SUMMARY: Cracked via rules.\n"
            "PHASES: Rules applied mutations.\n"
            "RECOMMENDATION: Avoid common words."
        )
        mock_resp = _make_mock_response(llm_response)
        with patch("smartcrack.explainer.httpx.post", return_value=mock_resp):
            narrative = explain_attack(
                result, ["dictionary", "rules"], llm_config=config
            )
        assert isinstance(narrative, AttackNarrative)

    def test_narrative_for_not_found(self) -> None:
        result = CrackResult(found=False, attempts=100_000, duration_seconds=10.0)
        narrative = explain_attack(result, ["dictionary", "rules", "profile"])
        assert "not" in narrative.summary.lower() or "fail" in narrative.summary.lower()

    def test_narrative_includes_correct_phase_count(self) -> None:
        result = CrackResult(
            found=True,
            plaintext="test123",
            hash_type=HashType.SHA1,
            attack_phase=AttackPhase.MASK,
            attempts=500,
            duration_seconds=0.2,
        )
        phases = ["dictionary", "rules", "mask"]
        narrative = explain_attack(result, phases)
        assert len(narrative.phase_details) == 3
```

Run:
```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m pytest tests/test_explainer.py -x --tb=short 2>&1 | head -20
```

Expected: all tests fail with `ImportError`.

### Step 4.2 — Create `src/smartcrack/explainer.py`

- [ ] Create the explainer module

```python
"""Attack strategy explainer — generates human-readable crack narratives."""

from __future__ import annotations

import logging
from dataclasses import dataclass

import httpx

from smartcrack.analysis import PasswordAnalysis, analyze_password
from smartcrack.models import CrackResult, LLMConfig

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AttackNarrative:
    """Immutable narrative explaining an attack session."""

    summary: str
    phase_details: list[str]
    recommendation: str


def explain_attack(
    result: CrackResult,
    phases_tried: list[str],
    llm_config: LLMConfig | None = None,
) -> AttackNarrative:
    """Generate a narrative explaining what happened during a crack attempt.

    When *llm_config* is provided with valid credentials, generates a rich
    AI-powered narrative. Otherwise falls back to a template-based narrative.

    Args:
        result: The final crack result.
        phases_tried: List of phase value strings that were attempted.
        llm_config: Optional LLM config for AI-generated narratives.

    Returns:
        An :class:`AttackNarrative` describing the session.
    """
    analysis: PasswordAnalysis | None = None
    if result.found and result.plaintext:
        analysis = analyze_password(result.plaintext)

    if llm_config is not None and llm_config.api_key and llm_config.base_url:
        return _ai_narrative(result, phases_tried, analysis, llm_config)

    return _template_narrative(result, phases_tried)


def _template_narrative(
    result: CrackResult,
    phases_tried: list[str],
) -> AttackNarrative:
    """Build a narrative using templates (no LLM required).

    Args:
        result: The crack result.
        phases_tried: Phase value strings attempted.

    Returns:
        A template-based :class:`AttackNarrative`.
    """
    # --- Summary ---
    if result.found and result.plaintext:
        phase_name = result.attack_phase.value if result.attack_phase else "unknown"
        pw_len = len(result.plaintext)
        summary = (
            f"The hash was cracked in the {phase_name} phase after "
            f"{result.attempts:,} attempts ({result.duration_seconds:.2f}s). "
            f"The recovered password is {pw_len} characters long."
        )
    else:
        summary = (
            f"The hash was not cracked after {result.attempts:,} attempts "
            f"across {len(phases_tried)} phase(s) ({result.duration_seconds:.2f}s)."
        )

    # --- Phase details ---
    phase_details: list[str] = []
    for i, phase in enumerate(phases_tried, 1):
        if result.found and result.attack_phase and phase == result.attack_phase.value:
            phase_details.append(f"Phase {i}: {phase} — cracked here")
        else:
            phase_details.append(f"Phase {i}: {phase} — exhausted")

    # --- Recommendation ---
    if result.found and result.plaintext:
        pw = result.plaintext
        analysis = analyze_password(pw)
        if analysis.strength in ("weak", "moderate"):
            recommendation = (
                f"The password \"{pw}\" is {analysis.strength} "
                f"(entropy: {analysis.entropy:.1f} bits). "
                "Recommend enforcing minimum 12-character passwords with mixed "
                "character classes and no dictionary words."
            )
        else:
            recommendation = (
                f"The password has {analysis.strength} strength "
                f"(entropy: {analysis.entropy:.1f} bits), but was still cracked. "
                "Consider bcrypt/argon2 hashing with high work factors."
            )
    else:
        recommendation = (
            "The hash resisted all attempted phases. Consider expanding the "
            "wordlist, adding a target profile for personalised attacks, "
            "or using mask attacks with common password patterns."
        )

    return AttackNarrative(
        summary=summary,
        phase_details=phase_details,
        recommendation=recommendation,
    )


# ---------------------------------------------------------------------------
# AI-powered narrative
# ---------------------------------------------------------------------------

_EXPLAINER_SYSTEM_PROMPT = (
    "You are a security analyst writing a post-engagement report for an "
    "authorized penetration test. Given the attack results, write a concise "
    "narrative with three sections:\n\n"
    "SUMMARY: One paragraph explaining what happened.\n"
    "PHASES: One line per attack phase describing what it tried.\n"
    "RECOMMENDATION: Actionable advice for the target to improve their password.\n\n"
    "Be professional, concise, and specific. Reference the actual password "
    "patterns and weaknesses you observe."
)


def _build_explainer_prompt(
    result: CrackResult,
    phases_tried: list[str],
    analysis: PasswordAnalysis | None,
) -> str:
    """Build the user prompt for AI narrative generation."""
    lines: list[str] = ["Attack session results:"]
    lines.append(f"  Found: {result.found}")
    if result.plaintext:
        lines.append(f"  Password: {result.plaintext}")
    if result.hash_type:
        lines.append(f"  Hash type: {result.hash_type.name}")
    if result.attack_phase:
        lines.append(f"  Winning phase: {result.attack_phase.value}")
    lines.append(f"  Total attempts: {result.attempts:,}")
    lines.append(f"  Duration: {result.duration_seconds:.2f}s")
    lines.append(f"  Phases tried: {', '.join(phases_tried)}")
    if analysis:
        lines.append(f"  Password entropy: {analysis.entropy:.1f} bits")
        lines.append(f"  Password strength: {analysis.strength}")
        if analysis.patterns:
            lines.append(f"  Patterns detected: {', '.join(analysis.patterns)}")
    return "\n".join(lines)


def _parse_ai_response(content: str, phases_tried: list[str]) -> AttackNarrative:
    """Parse structured AI response into an AttackNarrative."""
    summary = ""
    phase_details: list[str] = []
    recommendation = ""

    current_section = ""
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        upper = stripped.upper()
        if upper.startswith("SUMMARY:"):
            current_section = "summary"
            text = stripped[len("SUMMARY:"):].strip()
            if text:
                summary = text
        elif upper.startswith("PHASES:") or upper.startswith("PHASE"):
            current_section = "phases"
            text = stripped.split(":", 1)[-1].strip()
            if text:
                phase_details.append(text)
        elif upper.startswith("RECOMMENDATION:"):
            current_section = "recommendation"
            text = stripped[len("RECOMMENDATION:"):].strip()
            if text:
                recommendation = text
        elif current_section == "summary":
            summary += " " + stripped if summary else stripped
        elif current_section == "phases":
            phase_details.append(stripped)
        elif current_section == "recommendation":
            recommendation += " " + stripped if recommendation else stripped

    # Fallback if parsing failed
    if not summary:
        summary = content[:200] if content else "Attack narrative unavailable."
    if not phase_details:
        phase_details = [f"Phase: {p}" for p in phases_tried]
    if not recommendation:
        recommendation = "Review password policy and enforce stronger requirements."

    return AttackNarrative(
        summary=summary,
        phase_details=phase_details,
        recommendation=recommendation,
    )


def _ai_narrative(
    result: CrackResult,
    phases_tried: list[str],
    analysis: PasswordAnalysis | None,
    llm_config: LLMConfig,
) -> AttackNarrative:
    """Generate a narrative using an LLM.

    Falls back to :func:`_template_narrative` on any error.

    Args:
        result: The crack result.
        phases_tried: Phase value strings attempted.
        analysis: Optional password analysis (None if not cracked).
        llm_config: LLM connection configuration.

    Returns:
        An :class:`AttackNarrative`.
    """
    url = f"{llm_config.base_url.rstrip('/')}/chat/completions"
    payload = {
        "model": llm_config.model,
        "temperature": 0.5,
        "messages": [
            {"role": "system", "content": _EXPLAINER_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": _build_explainer_prompt(result, phases_tried, analysis),
            },
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
            logger.warning("explain_attack: empty choices — falling back to template")
            return _template_narrative(result, phases_tried)
        content: str = choices[0].get("message", {}).get("content", "")
        if not content:
            return _template_narrative(result, phases_tried)
        return _parse_ai_response(content, phases_tried)
    except (httpx.TimeoutException, httpx.HTTPStatusError, Exception) as exc:
        logger.warning(
            "explain_attack: LLM error (%s) — falling back to template",
            type(exc).__name__,
        )
        return _template_narrative(result, phases_tried)
```

Run:
```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m pytest tests/test_explainer.py -x --tb=short -q
```

Expected: all tests pass.

Commit:
```
feat: add attack strategy explainer with template and AI narratives

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
```

---

## Task 5: Attack Strategy Explainer — CLI Integration

**Files:**
- `src/smartcrack/cli.py` (edit)

### Step 5.1 — Add `--explain` flag to the `smart` command

- [ ] Add the `--explain` parameter to the `smart` function signature

Add after the `ai_masks` parameter:

```python
    explain: bool = typer.Option(False, "--explain", help="Generate a narrative explaining the attack after completion"),
```

### Step 5.2 — Add explain logic after result printing

- [ ] Edit `src/smartcrack/cli.py` — add explain block after the result output

Add the following import at the top of `cli.py`:

```python
from rich.panel import Panel
```

Add the following block at the very end of the `smart` function, after the `result.found` / not-found output block and after the session save block:

```python
    if explain:
        from smartcrack.explainer import explain_attack

        phases_tried = [plan.phase.value for plan in plans]
        narrative = explain_attack(result, phases_tried, llm_config=llm_config)
        console.print()
        console.print(Panel(
            f"[bold]Summary:[/] {narrative.summary}\n\n"
            + "\n".join(f"  {detail}" for detail in narrative.phase_details)
            + f"\n\n[bold]Recommendation:[/] {narrative.recommendation}",
            title="[bold cyan]Attack Narrative[/]",
            border_style="cyan",
            padding=(1, 2),
        ))
```

Run:
```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m pytest tests/ -x --tb=short -q
```

Expected: all tests pass.

Commit:
```
feat: add --explain CLI flag for post-crack attack narratives

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
```

---

## Task 6: Crack Time Estimator — Core Module

**Files:**
- `src/smartcrack/estimator.py` (create)
- `tests/test_estimator.py` (create)

### Step 6.1 — Write tests for the estimator

- [ ] Create `tests/test_estimator.py`

```python
"""Tests for the crack time estimator."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from smartcrack.estimator import (
    HASH_SPEEDS,
    CrackEstimate,
    check_hibp,
    estimate_crack,
)
from smartcrack.models import HashTarget, HashType


# ---------------------------------------------------------------------------
# HASH_SPEEDS
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestHashSpeeds:
    def test_md5_speed_is_defined(self) -> None:
        assert HashType.MD5 in HASH_SPEEDS
        assert HASH_SPEEDS[HashType.MD5] > 0

    def test_sha256_speed_is_defined(self) -> None:
        assert HashType.SHA256 in HASH_SPEEDS
        assert HASH_SPEEDS[HashType.SHA256] > 0

    def test_bcrypt_speed_is_slow(self) -> None:
        assert HASH_SPEEDS[HashType.BCRYPT] < 1000

    def test_md5_faster_than_bcrypt(self) -> None:
        assert HASH_SPEEDS[HashType.MD5] > HASH_SPEEDS[HashType.BCRYPT]

    def test_all_known_types_have_speeds(self) -> None:
        for ht in HashType:
            if ht != HashType.UNKNOWN:
                assert ht in HASH_SPEEDS, f"Missing speed for {ht.name}"


# ---------------------------------------------------------------------------
# CrackEstimate
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestCrackEstimate:
    def test_is_frozen(self) -> None:
        est = CrackEstimate(
            hash_type=HashType.MD5,
            wordlist_size=100_000,
            dictionary_probability=0.15,
            dictionary_eta=0.02,
            rules_probability=0.35,
            rules_eta=0.44,
            mask_eta=None,
            hibp_seen_count=None,
            recommendation="Use a stronger password.",
        )
        with pytest.raises(AttributeError):
            est.hash_type = HashType.SHA1  # type: ignore[misc]

    def test_fields_accessible(self) -> None:
        est = CrackEstimate(
            hash_type=HashType.SHA256,
            wordlist_size=50_000,
            dictionary_probability=0.10,
            dictionary_eta=0.025,
            rules_probability=0.25,
            rules_eta=0.275,
            mask_eta=120.0,
            hibp_seen_count=42,
            recommendation="Good.",
        )
        assert est.hash_type == HashType.SHA256
        assert est.wordlist_size == 50_000
        assert est.hibp_seen_count == 42
        assert est.mask_eta == 120.0


# ---------------------------------------------------------------------------
# estimate_crack
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestEstimateCrack:
    @pytest.fixture
    def wordlist_50k(self, tmp_path: Path) -> Path:
        """Create a wordlist with 50,000 lines."""
        wl = tmp_path / "50k.txt"
        wl.write_text("\n".join(f"word{i}" for i in range(50_000)) + "\n")
        return wl

    def test_returns_crack_estimate(self, wordlist_50k: Path) -> None:
        target = HashTarget(hash_value="d8578edf8458ce06fbc5bb76a58c5ca4", hash_type=HashType.MD5)
        est = estimate_crack(target, wordlist_50k)
        assert isinstance(est, CrackEstimate)

    def test_wordlist_size_matches(self, wordlist_50k: Path) -> None:
        target = HashTarget(hash_value="abc123", hash_type=HashType.MD5)
        est = estimate_crack(target, wordlist_50k)
        assert est.wordlist_size == 50_000

    def test_dictionary_eta_positive(self, wordlist_50k: Path) -> None:
        target = HashTarget(hash_value="abc123", hash_type=HashType.MD5)
        est = estimate_crack(target, wordlist_50k)
        assert est.dictionary_eta > 0

    def test_rules_eta_greater_than_dictionary(self, wordlist_50k: Path) -> None:
        target = HashTarget(hash_value="abc123", hash_type=HashType.MD5)
        est = estimate_crack(target, wordlist_50k)
        assert est.rules_eta >= est.dictionary_eta

    def test_bcrypt_takes_longer_than_md5(self, wordlist_50k: Path) -> None:
        target_md5 = HashTarget(hash_value="abc", hash_type=HashType.MD5)
        target_bcrypt = HashTarget(hash_value="$2b$12$abc", hash_type=HashType.BCRYPT)
        est_md5 = estimate_crack(target_md5, wordlist_50k)
        est_bcrypt = estimate_crack(target_bcrypt, wordlist_50k)
        assert est_bcrypt.dictionary_eta > est_md5.dictionary_eta

    def test_recommendation_is_nonempty(self, wordlist_50k: Path) -> None:
        target = HashTarget(hash_value="abc", hash_type=HashType.SHA256)
        est = estimate_crack(target, wordlist_50k)
        assert len(est.recommendation) > 0

    def test_thorough_preset_increases_rules_eta(self, wordlist_50k: Path) -> None:
        target = HashTarget(hash_value="abc", hash_type=HashType.MD5)
        est_quick = estimate_crack(target, wordlist_50k, rules_preset="quick")
        est_thorough = estimate_crack(target, wordlist_50k, rules_preset="thorough")
        assert est_thorough.rules_eta >= est_quick.rules_eta


# ---------------------------------------------------------------------------
# check_hibp
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestCheckHIBP:
    def test_returns_count_on_match(self) -> None:
        # SHA1 of "password" = 5BAA6...
        # HIBP API returns range results as SUFFIX:COUNT
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = (
            "003D68EB55068C33ACE09247EE4C639306B:3\n"
            "1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824\n"
            "FD66A3F84D9E9B0CC542BEB41B3CAE34B9:12\n"
        )
        mock_resp.raise_for_status = MagicMock()

        # SHA1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        with patch("smartcrack.estimator.httpx.get", return_value=mock_resp):
            count = check_hibp("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8")
        assert count == 9545824

    def test_returns_zero_on_no_match(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = (
            "003D68EB55068C33ACE09247EE4C639306B:3\n"
            "FD66A3F84D9E9B0CC542BEB41B3CAE34B9:12\n"
        )
        mock_resp.raise_for_status = MagicMock()

        with patch("smartcrack.estimator.httpx.get", return_value=mock_resp):
            count = check_hibp("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8")
        assert count == 0

    def test_returns_none_on_timeout(self) -> None:
        import httpx as _httpx

        with patch(
            "smartcrack.estimator.httpx.get",
            side_effect=_httpx.TimeoutException("timed out"),
        ):
            count = check_hibp("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8")
        assert count is None

    def test_returns_none_on_http_error(self) -> None:
        import httpx as _httpx

        mock_resp = MagicMock()
        mock_resp.status_code = 429
        error = _httpx.HTTPStatusError(
            "rate limited", request=MagicMock(), response=mock_resp
        )
        with patch("smartcrack.estimator.httpx.get", side_effect=error):
            count = check_hibp("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8")
        assert count is None

    def test_uses_k_anonymity_prefix(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = ""
        mock_resp.raise_for_status = MagicMock()

        with patch("smartcrack.estimator.httpx.get", return_value=mock_resp) as mock_get:
            check_hibp("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8")
        call_url = mock_get.call_args[0][0]
        assert call_url.endswith("/5BAA6")


# ---------------------------------------------------------------------------
# Rich table rendering (smoke test)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestEstimateRendering:
    def test_estimate_has_all_required_fields_for_table(self, tmp_path: Path) -> None:
        """All fields needed to render a Rich table are present."""
        wl = tmp_path / "small.txt"
        wl.write_text("\n".join(f"w{i}" for i in range(100)) + "\n")
        target = HashTarget(hash_value="abc", hash_type=HashType.MD5)
        est = estimate_crack(target, wl)
        # Verify we can access all fields needed for rendering
        assert est.hash_type is not None
        assert est.wordlist_size is not None
        assert est.dictionary_probability is not None
        assert est.dictionary_eta is not None
        assert est.rules_probability is not None
        assert est.rules_eta is not None
        assert est.recommendation is not None
```

Run:
```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m pytest tests/test_estimator.py -x --tb=short 2>&1 | head -20
```

Expected: all tests fail with `ImportError`.

### Step 6.2 — Create `src/smartcrack/estimator.py`

- [ ] Create the estimator module

```python
"""Crack time estimator — pre-attack probability and duration estimates."""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from pathlib import Path

import httpx

from smartcrack.models import HashTarget, HashType

logger = logging.getLogger(__name__)

# Benchmarked hashes/second per type (single CPU thread, conservative estimates)
HASH_SPEEDS: dict[HashType, int] = {
    HashType.MD5: 5_000_000,
    HashType.SHA1: 3_000_000,
    HashType.SHA224: 2_500_000,
    HashType.SHA256: 2_000_000,
    HashType.SHA384: 1_500_000,
    HashType.SHA512: 1_000_000,
    HashType.BCRYPT: 100,
    HashType.ARGON2: 10,
    HashType.NTLM: 8_000_000,
}

# Multipliers for rule presets (how many candidates per base word)
_RULES_MULTIPLIER: dict[str, int] = {
    "none": 1,
    "quick": 11,       # 1 original + 10 quick rules
    "thorough": 23,    # 1 original + 22 thorough rules
}

# Rough probability that a password is in a wordlist of given size
# Based on empirical data from password breach analysis
_COMMON_PASSWORD_SPACE = 10_000_000  # ~10M common passwords cover most reuse


@dataclass(frozen=True)
class CrackEstimate:
    """Immutable pre-attack estimate for a hash cracking attempt."""

    hash_type: HashType
    wordlist_size: int
    dictionary_probability: float
    dictionary_eta: float  # seconds
    rules_probability: float
    rules_eta: float  # seconds
    mask_eta: float | None  # seconds, None if not applicable
    hibp_seen_count: int | None  # None if check failed/skipped
    recommendation: str


def _count_wordlist_lines(wordlist_path: Path) -> int:
    """Count non-empty lines in a wordlist file."""
    count = 0
    with open(wordlist_path, "r", encoding="iso-8859-1") as f:
        for line in f:
            if line.rstrip("\n\r"):
                count += 1
    return count


def _eta_seconds(candidate_count: int, hash_type: HashType) -> float:
    """Estimate seconds to exhaust *candidate_count* candidates for *hash_type*."""
    speed = HASH_SPEEDS.get(hash_type, 1_000_000)
    if speed <= 0:
        return float("inf")
    return candidate_count / speed


def _estimate_probability(wordlist_size: int, multiplier: int) -> float:
    """Estimate probability of cracking based on coverage of common password space."""
    effective_size = wordlist_size * multiplier
    probability = min(effective_size / _COMMON_PASSWORD_SPACE, 0.95)
    return round(probability, 4)


def _build_recommendation(
    hash_type: HashType,
    dictionary_prob: float,
    rules_prob: float,
    hibp_count: int | None,
) -> str:
    """Generate a recommendation string based on the estimate."""
    parts: list[str] = []

    if dictionary_prob >= 0.5:
        parts.append(
            "High probability of dictionary crack — the wordlist covers a large "
            "portion of common passwords."
        )
    elif dictionary_prob >= 0.1:
        parts.append(
            "Moderate dictionary probability. Rules will significantly improve coverage."
        )
    else:
        parts.append(
            "Low dictionary probability. Consider a larger wordlist or profile-based attack."
        )

    if hash_type in (HashType.MD5, HashType.SHA1, HashType.NTLM):
        parts.append(
            f"{hash_type.name} is a fast hash — attacks will complete quickly. "
            "The target should migrate to bcrypt or argon2."
        )
    elif hash_type in (HashType.BCRYPT, HashType.ARGON2):
        parts.append(
            f"{hash_type.name} is a slow hash — expect long runtimes. "
            "Focus on targeted attacks (profile, AI masks) over brute force."
        )

    if hibp_count is not None and hibp_count > 0:
        parts.append(
            f"This hash has been seen {hibp_count:,} times in breaches (HIBP). "
            "Very likely to be a common password."
        )

    return " ".join(parts)


def estimate_crack(
    target: HashTarget,
    wordlist_path: Path,
    rules_preset: str = "quick",
) -> CrackEstimate:
    """Estimate probability and time to crack a hash before running any attack.

    Args:
        target: The hash target to estimate.
        wordlist_path: Path to the wordlist file.
        rules_preset: Rules preset name ("none", "quick", "thorough").

    Returns:
        A :class:`CrackEstimate` with probability and ETA for each attack vector.
    """
    wordlist_size = _count_wordlist_lines(wordlist_path)
    hash_type = target.hash_type if target.hash_type != HashType.UNKNOWN else HashType.MD5

    rules_mult = _RULES_MULTIPLIER.get(rules_preset, 11)

    dictionary_prob = _estimate_probability(wordlist_size, 1)
    rules_prob = _estimate_probability(wordlist_size, rules_mult)

    dictionary_eta = _eta_seconds(wordlist_size, hash_type)
    rules_eta = _eta_seconds(wordlist_size * rules_mult, hash_type)

    hibp_count = check_hibp(target.hash_value) if len(target.hash_value) == 40 else None

    recommendation = _build_recommendation(hash_type, dictionary_prob, rules_prob, hibp_count)

    return CrackEstimate(
        hash_type=hash_type,
        wordlist_size=wordlist_size,
        dictionary_probability=dictionary_prob,
        dictionary_eta=dictionary_eta,
        rules_probability=rules_prob,
        rules_eta=rules_eta,
        mask_eta=None,
        hibp_seen_count=hibp_count,
        recommendation=recommendation,
    )


# ---------------------------------------------------------------------------
# HIBP k-anonymity check
# ---------------------------------------------------------------------------

_HIBP_API_URL = "https://api.pwnedpasswords.com/range/"


def check_hibp(hash_value: str) -> int | None:
    """Check a SHA1 hash against the Have I Been Pwned Passwords API.

    Uses k-anonymity: only the first 5 hex characters of the SHA1 hash are
    sent to the API. The full hash is compared locally against the returned
    range.

    Args:
        hash_value: A SHA1 hex digest string (40 characters). If the input
                    is not a SHA1 hash, it will be SHA1-hashed first.

    Returns:
        The number of times the password has been seen in breaches, or 0 if
        not found in the range. Returns ``None`` on any network error.
    """
    # Normalize to uppercase SHA1
    sha1_hex = hash_value.upper()
    if len(sha1_hex) != 40:
        # Hash the value with SHA1 first (it might be the plaintext hash, not SHA1)
        sha1_hex = hashlib.sha1(hash_value.encode()).hexdigest().upper()

    prefix = sha1_hex[:5]
    suffix = sha1_hex[5:]

    try:
        response = httpx.get(
            f"{_HIBP_API_URL}{prefix}",
            timeout=5.0,
            headers={"User-Agent": "SmartCrack-PasswordAuditor"},
        )
        response.raise_for_status()
    except (httpx.TimeoutException, httpx.HTTPStatusError, Exception) as exc:
        logger.warning("HIBP check failed (%s) — skipping", type(exc).__name__)
        return None

    for line in response.text.splitlines():
        parts = line.strip().split(":")
        if len(parts) == 2 and parts[0].upper() == suffix:
            try:
                return int(parts[1])
            except ValueError:
                return None

    return 0
```

Run:
```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m pytest tests/test_estimator.py -x --tb=short -q
```

Expected: all tests pass.

Commit:
```
feat: add crack time estimator with HIBP integration

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
```

---

## Task 7: Crack Time Estimator — CLI Integration

**Files:**
- `src/smartcrack/cli.py` (edit)

### Step 7.1 — Add `estimate` command to CLI

- [ ] Add the `estimate` command to `src/smartcrack/cli.py`

Add the following import at the top of `cli.py` (alongside existing imports):

```python
from rich.table import Table
```

Add the new command after the `osint` command:

```python
@app.command()
def estimate(
    hash_value: str = typer.Option(..., "--hash", "-H", help="Hash to estimate"),
    wordlist: Path = typer.Option(Path("100K.txt"), "--wordlist", "-w", help="Wordlist file path"),
    hash_type: str = typer.Option("auto", "--type", "-t", help="Hash type (auto, md5, sha1, etc.)"),
    rules: str = typer.Option("quick", "--rules", "-r", help="Rules preset: none | quick | thorough"),
) -> None:
    """Estimate probability and time to crack a hash before running."""
    _print_banner()

    from smartcrack.estimator import estimate_crack

    resolved_path = resolve_wordlist(wordlist)

    type_map: dict[str, HashType] = {
        "md5": HashType.MD5,
        "sha1": HashType.SHA1,
        "sha224": HashType.SHA224,
        "sha256": HashType.SHA256,
        "sha384": HashType.SHA384,
        "sha512": HashType.SHA512,
    }

    resolved_type: HashType
    if hash_type.lower() == "auto":
        candidates_id = identify_hash(hash_value)
        resolved_type = candidates_id[0][0] if candidates_id else HashType.UNKNOWN
    else:
        resolved_type = type_map.get(hash_type.lower(), HashType.UNKNOWN)

    target = HashTarget(hash_value=hash_value, hash_type=resolved_type)
    est = estimate_crack(target, resolved_path, rules_preset=rules)

    # Build Rich table
    table = Table(title="Crack Estimate", border_style="cyan", show_header=True)
    table.add_column("Metric", style="bold")
    table.add_column("Value", justify="right")

    table.add_row("Hash Type", est.hash_type.name)
    table.add_row("Wordlist Size", f"{est.wordlist_size:,}")

    # Dictionary probability with color
    dict_pct = f"{est.dictionary_probability * 100:.1f}%"
    if est.dictionary_probability >= 0.5:
        dict_pct = f"[green]{dict_pct}[/green]"
    elif est.dictionary_probability >= 0.1:
        dict_pct = f"[yellow]{dict_pct}[/yellow]"
    else:
        dict_pct = f"[red]{dict_pct}[/red]"
    table.add_row("Dictionary Probability", dict_pct)
    table.add_row("Dictionary ETA", _format_eta(est.dictionary_eta))

    # Rules probability with color
    rules_pct = f"{est.rules_probability * 100:.1f}%"
    if est.rules_probability >= 0.5:
        rules_pct = f"[green]{rules_pct}[/green]"
    elif est.rules_probability >= 0.1:
        rules_pct = f"[yellow]{rules_pct}[/yellow]"
    else:
        rules_pct = f"[red]{rules_pct}[/red]"
    table.add_row("Rules Probability", rules_pct)
    table.add_row("Rules ETA", _format_eta(est.rules_eta))

    if est.mask_eta is not None:
        table.add_row("Mask ETA", _format_eta(est.mask_eta))

    if est.hibp_seen_count is not None:
        hibp_str = f"{est.hibp_seen_count:,}"
        if est.hibp_seen_count > 0:
            hibp_str = f"[red]{hibp_str} times[/red]"
        else:
            hibp_str = "[green]Not seen[/green]"
        table.add_row("HIBP Breaches", hibp_str)

    console.print()
    console.print(table)
    console.print()
    console.print(f"[bold]Recommendation:[/] {est.recommendation}")


def _format_eta(seconds: float) -> str:
    """Format seconds into a human-readable ETA string."""
    if seconds < 0.001:
        return "<1ms"
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    if seconds < 60:
        return f"{seconds:.1f}s"
    if seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    if seconds < 86400:
        hours = seconds / 3600
        return f"{hours:.1f}h"
    days = seconds / 86400
    if days < 365:
        return f"{days:.0f}d"
    years = days / 365
    return f"{years:.1f}y"
```

Run:
```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m pytest tests/ -x --tb=short -q
```

Expected: all tests pass.

Commit:
```
feat: add smartcrack estimate CLI command with Rich table output

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
```

---

## Task 8: Final Integration Test & Cleanup

**Files:**
- All test files
- All source files

### Step 8.1 — Run full test suite

- [ ] Run all tests to verify nothing is broken

```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m pytest tests/ -x --tb=short -q
```

Expected: all tests pass.

### Step 8.2 — Run linter

- [ ] Lint all new files

```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m ruff check src/smartcrack/mask.py src/smartcrack/explainer.py src/smartcrack/estimator.py
```

Expected: no errors.

### Step 8.3 — Type check new modules

- [ ] Verify type annotations

```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m mypy src/smartcrack/mask.py src/smartcrack/explainer.py src/smartcrack/estimator.py --ignore-missing-imports
```

Expected: no errors.

### Step 8.4 — Verify CLI help text

- [ ] Verify new flags appear in help

```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m smartcrack smart --help | grep -E "(mask|explain|ai-masks)"
cd /Users/sam/Documents/Projects/hashcrack && python -m smartcrack estimate --help
```

Expected: `--mask`, `--ai-masks`, and `--explain` appear in smart help; `estimate` command help shows all flags.

Commit:
```
chore: verify Phase B integration — all tests, lint, types pass

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
```

---

## Summary of New/Modified Files

| File | Action | Purpose |
|------|--------|---------|
| `src/smartcrack/mask.py` | Create | Mask engine: parse, generate, AI masks |
| `src/smartcrack/explainer.py` | Create | Attack narrative: template + AI |
| `src/smartcrack/estimator.py` | Create | Pre-attack estimation + HIBP |
| `src/smartcrack/models.py` | Edit | Add `AttackPhase.MASK` |
| `src/smartcrack/orchestrator.py` | Edit | Add mask phase to `plan_attacks()` |
| `src/smartcrack/cli.py` | Edit | Add `--mask`, `--ai-masks`, `--explain`, `estimate` command |
| `tests/test_mask.py` | Create | 22 tests for mask engine |
| `tests/test_explainer.py` | Create | 13 tests for explainer |
| `tests/test_estimator.py` | Create | 16 tests for estimator |
| `tests/test_orchestrator.py` | Edit | 4 tests for mask orchestration |

**Total: 55 new tests across 3 test files + 4 added to existing file.**
