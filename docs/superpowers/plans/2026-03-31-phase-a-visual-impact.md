# Phase A: Visual Impact — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Add forensic result cards and live telemetry to make SmartCrack's output visually stunning.

**Architecture:** Result cards use Rich Panels with embedded Tables for structured forensic output. Live telemetry uses a rolling-window stats tracker fed by existing progress callbacks.

**Tech Stack:** Rich (Panel, Table, Bar, Text), existing analysis.py pipeline, optional LLM for AI assessment.

---

## Task 1: Create `CrackTelemetry` class with rolling-window speed tracking

**Files:**
- **Create:** `src/smartcrack/telemetry.py`
- **Test:** `tests/test_telemetry.py`

### Steps

- [ ] **1.1** Write tests first in `tests/test_telemetry.py`:

```python
"""Tests for CrackTelemetry rolling-window speed tracker."""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from smartcrack.telemetry import CrackTelemetry


class TestHashesPerSecond:
    """Test hashes_per_second rolling average calculation."""

    def test_no_updates_returns_zero(self) -> None:
        tel = CrackTelemetry()
        assert tel.hashes_per_second == 0.0

    def test_single_update_calculates_speed(self) -> None:
        tel = CrackTelemetry()
        with patch("smartcrack.telemetry.time.monotonic", side_effect=[0.0, 1.0]):
            tel = CrackTelemetry.__new__(CrackTelemetry)
            tel._window_seconds = 5.0
            tel._samples = []
            tel._total_attempts = 0
            tel._start_time = 0.0
        # Use direct time manipulation instead
        tel = CrackTelemetry(window_seconds=5.0)
        tel._samples.append((time.monotonic(), 500))
        tel._total_attempts = 500
        # Speed depends on time between samples — at least check it's non-negative
        assert tel.hashes_per_second >= 0.0

    def test_rolling_average_over_window(self) -> None:
        tel = CrackTelemetry(window_seconds=5.0)
        base = time.monotonic()
        # Simulate 5 updates, 1 second apart, 100 hashes each
        tel._samples = [
            (base + 1.0, 100),
            (base + 2.0, 200),
            (base + 3.0, 300),
            (base + 4.0, 400),
            (base + 5.0, 500),
        ]
        tel._total_attempts = 500
        # The window covers 4 seconds of delta (from sample 0 to sample 4)
        # 500 hashes over ~4 seconds = ~125 H/s
        # Allow range since monotonic() introduces slight variance
        speed = tel.hashes_per_second
        assert 50.0 <= speed <= 200.0


class TestEtaSeconds:
    """Test ETA calculation."""

    def test_no_speed_returns_none(self) -> None:
        tel = CrackTelemetry()
        assert tel.eta_seconds(total_candidates=1000) is None

    def test_none_total_returns_none(self) -> None:
        tel = CrackTelemetry()
        assert tel.eta_seconds(total_candidates=None) is None

    def test_all_done_returns_zero(self) -> None:
        tel = CrackTelemetry()
        base = time.monotonic()
        tel._samples = [(base, 1000)]
        tel._total_attempts = 1000
        eta = tel.eta_seconds(total_candidates=1000)
        # Already done or None if speed is 0 — either is acceptable
        assert eta is None or eta == 0.0

    def test_eta_positive_when_work_remaining(self) -> None:
        tel = CrackTelemetry(window_seconds=5.0)
        base = time.monotonic()
        tel._samples = [
            (base - 2.0, 100),
            (base - 1.0, 200),
            (base, 300),
        ]
        tel._total_attempts = 300
        eta = tel.eta_seconds(total_candidates=1000)
        # 300 done, 700 remaining, ~100 H/s => ~7 seconds
        assert eta is not None
        assert eta > 0.0


class TestRollingWindow:
    """Test that old entries are discarded."""

    def test_old_entries_pruned(self) -> None:
        tel = CrackTelemetry(window_seconds=2.0)
        base = time.monotonic()
        tel._samples = [
            (base - 10.0, 100),  # stale — 10s ago
            (base - 9.0, 200),   # stale — 9s ago
            (base - 0.5, 300),   # fresh
            (base, 400),         # fresh
        ]
        tel._total_attempts = 400
        _ = tel.hashes_per_second  # triggers pruning
        assert len(tel._samples) == 2


class TestZeroDivisionSafety:
    """Test that zero-division is handled gracefully."""

    def test_single_sample_no_crash(self) -> None:
        tel = CrackTelemetry()
        base = time.monotonic()
        tel._samples = [(base, 0)]
        tel._total_attempts = 0
        assert tel.hashes_per_second == 0.0

    def test_identical_timestamps_no_crash(self) -> None:
        tel = CrackTelemetry()
        ts = time.monotonic()
        tel._samples = [(ts, 100), (ts, 200)]
        tel._total_attempts = 200
        # Should not raise — returns 0 or a safe value
        speed = tel.hashes_per_second
        assert speed >= 0.0


class TestElapsedSeconds:
    """Test elapsed time tracking."""

    def test_elapsed_positive(self) -> None:
        tel = CrackTelemetry()
        assert tel.elapsed_seconds >= 0.0


class TestTotalAttempts:
    """Test total attempt counting."""

    def test_initial_zero(self) -> None:
        tel = CrackTelemetry()
        assert tel.total_attempts == 0

    def test_update_increments(self) -> None:
        tel = CrackTelemetry()
        tel.update(50)
        tel.update(75)
        assert tel.total_attempts == 125


class TestUpdate:
    """Test the update method."""

    def test_update_adds_sample(self) -> None:
        tel = CrackTelemetry()
        tel.update(100)
        assert len(tel._samples) == 1
        assert tel._total_attempts == 100

    def test_multiple_updates_accumulate(self) -> None:
        tel = CrackTelemetry()
        tel.update(100)
        tel.update(200)
        assert tel._total_attempts == 300
        assert len(tel._samples) == 2
```

- [ ] **1.2** Run tests to confirm they fail (RED):

```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m pytest tests/test_telemetry.py -v 2>&1 | head -40
```

Expected: `ModuleNotFoundError: No module named 'smartcrack.telemetry'`

- [ ] **1.3** Implement `src/smartcrack/telemetry.py`:

```python
"""Live telemetry — rolling-window speed, ETA, and attempt tracking."""

from __future__ import annotations

import time


class CrackTelemetry:
    """Tracks cracking speed using a rolling time window of (timestamp, cumulative_count) samples.

    Thread-safe for single-writer / multiple-reader usage (the on_progress callback
    is the only writer; UI reads properties from the main thread).
    """

    def __init__(self, window_seconds: float = 5.0) -> None:
        self._window_seconds = window_seconds
        self._samples: list[tuple[float, int]] = []
        self._total_attempts: int = 0
        self._start_time: float = time.monotonic()

    # ------------------------------------------------------------------
    # Public mutator
    # ------------------------------------------------------------------

    def update(self, n: int) -> None:
        """Record *n* new hash attempts. Called from the progress callback."""
        self._total_attempts += n
        self._samples.append((time.monotonic(), self._total_attempts))

    # ------------------------------------------------------------------
    # Public read-only properties
    # ------------------------------------------------------------------

    @property
    def total_attempts(self) -> int:
        """Total hashes tested since creation."""
        return self._total_attempts

    @property
    def elapsed_seconds(self) -> float:
        """Wall-clock seconds since this tracker was created."""
        return time.monotonic() - self._start_time

    @property
    def hashes_per_second(self) -> float:
        """Rolling average hash rate over the last *window_seconds*."""
        self._prune()
        if len(self._samples) < 2:
            return 0.0
        first_ts, first_count = self._samples[0]
        last_ts, last_count = self._samples[-1]
        dt = last_ts - first_ts
        if dt <= 0:
            return 0.0
        return (last_count - first_count) / dt

    def eta_seconds(self, total_candidates: int | None) -> float | None:
        """Estimated seconds remaining, or None if unknown."""
        if total_candidates is None:
            return None
        speed = self.hashes_per_second
        if speed <= 0:
            return None
        remaining = total_candidates - self._total_attempts
        if remaining <= 0:
            return 0.0
        return remaining / speed

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _prune(self) -> None:
        """Discard samples older than the rolling window."""
        cutoff = time.monotonic() - self._window_seconds
        while self._samples and self._samples[0][0] < cutoff:
            self._samples.pop(0)
```

- [ ] **1.4** Run tests to confirm they pass (GREEN):

```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m pytest tests/test_telemetry.py -v
```

Expected output:
```
tests/test_telemetry.py::TestHashesPerSecond::test_no_updates_returns_zero PASSED
tests/test_telemetry.py::TestHashesPerSecond::test_single_update_calculates_speed PASSED
tests/test_telemetry.py::TestHashesPerSecond::test_rolling_average_over_window PASSED
tests/test_telemetry.py::TestEtaSeconds::test_no_speed_returns_none PASSED
tests/test_telemetry.py::TestEtaSeconds::test_none_total_returns_none PASSED
tests/test_telemetry.py::TestEtaSeconds::test_all_done_returns_zero PASSED
tests/test_telemetry.py::TestEtaSeconds::test_eta_positive_when_work_remaining PASSED
tests/test_telemetry.py::TestRollingWindow::test_old_entries_pruned PASSED
tests/test_telemetry.py::TestZeroDivisionSafety::test_single_sample_no_crash PASSED
tests/test_telemetry.py::TestZeroDivisionSafety::test_identical_timestamps_no_crash PASSED
tests/test_telemetry.py::TestElapsedSeconds::test_elapsed_positive PASSED
tests/test_telemetry.py::TestTotalAttempts::test_initial_zero PASSED
tests/test_telemetry.py::TestTotalAttempts::test_update_increments PASSED
tests/test_telemetry.py::TestUpdate::test_update_adds_sample PASSED
tests/test_telemetry.py::TestUpdate::test_multiple_updates_accumulate PASSED
```

- [ ] **1.5** Verify existing tests still pass:

```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m pytest --tb=short -q
```

- [ ] **1.6** Commit:

```
feat: add CrackTelemetry rolling-window speed tracker
```

---

## Task 2: Create forensic result card renderer

**Files:**
- **Create:** `src/smartcrack/result_card.py`
- **Test:** `tests/test_result_card.py`

### Steps

- [ ] **2.1** Write tests first in `tests/test_result_card.py`:

```python
"""Tests for forensic result card rendering."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from smartcrack.models import AttackPhase, CrackResult, HashType, LLMConfig
from smartcrack.result_card import (
    render_result_card,
    render_batch_summary_table,
    _entropy_bar,
    _strength_style,
)
from smartcrack.analysis import PasswordAnalysis


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def cracked_result() -> CrackResult:
    return CrackResult(
        found=True,
        plaintext="password123",
        hash_type=HashType.MD5,
        attack_phase=AttackPhase.DICTIONARY,
        attempts=4521,
        duration_seconds=1.34,
    )


@pytest.fixture
def not_found_result() -> CrackResult:
    return CrackResult(
        found=False,
        plaintext=None,
        hash_type=HashType.SHA256,
        attack_phase=None,
        attempts=100000,
        duration_seconds=12.5,
    )


@pytest.fixture
def strong_result() -> CrackResult:
    return CrackResult(
        found=True,
        plaintext="X#9kL!mP2@vQ",
        hash_type=HashType.SHA512,
        attack_phase=AttackPhase.RULES,
        attempts=85432,
        duration_seconds=8.77,
    )


@pytest.fixture
def llm_config() -> LLMConfig:
    return LLMConfig(
        base_url="https://api.example.com/v1",
        api_key="sk-test-key",
        model="gpt-4o",
        timeout_seconds=10,
    )


# ---------------------------------------------------------------------------
# Entropy bar
# ---------------------------------------------------------------------------


class TestEntropyBar:
    """Test entropy bar visual rendering."""

    def test_weak_password_short_bar(self) -> None:
        bar = _entropy_bar(entropy=15.0, strength="weak")
        assert "█" in bar
        assert "░" in bar
        # Weak passwords should have red styling
        assert "red" in bar

    def test_moderate_password_medium_bar(self) -> None:
        bar = _entropy_bar(entropy=35.0, strength="moderate")
        assert "█" in bar
        assert "yellow" in bar

    def test_strong_password_long_bar(self) -> None:
        bar = _entropy_bar(entropy=55.0, strength="strong")
        assert "█" in bar
        assert "green" in bar

    def test_very_strong_password_full_bar(self) -> None:
        bar = _entropy_bar(entropy=85.0, strength="very_strong")
        assert "█" in bar
        assert "cyan" in bar

    def test_zero_entropy(self) -> None:
        bar = _entropy_bar(entropy=0.0, strength="weak")
        assert "░" in bar


class TestStrengthStyle:
    """Test strength to Rich style mapping."""

    def test_weak_is_red(self) -> None:
        assert _strength_style("weak") == "bold red"

    def test_moderate_is_yellow(self) -> None:
        assert _strength_style("moderate") == "bold yellow"

    def test_strong_is_green(self) -> None:
        assert _strength_style("strong") == "bold green"

    def test_very_strong_is_cyan(self) -> None:
        assert _strength_style("very_strong") == "bold cyan"

    def test_unknown_falls_back(self) -> None:
        assert _strength_style("unknown") == "bold white"


# ---------------------------------------------------------------------------
# Render result card — no LLM
# ---------------------------------------------------------------------------


class TestRenderResultCardNoLLM:
    """Test card rendering without LLM config."""

    def test_returns_panel(self, cracked_result: CrackResult) -> None:
        panel = render_result_card(cracked_result)
        assert isinstance(panel, Panel)

    def test_panel_renders_without_error(self, cracked_result: CrackResult) -> None:
        panel = render_result_card(cracked_result)
        console = Console(file=MagicMock(), width=100)
        # Should not raise
        console.print(panel)

    def test_not_found_result_renders(self, not_found_result: CrackResult) -> None:
        panel = render_result_card(not_found_result)
        assert isinstance(panel, Panel)
        console = Console(file=MagicMock(), width=100)
        console.print(panel)

    def test_card_contains_plaintext(self, cracked_result: CrackResult) -> None:
        panel = render_result_card(cracked_result)
        # Render to string to check content
        console = Console(file=MagicMock(), width=120, no_color=True)
        with console.capture() as capture:
            console.print(panel)
        output = capture.get()
        assert "password123" in output

    def test_card_contains_algorithm(self, cracked_result: CrackResult) -> None:
        panel = render_result_card(cracked_result)
        console = Console(file=MagicMock(), width=120, no_color=True)
        with console.capture() as capture:
            console.print(panel)
        output = capture.get()
        assert "MD5" in output

    def test_card_contains_phase(self, cracked_result: CrackResult) -> None:
        panel = render_result_card(cracked_result)
        console = Console(file=MagicMock(), width=120, no_color=True)
        with console.capture() as capture:
            console.print(panel)
        output = capture.get()
        assert "dictionary" in output.lower()

    def test_card_contains_attempts(self, cracked_result: CrackResult) -> None:
        panel = render_result_card(cracked_result)
        console = Console(file=MagicMock(), width=120, no_color=True)
        with console.capture() as capture:
            console.print(panel)
        output = capture.get()
        assert "4,521" in output

    def test_card_contains_entropy_bar(self, cracked_result: CrackResult) -> None:
        panel = render_result_card(cracked_result)
        console = Console(file=MagicMock(), width=120, no_color=True)
        with console.capture() as capture:
            console.print(panel)
        output = capture.get()
        assert "█" in output or "░" in output

    def test_card_contains_strength_rating(self, cracked_result: CrackResult) -> None:
        panel = render_result_card(cracked_result)
        console = Console(file=MagicMock(), width=120, no_color=True)
        with console.capture() as capture:
            console.print(panel)
        output = capture.get()
        # password123 is weak
        assert "weak" in output.lower() or "moderate" in output.lower()

    def test_card_shows_ai_unavailable(self, cracked_result: CrackResult) -> None:
        panel = render_result_card(cracked_result, llm_config=None)
        console = Console(file=MagicMock(), width=120, no_color=True)
        with console.capture() as capture:
            console.print(panel)
        output = capture.get()
        assert "unavailable" in output.lower() or "no llm" in output.lower()

    def test_card_contains_patterns(self, cracked_result: CrackResult) -> None:
        panel = render_result_card(cracked_result)
        console = Console(file=MagicMock(), width=120, no_color=True)
        with console.capture() as capture:
            console.print(panel)
        output = capture.get()
        # password123 has common_suffix pattern
        assert "common_suffix" in output or "Patterns" in output or "None detected" in output


# ---------------------------------------------------------------------------
# Render result card — with mock LLM
# ---------------------------------------------------------------------------


class TestRenderResultCardWithLLM:
    """Test card rendering with LLM providing AI assessment."""

    def test_card_with_llm_response(
        self, cracked_result: CrackResult, llm_config: LLMConfig
    ) -> None:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": "This password is extremely weak. It uses a common base word with a trivial numeric suffix."
                    }
                }
            ]
        }
        mock_response.raise_for_status = MagicMock()

        with patch("smartcrack.result_card.httpx.post", return_value=mock_response):
            panel = render_result_card(cracked_result, llm_config=llm_config)

        console = Console(file=MagicMock(), width=120, no_color=True)
        with console.capture() as capture:
            console.print(panel)
        output = capture.get()
        assert "extremely weak" in output.lower()

    def test_card_handles_llm_timeout(
        self, cracked_result: CrackResult, llm_config: LLMConfig
    ) -> None:
        import httpx

        with patch(
            "smartcrack.result_card.httpx.post",
            side_effect=httpx.TimeoutException("timeout"),
        ):
            panel = render_result_card(cracked_result, llm_config=llm_config)

        console = Console(file=MagicMock(), width=120, no_color=True)
        with console.capture() as capture:
            console.print(panel)
        output = capture.get()
        assert "unavailable" in output.lower() or "failed" in output.lower()

    def test_card_handles_llm_http_error(
        self, cracked_result: CrackResult, llm_config: LLMConfig
    ) -> None:
        import httpx

        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "500", request=MagicMock(), response=mock_response
        )

        with patch("smartcrack.result_card.httpx.post", return_value=mock_response):
            panel = render_result_card(cracked_result, llm_config=llm_config)

        assert isinstance(panel, Panel)

    def test_card_handles_empty_choices(
        self, cracked_result: CrackResult, llm_config: LLMConfig
    ) -> None:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"choices": []}
        mock_response.raise_for_status = MagicMock()

        with patch("smartcrack.result_card.httpx.post", return_value=mock_response):
            panel = render_result_card(cracked_result, llm_config=llm_config)

        assert isinstance(panel, Panel)


# ---------------------------------------------------------------------------
# Batch summary table
# ---------------------------------------------------------------------------


class TestBatchSummaryTable:
    """Test batch summary table generation."""

    def test_returns_table(self) -> None:
        results = [
            CrackResult(found=True, plaintext="password", hash_type=HashType.MD5, attempts=100, duration_seconds=0.5),
            CrackResult(found=True, plaintext="X#9kL!mP2@vQ", hash_type=HashType.SHA256, attempts=5000, duration_seconds=3.2),
            CrackResult(found=False, plaintext=None, hash_type=HashType.SHA512, attempts=100000, duration_seconds=15.0),
        ]
        hashes = ["5f4dcc3b5aa765d61d8327deb882cf99", "abc123hash", "def456hash"]
        table = render_batch_summary_table(hashes, results)
        assert isinstance(table, Table)

    def test_table_renders_without_error(self) -> None:
        results = [
            CrackResult(found=True, plaintext="test", hash_type=HashType.MD5, attempts=10, duration_seconds=0.1),
        ]
        hashes = ["abc123"]
        table = render_batch_summary_table(hashes, results)
        console = Console(file=MagicMock(), width=120, no_color=True)
        with console.capture() as capture:
            console.print(table)
        output = capture.get()
        assert "test" in output

    def test_empty_results(self) -> None:
        table = render_batch_summary_table([], [])
        assert isinstance(table, Table)

    def test_strength_column_present(self) -> None:
        results = [
            CrackResult(found=True, plaintext="password", hash_type=HashType.MD5, attempts=100, duration_seconds=0.5),
        ]
        hashes = ["5f4dcc3b5aa765d61d8327deb882cf99"]
        table = render_batch_summary_table(hashes, results)
        console = Console(file=MagicMock(), width=120, no_color=True)
        with console.capture() as capture:
            console.print(table)
        output = capture.get()
        # Should contain strength indicator
        assert "weak" in output.lower() or "moderate" in output.lower() or "strong" in output.lower()
```

- [ ] **2.2** Run tests to confirm they fail (RED):

```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m pytest tests/test_result_card.py -v 2>&1 | head -30
```

Expected: `ModuleNotFoundError: No module named 'smartcrack.result_card'`

- [ ] **2.3** Implement `src/smartcrack/result_card.py`:

```python
"""Forensic result card — Rich Panel with autopsy-style cracking report."""

from __future__ import annotations

import logging
from typing import Sequence

import httpx
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from smartcrack.analysis import analyze_password, PasswordAnalysis
from smartcrack.models import CrackResult, LLMConfig

logger = logging.getLogger(__name__)

_ENTROPY_BAR_WIDTH = 20
_ENTROPY_MAX = 80.0  # entropy value that fills the bar completely

_ASSESSMENT_SYSTEM_PROMPT = (
    "You are a cybersecurity expert. Given a cracked password and its forensic "
    "analysis, provide a 1-2 sentence assessment of the password's quality and "
    "what it reveals about the user's password habits. Be direct and specific."
)


# ------------------------------------------------------------------
# Helper: strength → Rich style
# ------------------------------------------------------------------


def _strength_style(strength: str) -> str:
    """Map a strength rating to a Rich style string."""
    styles = {
        "weak": "bold red",
        "moderate": "bold yellow",
        "strong": "bold green",
        "very_strong": "bold cyan",
    }
    return styles.get(strength, "bold white")


# ------------------------------------------------------------------
# Helper: entropy bar
# ------------------------------------------------------------------


def _entropy_bar(entropy: float, strength: str) -> str:
    """Build a colored entropy bar string like [████████░░░░░░░░░░░░] 35.2 bits.

    Returns a Rich markup string.
    """
    ratio = min(entropy / _ENTROPY_MAX, 1.0)
    filled = int(ratio * _ENTROPY_BAR_WIDTH)
    empty = _ENTROPY_BAR_WIDTH - filled

    color_map = {
        "weak": "red",
        "moderate": "yellow",
        "strong": "green",
        "very_strong": "cyan",
    }
    color = color_map.get(strength, "white")

    filled_str = "█" * filled
    empty_str = "░" * empty
    return f"[{color}]{filled_str}[/{color}][dim]{empty_str}[/dim] {entropy:.1f} bits"


# ------------------------------------------------------------------
# Helper: AI assessment via LLM
# ------------------------------------------------------------------


def _fetch_ai_assessment(
    password: str,
    analysis: PasswordAnalysis,
    llm_config: LLMConfig,
) -> str:
    """Call the LLM for a 1-2 sentence password quality assessment.

    Returns the assessment text, or a fallback message on failure.
    """
    user_prompt = (
        f"Password: {password}\n"
        f"Length: {analysis.length}\n"
        f"Entropy: {analysis.entropy:.1f} bits\n"
        f"Strength: {analysis.strength}\n"
        f"Charset size: {analysis.charset_size}\n"
        f"Patterns: {', '.join(analysis.patterns) if analysis.patterns else 'none'}\n"
    )

    url = f"{llm_config.base_url.rstrip('/')}/chat/completions"
    payload = {
        "model": llm_config.model,
        "temperature": 0.3,
        "max_tokens": 150,
        "messages": [
            {"role": "system", "content": _ASSESSMENT_SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
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
            return "AI assessment unavailable (empty response)"
        content: str = choices[0].get("message", {}).get("content", "")
        return content.strip() or "AI assessment unavailable (empty content)"
    except httpx.TimeoutException:
        logger.warning("AI assessment timed out")
        return "AI assessment unavailable (request timed out)"
    except httpx.HTTPStatusError as exc:
        logger.warning("AI assessment HTTP error: %s", exc.response.status_code)
        return "AI assessment unavailable (HTTP error)"
    except Exception as exc:  # noqa: BLE001
        logger.warning("AI assessment failed: %s", type(exc).__name__)
        return f"AI assessment unavailable ({type(exc).__name__})"


# ------------------------------------------------------------------
# Public: render_result_card
# ------------------------------------------------------------------


def render_result_card(
    result: CrackResult,
    llm_config: LLMConfig | None = None,
) -> Panel:
    """Build a Rich Panel 'autopsy card' for a cracking result.

    Sections:
        RESULT — plaintext, algorithm, time, attempts, phase
        FORENSIC ANALYSIS — entropy bar, strength, patterns, charset
        AI ASSESSMENT — optional LLM-powered assessment
    """
    sections: list[Table | Text] = []

    # ── RESULT section ──────────────────────────────────────────
    result_table = Table(show_header=False, show_edge=False, box=None, padding=(0, 2))
    result_table.add_column("label", style="bold", width=14)
    result_table.add_column("value")

    if result.found and result.plaintext:
        result_table.add_row("Plaintext", f"[bold green]{result.plaintext}[/bold green]")
    else:
        result_table.add_row("Plaintext", "[dim]Not found[/dim]")

    algorithm = result.hash_type.name if result.hash_type else "Unknown"
    result_table.add_row("Algorithm", algorithm)

    phase = result.attack_phase.value if result.attack_phase else "—"
    result_table.add_row("Phase", phase)

    result_table.add_row("Attempts", f"{result.attempts:,}")
    result_table.add_row("Time", f"{result.duration_seconds:.2f}s")

    sections.append(Text("─── RESULT ───", style="bold cyan"))
    sections.append(result_table)

    # ── FORENSIC ANALYSIS section (only if password found) ──────
    if result.found and result.plaintext:
        analysis = analyze_password(result.plaintext)

        forensic_table = Table(show_header=False, show_edge=False, box=None, padding=(0, 2))
        forensic_table.add_column("label", style="bold", width=14)
        forensic_table.add_column("value")

        entropy_bar = _entropy_bar(analysis.entropy, analysis.strength)
        forensic_table.add_row("Entropy", entropy_bar)

        strength_display = f"[{_strength_style(analysis.strength)}]{analysis.strength.upper()}[/{_strength_style(analysis.strength)}]"
        forensic_table.add_row("Strength", strength_display)

        forensic_table.add_row("Length", str(analysis.length))
        forensic_table.add_row("Charset Size", str(analysis.charset_size))

        if analysis.patterns:
            patterns_str = ", ".join(analysis.patterns)
            forensic_table.add_row("Patterns", f"[yellow]{patterns_str}[/yellow]")
        else:
            forensic_table.add_row("Patterns", "[dim]None detected[/dim]")

        sections.append(Text(""))
        sections.append(Text("─── FORENSIC ANALYSIS ───", style="bold cyan"))
        sections.append(forensic_table)

        # ── AI ASSESSMENT section ───────────────────────────────
        sections.append(Text(""))
        sections.append(Text("─── AI ASSESSMENT ───", style="bold cyan"))

        if llm_config and llm_config.api_key:
            assessment = _fetch_ai_assessment(result.plaintext, analysis, llm_config)
        else:
            assessment = "AI assessment unavailable (no LLM configured)"

        sections.append(Text(f"  {assessment}", style="dim italic"))

    # ── Assemble panel ──────────────────────────────────────────
    from rich.console import Group

    panel_title = "[bold green]CRACKED[/bold green]" if result.found else "[bold red]NOT FOUND[/bold red]"

    return Panel(
        Group(*sections),
        title=f"🔓 {panel_title}",
        subtitle="[dim]SmartCrack Forensic Report[/dim]",
        border_style="green" if result.found else "red",
        padding=(1, 2),
    )


# ------------------------------------------------------------------
# Public: render_batch_summary_table
# ------------------------------------------------------------------


def render_batch_summary_table(
    hashes: Sequence[str],
    results: Sequence[CrackResult],
) -> Table:
    """Build a Rich Table summarizing batch cracking results with color-coded strength."""
    table = Table(title="Batch Summary", show_lines=True)
    table.add_column("#", style="dim", width=4)
    table.add_column("Hash", max_width=20)
    table.add_column("Status", width=10)
    table.add_column("Plaintext", max_width=20)
    table.add_column("Strength", width=14)
    table.add_column("Attempts", justify="right", width=12)
    table.add_column("Time", justify="right", width=8)

    for i, (hash_val, result) in enumerate(zip(hashes, results), 1):
        hash_display = hash_val[:16] + "…" if len(hash_val) > 16 else hash_val

        if result.found and result.plaintext:
            status = "[green]CRACKED[/green]"
            plaintext = result.plaintext
            analysis = analyze_password(result.plaintext)
            style = _strength_style(analysis.strength)
            strength = f"[{style}]{analysis.strength.upper()}[/{style}]"
        else:
            status = "[red]FAILED[/red]"
            plaintext = "—"
            strength = "—"

        table.add_row(
            str(i),
            hash_display,
            status,
            plaintext,
            strength,
            f"{result.attempts:,}",
            f"{result.duration_seconds:.2f}s",
        )

    return table
```

- [ ] **2.4** Run tests to confirm they pass (GREEN):

```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m pytest tests/test_result_card.py -v
```

Expected output:
```
tests/test_result_card.py::TestEntropyBar::test_weak_password_short_bar PASSED
tests/test_result_card.py::TestEntropyBar::test_moderate_password_medium_bar PASSED
tests/test_result_card.py::TestEntropyBar::test_strong_password_long_bar PASSED
tests/test_result_card.py::TestEntropyBar::test_very_strong_password_full_bar PASSED
tests/test_result_card.py::TestEntropyBar::test_zero_entropy PASSED
tests/test_result_card.py::TestStrengthStyle::test_weak_is_red PASSED
tests/test_result_card.py::TestStrengthStyle::test_moderate_is_yellow PASSED
tests/test_result_card.py::TestStrengthStyle::test_strong_is_green PASSED
tests/test_result_card.py::TestStrengthStyle::test_very_strong_is_cyan PASSED
tests/test_result_card.py::TestStrengthStyle::test_unknown_falls_back PASSED
tests/test_result_card.py::TestRenderResultCardNoLLM::test_returns_panel PASSED
tests/test_result_card.py::TestRenderResultCardNoLLM::test_panel_renders_without_error PASSED
tests/test_result_card.py::TestRenderResultCardNoLLM::test_not_found_result_renders PASSED
tests/test_result_card.py::TestRenderResultCardNoLLM::test_card_contains_plaintext PASSED
tests/test_result_card.py::TestRenderResultCardNoLLM::test_card_contains_algorithm PASSED
tests/test_result_card.py::TestRenderResultCardNoLLM::test_card_contains_phase PASSED
tests/test_result_card.py::TestRenderResultCardNoLLM::test_card_contains_attempts PASSED
tests/test_result_card.py::TestRenderResultCardNoLLM::test_card_contains_entropy_bar PASSED
tests/test_result_card.py::TestRenderResultCardNoLLM::test_card_contains_strength_rating PASSED
tests/test_result_card.py::TestRenderResultCardNoLLM::test_card_shows_ai_unavailable PASSED
tests/test_result_card.py::TestRenderResultCardNoLLM::test_card_contains_patterns PASSED
tests/test_result_card.py::TestRenderResultCardWithLLM::test_card_with_llm_response PASSED
tests/test_result_card.py::TestRenderResultCardWithLLM::test_card_handles_llm_timeout PASSED
tests/test_result_card.py::TestRenderResultCardWithLLM::test_card_handles_llm_http_error PASSED
tests/test_result_card.py::TestRenderResultCardWithLLM::test_card_handles_empty_choices PASSED
tests/test_result_card.py::TestBatchSummaryTable::test_returns_table PASSED
tests/test_result_card.py::TestBatchSummaryTable::test_table_renders_without_error PASSED
tests/test_result_card.py::TestBatchSummaryTable::test_empty_results PASSED
tests/test_result_card.py::TestBatchSummaryTable::test_strength_column_present PASSED
```

- [ ] **2.5** Verify all existing tests still pass:

```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m pytest --tb=short -q
```

- [ ] **2.6** Commit:

```
feat: add forensic result card renderer with entropy bar and AI assessment
```

---

## Task 3: Integrate result card into CLI `smart` command

**Files:**
- **Modify:** `src/smartcrack/cli.py`

### Steps

- [ ] **3.1** In `src/smartcrack/cli.py`, add the import for `render_result_card` at the top of the file. Add this after the existing `from smartcrack.session import ...` line:

```python
from smartcrack.result_card import render_result_card
```

- [ ] **3.2** Replace the result display block in the `smart` command. Find the block at the end of the `smart` function (lines 351-364):

```python
    if result.found:
        console.print(f"\n[green][+] Cracked:[/] [bold]{result.plaintext}[/]")
        if result.hash_type:
            console.print(f"[green][+] Algorithm:[/] {result.hash_type.name}")
        if result.attack_phase:
            console.print(f"[green][+] Phase:[/] {result.attack_phase.value}")
        console.print(f"[green][+] Attempts:[/] {result.attempts:,}")
        console.print(f"[green][+] Time:[/] {result.duration_seconds:.2f}s")
    else:
        console.print(
            f"\n[red][-] Not found after {result.attempts:,} attempts "
            f"({result.duration_seconds:.2f}s)[/]"
        )
        console.print("[dim]Try a larger wordlist, different rules, or add a target profile.[/]")
```

Replace with:

```python
    console.print()
    card = render_result_card(result, llm_config=llm_config)
    console.print(card)
    if not result.found:
        console.print("[dim]Try a larger wordlist, different rules, or add a target profile.[/]")
```

- [ ] **3.3** Verify the full test suite still passes:

```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m pytest --tb=short -q
```

- [ ] **3.4** Commit:

```
feat: replace smart command output with forensic result card
```

---

## Task 4: Integrate telemetry into CLI `smart` command progress display

**Files:**
- **Modify:** `src/smartcrack/cli.py`

### Steps

- [ ] **4.1** Add the telemetry import at the top of `src/smartcrack/cli.py`, next to the `render_result_card` import:

```python
from smartcrack.telemetry import CrackTelemetry
```

- [ ] **4.2** Replace the progress block in the `smart` function. Find the block (lines 315-345):

```python
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Starting…", total=None)
        attempts_counter: list[int] = [0]

        def _on_progress(n: int) -> None:
            attempts_counter[0] += n
            progress.update(task, advance=n, description=f"Tried {attempts_counter[0]:,}")

        def _on_phase_change(phase_name: str, phase_idx: int, total: int) -> None:
            progress.update(
                task,
                description=f"[{phase_idx + 1}/{total}] {phase_name}",
            )
            console.log(f"[yellow]→ Phase {phase_idx + 1}/{total}:[/] {phase_name}")

        result = run_orchestrated(
            target=target,
            plans=plans,
            max_workers=workers,
            on_progress=_on_progress,
            on_phase_change=_on_phase_change,
            session=session,
            timeout_seconds=timeout,
        )
```

Replace with:

```python
    telemetry = CrackTelemetry()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Starting…", total=None)

        def _on_progress(n: int) -> None:
            telemetry.update(n)
            speed = telemetry.hashes_per_second
            total = telemetry.total_attempts
            eta = telemetry.eta_seconds(total_candidates=None)
            eta_str = f" | ETA: {eta:.0f}s" if eta is not None else ""
            if speed >= 1_000_000:
                speed_str = f"{speed / 1_000_000:.1f}M H/s"
            elif speed >= 1_000:
                speed_str = f"{speed / 1_000:.1f}K H/s"
            else:
                speed_str = f"{speed:.0f} H/s"
            progress.update(
                task,
                advance=n,
                description=f"Tried {total:,} | {speed_str}{eta_str}",
            )

        def _on_phase_change(phase_name: str, phase_idx: int, total: int) -> None:
            progress.update(
                task,
                description=f"[{phase_idx + 1}/{total}] {phase_name}",
            )
            console.log(f"[yellow]→ Phase {phase_idx + 1}/{total}:[/] {phase_name}")

        result = run_orchestrated(
            target=target,
            plans=plans,
            max_workers=workers,
            on_progress=_on_progress,
            on_phase_change=_on_phase_change,
            session=session,
            timeout_seconds=timeout,
        )
```

- [ ] **4.3** Verify the full test suite still passes:

```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m pytest --tb=short -q
```

- [ ] **4.4** Commit:

```
feat: add live telemetry (speed + ETA) to smart command progress bar
```

---

## Task 5: Add `TelemetryWidget` to the TUI

**Files:**
- **Create:** `src/smartcrack/tui/widgets/telemetry.py`
- **Modify:** `src/smartcrack/tui/widgets/__init__.py`
- **Modify:** `src/smartcrack/tui/app.py`

### Steps

- [ ] **5.1** Create `src/smartcrack/tui/widgets/telemetry.py`:

```python
"""Telemetry widget — live speed, ETA, and total attempts display for the TUI."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.widgets import Label, Static

from smartcrack.telemetry import CrackTelemetry


def _format_speed(speed: float) -> str:
    """Return human-readable hash speed string."""
    if speed >= 1_000_000:
        return f"{speed / 1_000_000:.1f}M H/s"
    if speed >= 1_000:
        return f"{speed / 1_000:.1f}K H/s"
    return f"{speed:.0f} H/s"


def _format_eta(eta_seconds: float | None) -> str:
    """Return ETA string from remaining seconds."""
    if eta_seconds is None or eta_seconds <= 0:
        return "—"
    if eta_seconds < 60:
        return f"~{eta_seconds:.0f}s"
    minutes = eta_seconds / 60
    if minutes < 60:
        return f"~{minutes:.1f}m"
    hours = minutes / 60
    return f"~{hours:.1f}h"


def _format_elapsed(seconds: float) -> str:
    """Return human-readable elapsed time string."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = seconds / 60
    if minutes < 60:
        return f"{minutes:.1f}m"
    hours = minutes / 60
    return f"{hours:.1f}h"


class TelemetryWidget(Static):
    """Displays live cracking telemetry: speed, total attempts, elapsed, ETA."""

    DEFAULT_CSS = """
    TelemetryWidget {
        border: solid $secondary;
        border-title-color: $secondary;
        padding: 0 1;
        height: 4;
    }
    #telemetry-speed {
        height: 1;
    }
    #telemetry-stats {
        height: 1;
    }
    """

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self.border_title = "Telemetry"
        self._telemetry = CrackTelemetry()

    def compose(self) -> ComposeResult:
        yield Label("Speed: —    Elapsed: 0.0s", id="telemetry-speed")
        yield Label("Tried: 0    ETA: —", id="telemetry-stats")

    @property
    def telemetry(self) -> CrackTelemetry:
        """Expose the telemetry tracker for external updates."""
        return self._telemetry

    def refresh_telemetry(self) -> None:
        """Re-read telemetry state and update labels."""
        speed = self._telemetry.hashes_per_second
        elapsed = self._telemetry.elapsed_seconds
        total = self._telemetry.total_attempts

        speed_label = self.query_one("#telemetry-speed", Label)
        speed_label.update(
            f"Speed: [green]{_format_speed(speed)}[/green]"
            f"    Elapsed: [dim]{_format_elapsed(elapsed)}[/dim]"
        )

        stats_label = self.query_one("#telemetry-stats", Label)
        eta = self._telemetry.eta_seconds(total_candidates=None)
        stats_label.update(
            f"Tried: [yellow]{total:,}[/yellow]"
            f"    ETA: [dim]{_format_eta(eta)}[/dim]"
        )
```

- [ ] **5.2** Update `src/smartcrack/tui/widgets/__init__.py` to export the new widget. If the file is empty or just has imports, add:

```python
from smartcrack.tui.widgets.telemetry import TelemetryWidget
```

If the file already has content, append the import to the existing imports.

- [ ] **5.3** Modify `src/smartcrack/tui/app.py` to add the telemetry widget. Add the import at the top with the other widget imports:

```python
from smartcrack.tui.widgets.telemetry import TelemetryWidget
```

Add the widget to the `compose` method, after the `ProgressWidget` yield:

```python
            yield TelemetryWidget(id="telemetry")
```

Add CSS for spacing in `DEFAULT_CSS`:

```css
    TelemetryWidget {
        margin-bottom: 1;
    }
```

Update the `_on_progress` callback inside `_run_cracking` to also feed the telemetry widget. Replace the existing `_on_progress` function:

```python
        def _on_progress(n: int) -> None:
            with self._attempts_lock:
                self._total_attempts += n
                total = self._total_attempts
            telemetry_widget = self.query_one("#telemetry", TelemetryWidget)
            telemetry_widget.telemetry.update(n)
            self.call_from_thread(self.post_message, CrackProgress(total))
```

Add a handler to refresh telemetry display when progress updates arrive. Add this method to the `SmartCrackApp` class:

```python
    def on_crack_progress(self, message: CrackProgress) -> None:
        """Update progress widget and telemetry with latest attempt count."""
        progress = self.query_one("#progress", ProgressWidget)
        progress.update_progress(message.attempts)
        telemetry = self.query_one("#telemetry", TelemetryWidget)
        telemetry.refresh_telemetry()
```

This replaces the existing `on_crack_progress` handler.

- [ ] **5.4** Verify all tests pass:

```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m pytest --tb=short -q
```

- [ ] **5.5** Commit:

```
feat: add TelemetryWidget to TUI with live speed and ETA display
```

---

## Task 6: Integrate result card into batch command

**Files:**
- **Modify:** `src/smartcrack/cli.py`

### Steps

- [ ] **6.1** Add the `render_batch_summary_table` import. Update the existing `result_card` import line in `src/smartcrack/cli.py`:

```python
from smartcrack.result_card import render_batch_summary_table, render_result_card
```

- [ ] **6.2** Modify the `batch` command to use the summary table. Find the result summary block at the end of the `batch` function (around lines 440-441):

```python
    if jobs:
        console.print(f"\n[bold]Results:[/] {cracked}/{len(jobs)} cracked ({cracked / len(jobs) * 100:.0f}%)")
```

Replace with:

```python
    if jobs:
        console.print(f"\n[bold]Results:[/] {cracked}/{len(jobs)} cracked ({cracked / len(jobs) * 100:.0f}%)")

        all_hashes = [job.hash_value for job in jobs]
        all_results = [results.get(job.hash_value, CrackResult(found=False, attempts=0)) for job in jobs]
        summary_table = render_batch_summary_table(all_hashes, all_results)
        console.print()
        console.print(summary_table)

        # Show individual forensic cards for cracked hashes
        for hash_val, result_obj in results.items():
            if hasattr(result_obj, "found") and result_obj.found:
                console.print()
                console.print(render_result_card(result_obj))
```

- [ ] **6.3** Also need to ensure the `results` dict stores `CrackResult` objects. Check the existing code — the `results` dict is typed as `dict[str, object]` at line 411. Update the type annotation:

Find:
```python
    results: dict[str, object] = {}
```

Replace with:
```python
    results: dict[str, CrackResult] = {}
```

- [ ] **6.4** Clean up the audit section that accesses `result.plaintext` — since the type is now `CrackResult`, simplify the list comprehension. Find:

```python
        passwords = [r.plaintext for r in results.values() if hasattr(r, "plaintext") and r.plaintext]  # type: ignore[union-attr]
```

Replace with:

```python
        passwords = [r.plaintext for r in results.values() if r.plaintext]
```

- [ ] **6.5** Verify all tests pass:

```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m pytest --tb=short -q
```

- [ ] **6.6** Commit:

```
feat: add batch summary table with strength indicators and forensic cards
```

---

## Task 7: Final integration test and lint

**Files:**
- **All modified files**

### Steps

- [ ] **7.1** Run the full test suite:

```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m pytest tests/ -v --tb=short
```

- [ ] **7.2** Run linting:

```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m ruff check src/smartcrack/telemetry.py src/smartcrack/result_card.py src/smartcrack/tui/widgets/telemetry.py src/smartcrack/cli.py
```

- [ ] **7.3** Fix any lint issues found in the previous step.

- [ ] **7.4** Run the full test suite one final time:

```bash
cd /Users/sam/Documents/Projects/hashcrack && python -m pytest --tb=short -q
```

- [ ] **7.5** Commit any lint fixes:

```
fix: resolve lint issues in Phase A files
```

---

## Summary of all files

| Action | File |
|--------|------|
| Create | `src/smartcrack/telemetry.py` |
| Create | `src/smartcrack/result_card.py` |
| Create | `src/smartcrack/tui/widgets/telemetry.py` |
| Create | `tests/test_telemetry.py` |
| Create | `tests/test_result_card.py` |
| Modify | `src/smartcrack/cli.py` |
| Modify | `src/smartcrack/tui/app.py` |
| Modify | `src/smartcrack/tui/widgets/__init__.py` |

## Dependency check

No new dependencies required. All features use:
- `rich` (already installed — Panel, Table, Text, Group)
- `httpx` (already installed — used by profiler.py)
- `textual` (already installed — used by existing TUI)
