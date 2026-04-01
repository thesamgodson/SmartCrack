"""Tests for forensic result card rendering."""

from __future__ import annotations

from unittest.mock import MagicMock

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from smartcrack.models import AttackPhase, CrackResult, HashType
from smartcrack.result_card import (
    render_result_card,
    render_batch_summary_table,
    _entropy_bar,
    _strength_style,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

import pytest


@pytest.fixture
def cracked_result() -> CrackResult:
    return CrackResult(
        found=True,
        plaintext="password123",
        hash_type=HashType.MD5,
        attack_phase=AttackPhase.DICTIONARY,
        attempts=10_000,
        duration_seconds=1.5,
    )


@pytest.fixture
def not_found_result() -> CrackResult:
    return CrackResult(
        found=False,
        plaintext=None,
        hash_type=None,
        attack_phase=None,
        attempts=100_000,
        duration_seconds=15.0,
    )


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


class TestEntropyBar:
    def test_zero_entropy(self) -> None:
        bar = _entropy_bar(0.0, "weak")
        assert isinstance(bar, str)

    def test_high_entropy(self) -> None:
        bar = _entropy_bar(80.0, "very_strong")
        assert isinstance(bar, str)

    def test_contains_bits_label(self) -> None:
        bar = _entropy_bar(42.5, "strong")
        assert "42.5" in bar
        assert "bits" in bar.lower()


class TestStrengthStyle:
    def test_weak_style(self) -> None:
        style = _strength_style("weak")
        assert isinstance(style, str)

    def test_strong_style(self) -> None:
        style = _strength_style("strong")
        assert isinstance(style, str)


# ---------------------------------------------------------------------------
# Result card rendering
# ---------------------------------------------------------------------------


class TestRenderResultCard:
    def test_returns_panel(self, cracked_result: CrackResult) -> None:
        panel = render_result_card(cracked_result)
        assert isinstance(panel, Panel)

    def test_not_found_returns_panel(self, not_found_result: CrackResult) -> None:
        panel = render_result_card(not_found_result)
        assert isinstance(panel, Panel)

    def test_card_contains_plaintext(self, cracked_result: CrackResult) -> None:
        panel = render_result_card(cracked_result)
        console = Console(file=MagicMock(), width=120, no_color=True)
        with console.capture() as capture:
            console.print(panel)
        output = capture.get()
        assert "password123" in output

    def test_card_contains_hash_type(self, cracked_result: CrackResult) -> None:
        panel = render_result_card(cracked_result)
        console = Console(file=MagicMock(), width=120, no_color=True)
        with console.capture() as capture:
            console.print(panel)
        output = capture.get()
        assert "MD5" in output

    def test_card_contains_attempts(self, cracked_result: CrackResult) -> None:
        panel = render_result_card(cracked_result)
        console = Console(file=MagicMock(), width=120, no_color=True)
        with console.capture() as capture:
            console.print(panel)
        output = capture.get()
        assert "10,000" in output or "10000" in output

    def test_card_contains_duration(self, cracked_result: CrackResult) -> None:
        panel = render_result_card(cracked_result)
        console = Console(file=MagicMock(), width=120, no_color=True)
        with console.capture() as capture:
            console.print(panel)
        output = capture.get()
        assert "1.5" in output

    def test_card_contains_entropy(self, cracked_result: CrackResult) -> None:
        panel = render_result_card(cracked_result)
        console = Console(file=MagicMock(), width=120, no_color=True)
        with console.capture() as capture:
            console.print(panel)
        output = capture.get()
        assert "bits" in output.lower()

    def test_card_contains_strength(self, cracked_result: CrackResult) -> None:
        panel = render_result_card(cracked_result)
        console = Console(file=MagicMock(), width=120, no_color=True)
        with console.capture() as capture:
            console.print(panel)
        output = capture.get()
        assert "weak" in output.lower() or "moderate" in output.lower() or "strong" in output.lower()

    def test_card_contains_patterns(self, cracked_result: CrackResult) -> None:
        panel = render_result_card(cracked_result)
        console = Console(file=MagicMock(), width=120, no_color=True)
        with console.capture() as capture:
            console.print(panel)
        output = capture.get()
        assert "common_suffix" in output or "Patterns" in output or "None detected" in output


# ---------------------------------------------------------------------------
# Batch summary table
# ---------------------------------------------------------------------------


class TestBatchSummaryTable:
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
        assert "weak" in output.lower() or "moderate" in output.lower() or "strong" in output.lower()
