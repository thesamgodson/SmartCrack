"""Tests for the HashCrack Textual TUI dashboard."""

from __future__ import annotations

import pytest

from hashcrack.models import AttackPhase, CrackResult, HashTarget, HashType
from hashcrack.orchestrator import AttackPlan
from hashcrack.tui.app import CrackComplete, CrackProgress, HashCrackApp, PhaseChanged
from hashcrack.tui.widgets.hash_info import HashInfoWidget
from hashcrack.tui.widgets.log import LogWidget
from hashcrack.tui.widgets.phases import PhasesWidget, PhaseItem
from hashcrack.tui.widgets.progress import ProgressWidget
from hashcrack.tui.widgets.result import ResultWidget


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_target() -> HashTarget:
    return HashTarget(
        hash_value="5f4dcc3b5aa765d61d8327deb882cf99",
        hash_type=HashType.MD5,
    )


def _make_plans() -> list[AttackPlan]:
    """Return two minimal no-op attack plans."""
    return [
        AttackPlan(
            name="Dictionary",
            phase=AttackPhase.DICTIONARY,
            candidates_fn=lambda: iter([]),
        ),
        AttackPlan(
            name="Rules",
            phase=AttackPhase.RULES,
            candidates_fn=lambda: iter([]),
        ),
    ]


def _make_app(auto_start: bool = False) -> HashCrackApp:
    """Create a test app; auto_start=False prevents the worker from firing."""
    return HashCrackApp(
        target=_make_target(),
        plans=_make_plans(),
        max_workers=1,
        batch_size=100,
        auto_start=auto_start,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_app_launches_without_crash() -> None:
    """App should mount and render without raising exceptions."""
    app = _make_app()
    async with app.run_test():
        assert app is not None
        # Header should be present
        assert app.title == f"HashCrack v{__import__('hashcrack').__version__}"


@pytest.mark.asyncio
async def test_hash_info_widget_renders() -> None:
    """HashInfoWidget should render hash value and type."""
    target = _make_target()
    app = _make_app()
    async with app.run_test():
        widget = app.query_one("#hash-info", HashInfoWidget)
        assert widget is not None
        # The widget should have the correct target
        assert widget._target.hash_value == target.hash_value


@pytest.mark.asyncio
async def test_progress_widget_renders_initial_state() -> None:
    """ProgressWidget should be present with initial zero attempts."""
    app = _make_app()
    async with app.run_test():
        widget = app.query_one("#progress", ProgressWidget)
        assert widget is not None
        assert widget.attempts == 0


@pytest.mark.asyncio
async def test_phases_widget_renders() -> None:
    """PhasesWidget should render one PhaseItem per plan."""
    app = _make_app()
    async with app.run_test():
        widget = app.query_one("#phases", PhasesWidget)
        items = list(widget.query(PhaseItem))
        assert len(items) == 2


@pytest.mark.asyncio
async def test_log_widget_renders() -> None:
    """LogWidget should be present after mount."""
    app = _make_app()
    async with app.run_test():
        widget = app.query_one("#log", LogWidget)
        assert widget is not None


@pytest.mark.asyncio
async def test_result_widget_hidden_initially() -> None:
    """ResultWidget should be hidden until cracking completes."""
    app = _make_app()
    async with app.run_test():
        widget = app.query_one("#result", ResultWidget)
        assert widget.display is False


@pytest.mark.asyncio
async def test_crack_progress_updates_progress_widget() -> None:
    """CrackProgress message should update attempt count on ProgressWidget."""
    app = _make_app()
    async with app.run_test() as pilot:
        app.post_message(CrackProgress(42_000))
        await pilot.pause()
        widget = app.query_one("#progress", ProgressWidget)
        assert widget.attempts == 42_000


@pytest.mark.asyncio
async def test_phase_changed_updates_phases_widget() -> None:
    """PhaseChanged message should mark the correct phase as active."""
    app = _make_app()
    async with app.run_test() as pilot:
        app.post_message(PhaseChanged("Rules", 1, 2))
        await pilot.pause()
        phases = app.query_one("#phases", PhasesWidget)
        items = list(phases.query(PhaseItem))
        assert items[0].status == "done"
        assert items[1].status == "active"


@pytest.mark.asyncio
async def test_phase_changed_updates_progress_label() -> None:
    """PhaseChanged message should update phase name in ProgressWidget."""
    app = _make_app()
    async with app.run_test() as pilot:
        app.post_message(PhaseChanged("Dictionary", 0, 2))
        await pilot.pause()
        widget = app.query_one("#progress", ProgressWidget)
        assert widget.phase_name == "Dictionary"


@pytest.mark.asyncio
async def test_crack_complete_shows_result_cracked() -> None:
    """CrackComplete with found=True should reveal ResultWidget with plaintext."""
    app = _make_app()
    result = CrackResult(
        found=True,
        plaintext="password",
        hash_type=HashType.MD5,
        attack_phase=AttackPhase.DICTIONARY,
        attempts=1_000,
        duration_seconds=0.5,
    )
    async with app.run_test() as pilot:
        app.post_message(CrackComplete(result))
        await pilot.pause()
        widget = app.query_one("#result", ResultWidget)
        assert widget.display is True
        assert "cracked" in widget.classes


@pytest.mark.asyncio
async def test_crack_complete_shows_result_not_found() -> None:
    """CrackComplete with found=False should reveal ResultWidget in error state."""
    app = _make_app()
    result = CrackResult(
        found=False,
        attempts=500,
        duration_seconds=1.0,
    )
    async with app.run_test() as pilot:
        app.post_message(CrackComplete(result))
        await pilot.pause()
        widget = app.query_one("#result", ResultWidget)
        assert widget.display is True
        assert "not-found" in widget.classes


@pytest.mark.asyncio
async def test_all_phases_done_on_complete() -> None:
    """CrackComplete should mark all phases as done."""
    app = _make_app()
    result = CrackResult(found=False, attempts=0, duration_seconds=0.0)
    async with app.run_test() as pilot:
        app.post_message(CrackComplete(result))
        await pilot.pause()
        phases = app.query_one("#phases", PhasesWidget)
        for item in phases.query(PhaseItem):
            assert item.status == "done"


@pytest.mark.asyncio
async def test_key_q_triggers_quit() -> None:
    """Pressing q should exit the app."""
    app = _make_app()
    async with app.run_test() as pilot:
        await pilot.press("q")
        # After quit the app should no longer be running
        assert not app.is_running
