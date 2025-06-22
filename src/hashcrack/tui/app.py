"""HashCrack Textual TUI application."""

from __future__ import annotations

import logging
import threading
from typing import ClassVar

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.message import Message
from textual.widgets import Footer, Header

from hashcrack import __version__
from hashcrack.models import CrackResult, HashTarget
from hashcrack.orchestrator import AttackPlan, run_orchestrated
from hashcrack.tui.widgets.ai_reasoning import AIReasoningWidget
from hashcrack.tui.widgets.hash_info import HashInfoWidget
from hashcrack.tui.widgets.log import LogWidget
from hashcrack.tui.widgets.phases import PhasesWidget
from hashcrack.tui.widgets.progress import ProgressWidget
from hashcrack.tui.widgets.result import ResultWidget


# ---------------------------------------------------------------------------
# Messages
# ---------------------------------------------------------------------------


class CrackProgress(Message):
    """Emitted when the cracker reports new attempt counts."""

    def __init__(self, attempts: int) -> None:
        super().__init__()
        self.attempts = attempts


class PhaseChanged(Message):
    """Emitted when the orchestrator moves to a new attack phase."""

    def __init__(self, name: str, index: int, total: int) -> None:
        super().__init__()
        self.name = name
        self.index = index
        self.total = total


class CrackComplete(Message):
    """Emitted when orchestration finishes (found or exhausted)."""

    def __init__(self, result: CrackResult) -> None:
        super().__init__()
        self.result = result


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------


class HashCrackApp(App[CrackResult | None]):
    """Interactive TUI dashboard for HashCrack."""

    TITLE = f"HashCrack v{__version__}"
    SUB_TITLE = "Intelligent Hash Cracking"

    BINDINGS: ClassVar[list[Binding]] = [
        Binding("q", "quit", "Quit", show=True),
    ]

    DEFAULT_CSS = """
    Screen {
        background: $background;
        layout: vertical;
    }
    #main-container {
        padding: 0 1;
    }
    HashInfoWidget {
        margin-bottom: 1;
    }
    ProgressWidget {
        margin-bottom: 1;
    }
    PhasesWidget {
        margin-bottom: 1;
    }
    AIReasoningWidget {
        margin-bottom: 1;
    }
    LogWidget {
        margin-bottom: 1;
    }
    ResultWidget {
        margin-bottom: 1;
    }
    """

    def __init__(
        self,
        target: HashTarget,
        plans: list[AttackPlan],
        max_workers: int | None = None,
        batch_size: int = 10_000,
        auto_start: bool = True,
        **kwargs: object,
    ) -> None:
        super().__init__(**kwargs)
        self._target = target
        self._plans = plans
        self._max_workers = max_workers
        self._batch_size = batch_size
        self._auto_start = auto_start
        self._total_attempts: int = 0
        self._attempts_lock = threading.Lock()
        self._result: CrackResult | None = None

    def compose(self) -> ComposeResult:
        yield Header()
        phase_names = [p.name for p in self._plans]
        with Vertical(id="main-container"):
            yield HashInfoWidget(self._target, id="hash-info")
            yield ProgressWidget(id="progress")
            yield PhasesWidget(phase_names, id="phases")
            yield AIReasoningWidget(id="ai-reasoning")
            yield LogWidget(id="log")
            yield ResultWidget(id="result")
        yield Footer()

    def on_mount(self) -> None:
        """Start cracking in a background worker once the UI is ready."""
        log = self.query_one("#log", LogWidget)
        log.write_info(f"Starting — {len(self._plans)} phase(s) planned")
        if self._auto_start:
            self._run_cracking()

    @work(thread=True, name="cracking-worker")
    def _run_cracking(self) -> None:
        """Run the orchestrator in a background thread."""
        logger = logging.getLogger(__name__)

        def _on_progress(n: int) -> None:
            with self._attempts_lock:
                self._total_attempts += n
                total = self._total_attempts
            self.call_from_thread(self.post_message, CrackProgress(total))

        def _on_phase_change(phase_name: str, phase_idx: int, total: int) -> None:
            self.call_from_thread(
                self.post_message, PhaseChanged(phase_name, phase_idx, total)
            )

        try:
            result = run_orchestrated(
                target=self._target,
                plans=self._plans,
                max_workers=self._max_workers,
                batch_size=self._batch_size,
                on_progress=_on_progress,
                on_phase_change=_on_phase_change,
            )
        except Exception:
            logger.exception("Cracking worker failed")
            result = CrackResult(found=False, attempts=self._total_attempts)

        self._result = result
        self.call_from_thread(self.post_message, CrackComplete(result))

    # ------------------------------------------------------------------
    # Message handlers
    # ------------------------------------------------------------------

    def on_crack_progress(self, message: CrackProgress) -> None:
        """Update progress widget with latest attempt count."""
        progress = self.query_one("#progress", ProgressWidget)
        progress.update_progress(message.attempts)

    def on_phase_changed(self, message: PhaseChanged) -> None:
        """Update phases timeline and progress label."""
        phases = self.query_one("#phases", PhasesWidget)
        phases.set_phase_active(message.index)

        progress = self.query_one("#progress", ProgressWidget)
        progress.update_phase(message.name, message.index, message.total)

        log = self.query_one("#log", LogWidget)
        log.write_phase(
            f"Phase [{message.index + 1}/{message.total}]: {message.name}"
        )

    def on_crack_complete(self, message: CrackComplete) -> None:
        """Show final result and mark phases done."""
        result = message.result
        phases = self.query_one("#phases", PhasesWidget)
        phases.set_all_done()

        result_widget = self.query_one("#result", ResultWidget)
        result_widget.show_result(result)

        log = self.query_one("#log", LogWidget)
        if result.found:
            log.write_success(f"Cracked! Plaintext: {result.plaintext}")
        else:
            log.write_error(
                f"Not found after {result.attempts:,} attempts"
            )

    def action_quit(self) -> None:
        """Quit the app, returning the crack result."""
        self.exit(self._result)
