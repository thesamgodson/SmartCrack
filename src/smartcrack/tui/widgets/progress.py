"""Progress widget — live speed, ETA, and progress bar."""

from __future__ import annotations

import time

from textual.app import ComposeResult
from textual.reactive import reactive
from textual.widgets import Label, ProgressBar, Static


def _format_speed(speed: float) -> str:
    """Return human-readable hash speed string."""
    if speed >= 1_000_000:
        return f"{speed / 1_000_000:.1f}M H/s"
    if speed >= 1_000:
        return f"{speed / 1_000:.1f}K H/s"
    return f"{speed:.0f} H/s"


def _format_eta(eta_seconds: float) -> str:
    """Return ETA string from remaining seconds."""
    if eta_seconds <= 0:
        return "—"
    if eta_seconds < 60:
        return f"~{eta_seconds:.0f}s"
    minutes = eta_seconds / 60
    return f"~{minutes:.1f}m"


class ProgressWidget(Static):
    """Shows current phase, speed, candidates tried, ETA, and a progress bar."""

    DEFAULT_CSS = """
    ProgressWidget {
        border: solid $primary;
        border-title-color: $primary;
        padding: 0 1;
        height: 6;
    }
    #progress-stats {
        height: 1;
    }
    #progress-phase {
        height: 1;
    }
    ProgressBar {
        margin-top: 0;
    }
    """

    phase_name: reactive[str] = reactive("—")
    phase_index: reactive[int] = reactive(0)
    phase_total: reactive[int] = reactive(1)
    attempts: reactive[int] = reactive(0)
    speed: reactive[float] = reactive(0.0)
    progress_pct: reactive[float] = reactive(0.0)

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self.border_title = "Progress"
        self._start_time: float = time.monotonic()
        self._last_attempts: int = 0
        self._last_time: float = time.monotonic()

    def compose(self) -> ComposeResult:
        yield Label("Phase: —", id="progress-phase")
        yield Label("Speed: —    Tried: 0    ETA: —", id="progress-stats")
        yield ProgressBar(total=100, show_eta=False, id="progress-bar")

    def update_progress(self, new_attempts: int) -> None:
        """Recalculate speed and update reactive state from new attempt count."""
        now = time.monotonic()
        elapsed = now - self._last_time
        if elapsed > 0.1:
            delta = new_attempts - self._last_attempts
            self.speed = delta / elapsed
            self._last_attempts = new_attempts
            self._last_time = now
        self.attempts = new_attempts
        self._refresh_stats()

    def update_phase(self, name: str, index: int, total: int) -> None:
        """Update phase name and counters."""
        self.phase_name = name
        self.phase_index = index
        self.phase_total = total
        self._refresh_phase()

    def _refresh_phase(self) -> None:
        label = self.query_one("#progress-phase", Label)
        label.update(
            f"Phase: [bold cyan]{self.phase_name}[/bold cyan]"
            f"    [[{self.phase_index + 1}/{self.phase_total}]]"
        )

    def _refresh_stats(self) -> None:
        speed_str = _format_speed(self.speed)
        total_time = time.monotonic() - self._start_time
        eta = 0.0
        if self.speed > 0 and self.progress_pct < 100:
            remaining_pct = 100 - self.progress_pct
            eta = (remaining_pct / 100) * (total_time / max(self.progress_pct / 100, 0.001))
        eta_str = _format_eta(eta)
        stats_label = self.query_one("#progress-stats", Label)
        stats_label.update(
            f"Speed: [green]{speed_str}[/green]"
            f"    Tried: [yellow]{self.attempts:,}[/yellow]"
            f"    ETA: [dim]{eta_str}[/dim]"
        )
