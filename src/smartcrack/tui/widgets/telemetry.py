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
