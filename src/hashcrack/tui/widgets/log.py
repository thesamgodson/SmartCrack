"""Scrolling log widget with color-coded message types."""

from __future__ import annotations

from datetime import datetime

from rich.text import Text
from textual.app import ComposeResult
from textual.widgets import RichLog, Static

_LEVEL_STYLES: dict[str, str] = {
    "info": "white",
    "phase": "cyan",
    "success": "bold green",
    "error": "bold red",
    "warn": "yellow",
}


def _timestamp() -> str:
    return datetime.now().strftime("%H:%M:%S")


class LogWidget(Static):
    """Color-coded scrolling log backed by Textual RichLog."""

    DEFAULT_CSS = """
    LogWidget {
        border: solid $primary;
        border-title-color: $primary;
        height: 10;
    }
    RichLog {
        height: 1fr;
        padding: 0 1;
    }
    """

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self.border_title = "Log"

    def compose(self) -> ComposeResult:
        yield RichLog(highlight=False, markup=True, wrap=False, id="log-richlog")

    def write_message(self, message: str, level: str = "info") -> None:
        """Append a timestamped message with the given level style."""
        style = _LEVEL_STYLES.get(level, "white")
        rich_log = self.query_one("#log-richlog", RichLog)
        ts = _timestamp()
        text = Text.assemble(
            (f"[{ts}] ", "dim"),
            (message, style),
        )
        rich_log.write(text)

    def write_info(self, message: str) -> None:
        """Append an info-level message."""
        self.write_message(message, level="info")

    def write_phase(self, message: str) -> None:
        """Append a phase-change message."""
        self.write_message(message, level="phase")

    def write_success(self, message: str) -> None:
        """Append a success message."""
        self.write_message(message, level="success")

    def write_error(self, message: str) -> None:
        """Append an error message."""
        self.write_message(message, level="error")
