"""Attack phases timeline widget."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.reactive import reactive
from textual.widgets import Static

_STATUS_ICONS: dict[str, str] = {
    "pending": "[dim][ ][/dim]",
    "active": "[yellow]>[/yellow]",
    "done": "[green]✓[/green]",
    "failed": "[red]✗[/red]",
}


class PhaseItem(Static):
    """Single phase badge in the timeline."""

    DEFAULT_CSS = """
    PhaseItem {
        width: auto;
        padding: 0 1;
    }
    """

    status: reactive[str] = reactive("pending")

    def __init__(self, name: str, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._name = name

    def render(self) -> str:
        icon = _STATUS_ICONS.get(self.status, "[ ]")
        return f"{icon} {self._name}"

    def set_status(self, status: str) -> None:
        """Update the phase status: pending | active | done | failed."""
        self.status = status


class PhasesWidget(Static):
    """Horizontal timeline showing all attack phases and their status."""

    DEFAULT_CSS = """
    PhasesWidget {
        border: solid $primary;
        border-title-color: $primary;
        padding: 0 1;
        height: 3;
    }
    #phases-row {
        height: 1;
        layout: horizontal;
    }
    """

    def __init__(self, phase_names: list[str], **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._phase_names = phase_names
        self.border_title = "Attack Phases"

    def compose(self) -> ComposeResult:
        with Horizontal(id="phases-row"):
            for name in self._phase_names:
                yield PhaseItem(name, id=f"phase-{name.lower().replace(' ', '-')}")

    def set_phase_active(self, index: int) -> None:
        """Mark phase at index active; mark previous phases done."""
        items = list(self.query(PhaseItem))
        for i, item in enumerate(items):
            if i < index:
                item.set_status("done")
            elif i == index:
                item.set_status("active")
            else:
                item.set_status("pending")

    def set_all_done(self) -> None:
        """Mark every phase as done (cracking succeeded or all exhausted)."""
        for item in self.query(PhaseItem):
            item.set_status("done")
