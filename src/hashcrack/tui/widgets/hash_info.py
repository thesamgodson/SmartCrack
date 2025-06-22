"""Hash info widget — displays hash value, type and salt."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.widgets import Static

from hashcrack.models import HashTarget, HashType

_MAX_HASH_DISPLAY = 48


def _truncate_hash(value: str, max_len: int = _MAX_HASH_DISPLAY) -> str:
    """Return hash truncated with ellipsis when over max_len."""
    if len(value) <= max_len:
        return value
    return value[:max_len] + "…"


def _confidence_label(target: HashTarget) -> str:
    """Return type name with optional confidence percent."""
    if target.hash_type == HashType.UNKNOWN and target.possible_types:
        top = target.possible_types[0]
        return f"{top.name} (detected)"
    return target.hash_type.name


class HashInfoWidget(Static):
    """Static widget showing hash info — set once at startup."""

    DEFAULT_CSS = """
    HashInfoWidget {
        border: solid $primary;
        border-title-color: $primary;
        padding: 0 1;
        height: 4;
    }
    """

    def __init__(self, target: HashTarget, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self._target = target
        self.border_title = "Hash Info"

    def compose(self) -> ComposeResult:
        hash_display = _truncate_hash(self._target.hash_value)
        type_label = _confidence_label(self._target)
        salt_label = self._target.salt if self._target.salt else "(none)"

        yield Static(
            f"[bold]Hash:[/bold]  [cyan]{hash_display}[/cyan]\n"
            f"[bold]Type:[/bold]  [yellow]{type_label}[/yellow]"
            f"          [bold]Salt:[/bold] [dim]{salt_label}[/dim]"
        )
