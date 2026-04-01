"""Wordlist loading and generator pipelines."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterator

logger = logging.getLogger(__name__)


def file_candidates(path: Path, encoding: str = "iso-8859-1") -> Iterator[str]:
    """Yield lines from a wordlist file as a generator. Never materializes full list."""
    with open(path, "r", encoding=encoding) as f:
        for line in f:
            stripped = line.rstrip("\n\r")
            if stripped:
                yield stripped


def file_candidates_from_offset(
    path: Path, offset: int = 0, encoding: str = "iso-8859-1"
) -> Iterator[str]:
    """Yield lines from a wordlist file, skipping the first `offset` lines."""
    yielded = False
    with open(path, "r", encoding=encoding) as f:
        for i, line in enumerate(f):
            if i < offset:
                continue
            stripped = line.rstrip("\n\r")
            if stripped:
                yielded = True
                yield stripped
    if not yielded and offset > 0:
        logger.warning(
            "Wordlist offset %d skipped all lines in %s — "
            "the wordlist may be shorter than the saved offset",
            offset,
            path,
        )


def resolve_wordlist(path: Path) -> Path:
    """Resolve wordlist path, falling back to bundled 100K.txt."""
    if path.exists():
        return path
    bundled = Path(__file__).parent / "data" / "100K.txt"
    if bundled.exists():
        return bundled
    raise FileNotFoundError(f"Wordlist not found: {path} (bundled fallback also missing)")
