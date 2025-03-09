"""Shared test fixtures."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest


KNOWN_PAIRS: list[tuple[str, str, str]] = [
    ("password", "md5", hashlib.md5(b"password").hexdigest()),
    ("test123", "sha1", hashlib.sha1(b"test123").hexdigest()),
    ("hello", "sha256", hashlib.sha256(b"hello").hexdigest()),
    ("world", "sha512", hashlib.sha512(b"world").hexdigest()),
]


@pytest.fixture
def tmp_wordlist(tmp_path: Path) -> Path:
    """Create a small temporary wordlist."""
    words = ["apple", "banana", "password", "test123", "hello", "world", "admin", "root"]
    wordlist = tmp_path / "test_wordlist.txt"
    wordlist.write_text("\n".join(words) + "\n")
    return wordlist


@pytest.fixture
def known_md5_hash() -> tuple[str, str]:
    """Return (plaintext, md5_hash) pair."""
    return ("password", hashlib.md5(b"password").hexdigest())


@pytest.fixture
def known_sha256_hash() -> tuple[str, str]:
    """Return (plaintext, sha256_hash) pair."""
    return ("hello", hashlib.sha256(b"hello").hexdigest())
