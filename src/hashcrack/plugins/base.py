"""Base classes and protocols for hashcrack plugins."""
from __future__ import annotations
from typing import Protocol, Iterator, runtime_checkable
from hashcrack.models import HashType


@runtime_checkable
class HashPlugin(Protocol):
    """Plugin that adds support for a new hash type."""
    name: str
    hash_type: HashType

    def compute(self, plaintext: str, **kwargs: object) -> str: ...
    def verify(self, plaintext: str, hash_value: str) -> bool: ...


@runtime_checkable
class AttackPlugin(Protocol):
    """Plugin that provides a new attack strategy."""
    name: str

    def candidates(self, context: dict[str, object]) -> Iterator[str]: ...


@runtime_checkable
class ProfilerPlugin(Protocol):
    """Plugin that provides an alternative profiler backend."""
    name: str

    def generate(self, profile: object) -> Iterator[str]: ...
