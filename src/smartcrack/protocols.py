"""Protocol definitions for pluggable attacks and hash identification."""

from __future__ import annotations

from typing import Iterator, Protocol, runtime_checkable

from smartcrack.models import HashTarget, HashType, TargetProfile


@runtime_checkable
class AttackStrategy(Protocol):
    """Any attack must implement this interface."""

    @property
    def name(self) -> str: ...

    def candidates(
        self, target: HashTarget, profile: TargetProfile | None = None
    ) -> Iterator[str]: ...


@runtime_checkable
class HashIdentifierProtocol(Protocol):
    """Identifies hash type from raw hash string."""

    def identify(self, hash_value: str) -> list[HashType]: ...


@runtime_checkable
class ProfilerProtocol(Protocol):
    """Generates password candidates from target profile."""

    def generate(self, profile: TargetProfile) -> Iterator[str]: ...

    @property
    def requires_api(self) -> bool: ...
