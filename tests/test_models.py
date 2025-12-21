"""Tests for core data models."""

from __future__ import annotations

import pytest

from hashcrack.models import (
    AttackConfig,
    CrackResult,
    HashTarget,
    HashType,
    LLMConfig,
    TargetProfile,
)


class TestHashType:
    def test_all_types_exist(self) -> None:
        expected = {"MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "BCRYPT", "ARGON2", "NTLM", "UNKNOWN"}
        assert {t.name for t in HashType} == expected


class TestHashTarget:
    def test_frozen(self) -> None:
        target = HashTarget(hash_value="abc123")
        with pytest.raises(AttributeError):
            target.hash_value = "changed"  # type: ignore[misc]

    def test_defaults(self) -> None:
        target = HashTarget(hash_value="abc")
        assert target.hash_type == HashType.UNKNOWN
        assert target.salt == ""
        assert target.possible_types == ()


class TestCrackResult:
    def test_not_found(self) -> None:
        result = CrackResult(found=False, attempts=1000)
        assert not result.found
        assert result.plaintext is None

    def test_found(self) -> None:
        result = CrackResult(found=True, plaintext="password", hash_type=HashType.MD5)
        assert result.found
        assert result.plaintext == "password"


class TestAttackConfig:
    def test_defaults(self) -> None:
        config = AttackConfig()
        assert config.batch_size == 10_000
        assert config.max_workers is None
        assert not config.rules_enabled


class TestTargetProfile:
    def test_frozen(self) -> None:
        profile = TargetProfile(first_name="John")
        with pytest.raises(AttributeError):
            profile.first_name = "Jane"  # type: ignore[misc]

    def test_keywords_tuple(self) -> None:
        profile = TargetProfile(keywords=("hiker", "coder"))
        assert len(profile.keywords) == 2


class TestLLMConfig:
    def test_defaults(self) -> None:
        config = LLMConfig()
        assert config.base_url == ""
        assert config.model == ""
        assert config.api_key == ""
        assert config.timeout_seconds == 90
