"""Tests for hash computation and verification."""

from __future__ import annotations

import hashlib

import argon2
import bcrypt as bcrypt_lib
import pytest

from smartcrack.hashers import compute_hash, verify, verify_any
from smartcrack.models import HashTarget, HashType


class TestComputeHash:
    @pytest.mark.parametrize(
        "hash_type,expected_fn",
        [
            (HashType.MD5, hashlib.md5),
            (HashType.SHA1, hashlib.sha1),
            (HashType.SHA224, hashlib.sha224),
            (HashType.SHA256, hashlib.sha256),
            (HashType.SHA384, hashlib.sha384),
            (HashType.SHA512, hashlib.sha512),
        ],
    )
    def test_all_types(self, hash_type: HashType, expected_fn) -> None:
        result = compute_hash("test", hash_type)
        expected = expected_fn(b"test").hexdigest()
        assert result == expected

    def test_with_salt(self) -> None:
        result = compute_hash("pass", HashType.MD5, salt="salt")
        expected = hashlib.md5(b"passsalt").hexdigest()
        assert result == expected

    def test_unsupported_type_raises(self) -> None:
        with pytest.raises(ValueError, match="Unsupported"):
            compute_hash("test", HashType.UNKNOWN)


class TestVerify:
    def test_correct_match(self) -> None:
        h = hashlib.md5(b"password").hexdigest()
        target = HashTarget(hash_value=h, hash_type=HashType.MD5)
        assert verify("password", target)

    def test_wrong_plaintext(self) -> None:
        h = hashlib.md5(b"password").hexdigest()
        target = HashTarget(hash_value=h, hash_type=HashType.MD5)
        assert not verify("wrong", target)

    def test_unknown_type_returns_false(self) -> None:
        target = HashTarget(hash_value="abc", hash_type=HashType.UNKNOWN)
        assert not verify("anything", target)

    def test_case_insensitive_hash(self) -> None:
        h = hashlib.md5(b"test").hexdigest().upper()
        target = HashTarget(hash_value=h, hash_type=HashType.MD5)
        assert verify("test", target)


class TestVerifyAny:
    def test_finds_md5(self) -> None:
        h = hashlib.md5(b"hello").hexdigest()
        target = HashTarget(hash_value=h)
        assert verify_any("hello", target) == HashType.MD5

    def test_finds_sha256(self) -> None:
        h = hashlib.sha256(b"world").hexdigest()
        target = HashTarget(hash_value=h)
        assert verify_any("world", target) == HashType.SHA256

    def test_no_match(self) -> None:
        target = HashTarget(hash_value="0" * 32)
        assert verify_any("nope", target) is None

    def test_with_possible_types(self) -> None:
        h = hashlib.sha256(b"test").hexdigest()
        target = HashTarget(hash_value=h, possible_types=(HashType.SHA256,))
        assert verify_any("test", target) == HashType.SHA256

    def test_with_salt(self) -> None:
        h = hashlib.md5(b"passsalt").hexdigest()
        target = HashTarget(hash_value=h, salt="salt")
        assert verify_any("pass", target) == HashType.MD5


class TestBcryptHashing:
    def test_compute_hash_bcrypt(self) -> None:
        result = compute_hash("password123", HashType.BCRYPT)
        assert result.startswith("$2b$")
        assert bcrypt_lib.checkpw(b"password123", result.encode())

    def test_verify_bcrypt(self) -> None:
        hashed = bcrypt_lib.hashpw(b"test123", bcrypt_lib.gensalt(rounds=4))
        target = HashTarget(hash_value=hashed.decode(), hash_type=HashType.BCRYPT)
        assert verify("test123", target) is True
        assert verify("wrong", target) is False


class TestArgon2Hashing:
    def test_compute_hash_argon2(self) -> None:
        result = compute_hash("password123", HashType.ARGON2)
        assert result.startswith("$argon2")

    def test_verify_argon2(self) -> None:
        ph = argon2.PasswordHasher(time_cost=1, memory_cost=8192)
        hashed = ph.hash("test123")
        target = HashTarget(hash_value=hashed, hash_type=HashType.ARGON2)
        assert verify("test123", target) is True
        assert verify("wrong", target) is False


class TestNTLMHashing:
    def test_compute_hash_ntlm(self) -> None:
        # Known NTLM hash of "password" = MD4("password".encode("utf-16-le"))
        result = compute_hash("password", HashType.NTLM)
        assert result == "8846f7eaee8fb117ad06bdd830b7586c"

    def test_verify_ntlm(self) -> None:
        target = HashTarget(
            hash_value="8846f7eaee8fb117ad06bdd830b7586c",
            hash_type=HashType.NTLM,
        )
        assert verify("password", target) is True
