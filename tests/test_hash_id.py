"""Tests for the hash auto-identification module."""

from __future__ import annotations

import pytest

from hashcrack.hash_id import identify_hash
from hashcrack.models import HashType


class TestMD5:
    def test_md5_returns_md5_and_ntlm(self) -> None:
        md5_hash = "d41d8cd98f00b204e9800998ecf8427e"  # MD5("") — 32 hex chars
        results = identify_hash(md5_hash)
        types = [t for t, _ in results]
        assert HashType.MD5 in types
        assert HashType.NTLM in types

    def test_md5_confidence(self) -> None:
        md5_hash = "d41d8cd98f00b204e9800998ecf8427e"
        results = identify_hash(md5_hash)
        by_type = dict(results)
        assert by_type[HashType.MD5] == pytest.approx(0.95)
        assert by_type[HashType.NTLM] == pytest.approx(0.5)

    def test_md5_uppercase(self) -> None:
        md5_hash = "D41D8CD98F00B204E9800998ECF8427E"
        results = identify_hash(md5_hash)
        types = [t for t, _ in results]
        assert HashType.MD5 in types


class TestSHA1:
    def test_sha1_identified(self) -> None:
        sha1_hash = "da39a3ee5e6b4b0d3255bfef95601890afd80709"  # SHA1("") — 40 hex
        results = identify_hash(sha1_hash)
        assert results == [(HashType.SHA1, pytest.approx(0.95))]

    def test_sha1_uppercase(self) -> None:
        sha1_hash = "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"
        results = identify_hash(sha1_hash)
        assert results[0][0] == HashType.SHA1


class TestSHA224:
    def test_sha224_identified(self) -> None:
        # 56 hex chars
        sha224_hash = "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        results = identify_hash(sha224_hash)
        assert results == [(HashType.SHA224, pytest.approx(0.95))]


class TestSHA256:
    def test_sha256_identified(self) -> None:
        # 64 hex chars
        sha256_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        results = identify_hash(sha256_hash)
        assert results == [(HashType.SHA256, pytest.approx(0.95))]

    def test_sha256_uppercase(self) -> None:
        sha256_hash = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
        results = identify_hash(sha256_hash)
        assert results[0][0] == HashType.SHA256


class TestSHA384:
    def test_sha384_identified(self) -> None:
        # 96 hex chars
        sha384_hash = (
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da"
            "274edebfe76f65fbd51ad2f14898b95b"
        )
        results = identify_hash(sha384_hash)
        assert results == [(HashType.SHA384, pytest.approx(0.95))]


class TestSHA512:
    def test_sha512_identified(self) -> None:
        # 128 hex chars
        sha512_hash = (
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
            "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        )
        results = identify_hash(sha512_hash)
        assert results == [(HashType.SHA512, pytest.approx(0.95))]


class TestBcrypt:
    def test_bcrypt_2b_prefix(self) -> None:
        bcrypt_hash = "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW"
        results = identify_hash(bcrypt_hash)
        assert results == [(HashType.BCRYPT, pytest.approx(0.99))]

    def test_bcrypt_2a_prefix(self) -> None:
        bcrypt_hash = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
        results = identify_hash(bcrypt_hash)
        assert results == [(HashType.BCRYPT, pytest.approx(0.99))]

    def test_bcrypt_2y_prefix(self) -> None:
        bcrypt_hash = "$2y$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
        results = identify_hash(bcrypt_hash)
        assert results == [(HashType.BCRYPT, pytest.approx(0.99))]


class TestArgon2:
    def test_argon2id_identified(self) -> None:
        argon2_hash = "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG"
        results = identify_hash(argon2_hash)
        assert results == [(HashType.ARGON2, pytest.approx(0.99))]

    def test_argon2i_identified(self) -> None:
        argon2_hash = "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ"
        results = identify_hash(argon2_hash)
        assert results == [(HashType.ARGON2, pytest.approx(0.99))]


class TestUnknown:
    def test_garbage_string(self) -> None:
        results = identify_hash("not-a-hash-at-all!")
        assert results == [(HashType.UNKNOWN, pytest.approx(0.0))]

    def test_empty_string(self) -> None:
        results = identify_hash("")
        assert results == [(HashType.UNKNOWN, pytest.approx(0.0))]

    def test_wrong_length_hex(self) -> None:
        # 33 hex chars — valid hex but unknown length
        results = identify_hash("d41d8cd98f00b204e9800998ecf8427e0")
        assert results == [(HashType.UNKNOWN, pytest.approx(0.0))]
