"""Tests for the hash auto-identification module."""

from __future__ import annotations

import pytest

from smartcrack.hash_id import identify_hash
from smartcrack.models import HashType


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

    def test_argon2d_identified(self) -> None:
        argon2_hash = "$argon2d$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG"
        results = identify_hash(argon2_hash)
        assert results == [(HashType.ARGON2, pytest.approx(0.99))]


class TestSHA512Crypt:
    def test_sha512crypt_identified(self) -> None:
        h = "$6$rounds=5000$saltsalt$abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12"
        results = identify_hash(h)
        assert results == [(HashType.SHA512CRYPT, pytest.approx(0.99))]


class TestSHA256Crypt:
    def test_sha256crypt_identified(self) -> None:
        h = "$5$rounds=5000$saltsalt$abcdef1234567890abcdef1234567890abcdef1234567890"
        results = identify_hash(h)
        assert results == [(HashType.SHA256CRYPT, pytest.approx(0.99))]


class TestMD5Crypt:
    def test_md5crypt_identified(self) -> None:
        h = "$1$saltsalt$abcdef1234567890abcdef12"
        results = identify_hash(h)
        assert results == [(HashType.MD5CRYPT, pytest.approx(0.99))]


class TestYescrypt:
    def test_yescrypt_identified(self) -> None:
        h = "$y$j9T$F5Jx5fExrKuPp53xLKQ..1$X3DX6M94c7o.9agCG/4.QhbgP48jz8OHnv0ym/O2QOB"
        results = identify_hash(h)
        assert results == [(HashType.YESCRYPT, pytest.approx(0.99))]


class TestPhpass:
    def test_phpass_P_prefix(self) -> None:
        h = "$P$B12345678abcdefghijklmnopqrstuv"
        results = identify_hash(h)
        assert results == [(HashType.PHPASS, pytest.approx(0.99))]

    def test_phpass_H_prefix(self) -> None:
        h = "$H$B12345678abcdefghijklmnopqrstuv"
        results = identify_hash(h)
        assert results == [(HashType.PHPASS, pytest.approx(0.99))]


class TestDrupal7:
    def test_drupal7_identified(self) -> None:
        h = "$S$DabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234"
        results = identify_hash(h)
        assert results == [(HashType.DRUPAL7, pytest.approx(0.99))]


class TestKerberosTGS:
    def test_kerberos_tgs_23(self) -> None:
        h = "$krb5tgs$23$*user$realm$spn*$aabbccddee"
        results = identify_hash(h)
        assert results == [(HashType.KERBEROS_TGS, pytest.approx(0.99))]

    def test_kerberos_tgs_17(self) -> None:
        h = "$krb5tgs$17$user$realm$data"
        results = identify_hash(h)
        assert results == [(HashType.KERBEROS_TGS, pytest.approx(0.99))]

    def test_kerberos_tgs_18(self) -> None:
        h = "$krb5tgs$18$user$realm$data"
        results = identify_hash(h)
        assert results == [(HashType.KERBEROS_TGS, pytest.approx(0.99))]


class TestKerberosASREP:
    def test_kerberos_asrep_identified(self) -> None:
        h = "$krb5asrep$23$user@REALM:aabbccddee"
        results = identify_hash(h)
        assert results == [(HashType.KERBEROS_ASREP, pytest.approx(0.99))]


class TestDCC2:
    def test_dcc2_identified(self) -> None:
        h = "$DCC2$10240#user#aabbccddeeff00112233445566778899"
        results = identify_hash(h)
        assert results == [(HashType.DCC2, pytest.approx(0.99))]


class TestDCC1:
    def test_dcc1_identified(self) -> None:
        h = "$DCC$user#aabbccddeeff00112233445566778899"
        results = identify_hash(h)
        assert results == [(HashType.DCC1, pytest.approx(0.95))]


class TestDjangoPBKDF2:
    def test_django_pbkdf2_identified(self) -> None:
        h = "pbkdf2_sha256$260000$salt$hash_base64_encoded"
        results = identify_hash(h)
        assert results == [(HashType.DJANGO_PBKDF2, pytest.approx(0.99))]


class TestLDAPSSHA:
    def test_ldap_ssha_identified(self) -> None:
        h = "{SSHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="
        results = identify_hash(h)
        assert results == [(HashType.LDAP_SSHA, pytest.approx(0.99))]


class TestScrypt:
    def test_scrypt_colon_prefix(self) -> None:
        h = "SCRYPT:1024:8:1:c2FsdA==:aGFzaA=="
        results = identify_hash(h)
        assert results == [(HashType.SCRYPT, pytest.approx(0.99))]

    def test_scrypt_dollar_prefix(self) -> None:
        h = "$7$C6..../....SodiumChloride$kBGj9fHznVYFQMEn/qDCfrDevf9YDtcDdKvEqHJLV8D"
        results = identify_hash(h)
        assert results == [(HashType.SCRYPT, pytest.approx(0.95))]


class TestLM:
    def test_lm_prefix_format(self) -> None:
        h = "$LM$aabbccddeeff0011"
        results = identify_hash(h)
        assert results == [(HashType.LM, pytest.approx(0.95))]

    def test_lm_bare_16_hex(self) -> None:
        h = "aabbccddeeff0011"
        results = identify_hash(h)
        types = [t for t, _ in results]
        assert HashType.LM in types


class TestPostgresSCRAM:
    def test_postgres_scram_identified(self) -> None:
        h = "SCRAM-SHA-256$4096:salt$StoredKey:ServerKey"
        results = identify_hash(h)
        assert results == [(HashType.POSTGRES_SCRAM, pytest.approx(0.99))]


class TestPostgresMD5:
    def test_postgres_md5_identified(self) -> None:
        h = "md5" + "a" * 32
        results = identify_hash(h)
        assert results == [(HashType.POSTGRES_MD5, pytest.approx(0.97))]


class TestMySQL41:
    def test_mysql41_identified(self) -> None:
        h = "*" + "A" * 40
        results = identify_hash(h)
        assert results == [(HashType.MYSQL41, pytest.approx(0.99))]


class TestMSSQL2012:
    def test_mssql_0x0200(self) -> None:
        h = "0x0200AABBCCDD00112233445566778899AABBCCDDEEFF"
        results = identify_hash(h)
        assert results == [(HashType.MSSQL2012, pytest.approx(0.95))]

    def test_mssql_0x0100(self) -> None:
        h = "0x0100AABBCCDD00112233445566778899AABBCCDDEEFF"
        results = identify_hash(h)
        assert results == [(HashType.MSSQL2012, pytest.approx(0.95))]


class TestOracle11G:
    def test_oracle11g_identified(self) -> None:
        h = "S:" + "A" * 40
        results = identify_hash(h)
        assert results == [(HashType.ORACLE11G, pytest.approx(0.95))]


class TestOracle12C:
    def test_oracle12c_identified(self) -> None:
        h = "T:" + "A" * 40
        results = identify_hash(h)
        assert results == [(HashType.ORACLE12C, pytest.approx(0.95))]


class TestNetNTLMv2:
    def test_netntlmv2_identified(self) -> None:
        h = "user::DOMAIN:challenge:response:blob:extra:more"
        results = identify_hash(h)
        assert results == [(HashType.NETNTLMV2, pytest.approx(0.95))]


class TestNetNTLMv1:
    def test_netntlmv1_identified(self) -> None:
        h = "user::DOMAIN:lm:ntlm"
        results = identify_hash(h)
        assert results == [(HashType.NETNTLMV1, pytest.approx(0.90))]


class TestKeePass:
    def test_keepass_identified(self) -> None:
        h = "$keepass$*2*6000*0*aabbccdd"
        results = identify_hash(h)
        assert results == [(HashType.KEEPASS, pytest.approx(0.99))]


class TestWPA2PMKID:
    def test_wpa2_pmkid_identified(self) -> None:
        h = "WPA*02*aabbccdd*112233445566*778899aabbcc*NetworkName"
        results = identify_hash(h)
        assert results == [(HashType.WPA2_PMKID, pytest.approx(0.99))]


class TestMSOffice:
    def test_ms_office_identified(self) -> None:
        h = "$office$*2013*100000*256*16*salt*hash"
        results = identify_hash(h)
        assert results == [(HashType.MS_OFFICE, pytest.approx(0.99))]


class TestPDF:
    def test_pdf_identified(self) -> None:
        h = "$pdf$4*4*128*-1060*1*16*aabbccdd*32*eeff0011"
        results = identify_hash(h)
        assert results == [(HashType.PDF, pytest.approx(0.99))]


class TestRAR5:
    def test_rar5_identified(self) -> None:
        h = "$RAR5$*0*aabbccdd*eeff0011"
        results = identify_hash(h)
        assert results == [(HashType.RAR5, pytest.approx(0.99))]


class TestSevenZip:
    def test_7zip_identified(self) -> None:
        h = "$7z$0$19$0$salt$data"
        results = identify_hash(h)
        assert results == [(HashType.SEVENZIP, pytest.approx(0.99))]


class TestBitcoin:
    def test_bitcoin_identified(self) -> None:
        h = "$bitcoin$96$aabbccddee"
        results = identify_hash(h)
        assert results == [(HashType.BITCOIN, pytest.approx(0.99))]


class TestEthereum:
    def test_ethereum_identified(self) -> None:
        h = "$ethereum$p*1024*aabbccdd"
        results = identify_hash(h)
        assert results == [(HashType.ETHEREUM, pytest.approx(0.99))]


class TestCiscoType8:
    def test_cisco_type8_identified(self) -> None:
        h = "$8$salt$hash_data_here"
        results = identify_hash(h)
        assert results == [(HashType.CISCO_TYPE8, pytest.approx(0.99))]


class TestCiscoType9:
    def test_cisco_type9_identified(self) -> None:
        h = "$9$salt$hash_data_here"
        results = identify_hash(h)
        assert results == [(HashType.CISCO_TYPE9, pytest.approx(0.99))]


class TestMacOSPBKDF2:
    def test_macos_pbkdf2_identified(self) -> None:
        h = "$ml$32000$aabbccddee$ff00112233"
        results = identify_hash(h)
        assert results == [(HashType.MACOS_PBKDF2, pytest.approx(0.95))]


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
