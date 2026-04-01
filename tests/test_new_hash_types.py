"""Tests for new hash type support — Unix crypt, phpass, Django, MySQL, MSSQL."""

from __future__ import annotations

from smartcrack.hash_id import identify_hash
from smartcrack.hashers import verify
from smartcrack.models import HashTarget, HashType


# ---------------------------------------------------------------------------
# Hash identifier — prefix detection
# ---------------------------------------------------------------------------


class TestHashIdPrefixes:
    def test_sha512crypt(self) -> None:
        h = "$6$rounds=5000$salt$hash"
        results = identify_hash(h)
        assert results[0][0] == HashType.SHA512CRYPT

    def test_sha256crypt(self) -> None:
        h = "$5$rounds=5000$salt$hash"
        results = identify_hash(h)
        assert results[0][0] == HashType.SHA256CRYPT

    def test_md5crypt(self) -> None:
        h = "$1$salt$hash"
        results = identify_hash(h)
        assert results[0][0] == HashType.MD5CRYPT

    def test_yescrypt(self) -> None:
        h = "$y$j9T$salt$hash"
        results = identify_hash(h)
        assert results[0][0] == HashType.YESCRYPT

    def test_phpass_wordpress(self) -> None:
        h = "$P$B9xv18PXFDqXIrNOiRkHpNdyInuUbi1"
        results = identify_hash(h)
        assert results[0][0] == HashType.PHPASS

    def test_phpass_phpbb(self) -> None:
        h = "$H$9V1cBfLAqAf9E3XKK/1K9F9j8D.Y2e1"
        results = identify_hash(h)
        assert results[0][0] == HashType.PHPASS

    def test_drupal7(self) -> None:
        h = "$S$C33783772bRXEx1aCsvY.dqgaaSu76XmVlKrW9Qu8IQlvxHlmzLf"
        results = identify_hash(h)
        assert results[0][0] == HashType.DRUPAL7

    def test_django_pbkdf2(self) -> None:
        h = "pbkdf2_sha256$260000$salt$hash"
        results = identify_hash(h)
        assert results[0][0] == HashType.DJANGO_PBKDF2

    def test_kerberos_tgs(self) -> None:
        h = "$krb5tgs$23$*user$DOMAIN$http/server$*ticket"
        results = identify_hash(h)
        assert results[0][0] == HashType.KERBEROS_TGS

    def test_kerberos_asrep(self) -> None:
        h = "$krb5asrep$23$user@DOMAIN:hash"
        results = identify_hash(h)
        assert results[0][0] == HashType.KERBEROS_ASREP

    def test_dcc2(self) -> None:
        h = "$DCC2$10240#bjones#e4e938d12fe5974dc42a90120bd9c90"
        results = identify_hash(h)
        assert results[0][0] == HashType.DCC2

    def test_mysql41(self) -> None:
        h = "*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"
        results = identify_hash(h)
        assert results[0][0] == HashType.MYSQL41

    def test_mssql2012(self) -> None:
        h = "0x0200F733058A07892C5CECE899"
        results = identify_hash(h)
        assert results[0][0] == HashType.MSSQL2012

    def test_netntlmv2(self) -> None:
        h = "admin::N46iSNekpT:08ca45b7:88dcbe44:0100000000"
        results = identify_hash(h)
        assert results[0][0] == HashType.NETNTLMV2

    def test_ldap_ssha(self) -> None:
        h = "{SSHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="
        results = identify_hash(h)
        assert results[0][0] == HashType.LDAP_SSHA

    def test_scrypt_prefix(self) -> None:
        h = "SCRYPT:1024:1:1:c2FsdA==:aGFzaA=="
        results = identify_hash(h)
        assert results[0][0] == HashType.SCRYPT

    def test_md5_still_works(self) -> None:
        h = "5f4dcc3b5aa765d61d8327deb882cf99"
        results = identify_hash(h)
        assert results[0][0] == HashType.MD5

    def test_bcrypt_still_works(self) -> None:
        h = "$2b$12$WApznUPhDubN0oeveSXHp.hkCKJoq5bCFOyB3HkUh3KKRYB/fGMm"
        results = identify_hash(h)
        assert results[0][0] == HashType.BCRYPT


# ---------------------------------------------------------------------------
# Hash verification — actual cracking
# ---------------------------------------------------------------------------


class TestVerifyMd5Crypt:
    def test_verify_correct(self) -> None:
        from passlib.hash import md5_crypt
        h = md5_crypt.hash("password")
        target = HashTarget(hash_value=h, hash_type=HashType.MD5CRYPT)
        assert verify("password", target) is True

    def test_verify_wrong(self) -> None:
        from passlib.hash import md5_crypt
        h = md5_crypt.hash("password")
        target = HashTarget(hash_value=h, hash_type=HashType.MD5CRYPT)
        assert verify("wrong", target) is False


class TestVerifySha256Crypt:
    def test_verify_correct(self) -> None:
        from passlib.hash import sha256_crypt
        h = sha256_crypt.hash("password")
        target = HashTarget(hash_value=h, hash_type=HashType.SHA256CRYPT)
        assert verify("password", target) is True

    def test_verify_wrong(self) -> None:
        from passlib.hash import sha256_crypt
        h = sha256_crypt.hash("password")
        target = HashTarget(hash_value=h, hash_type=HashType.SHA256CRYPT)
        assert verify("wrong", target) is False


class TestVerifySha512Crypt:
    def test_verify_correct(self) -> None:
        from passlib.hash import sha512_crypt
        h = sha512_crypt.hash("password")
        target = HashTarget(hash_value=h, hash_type=HashType.SHA512CRYPT)
        assert verify("password", target) is True

    def test_verify_wrong(self) -> None:
        from passlib.hash import sha512_crypt
        h = sha512_crypt.hash("password")
        target = HashTarget(hash_value=h, hash_type=HashType.SHA512CRYPT)
        assert verify("wrong", target) is False


class TestVerifyPhpass:
    def test_verify_correct(self) -> None:
        from passlib.hash import phpass
        h = phpass.hash("password")
        target = HashTarget(hash_value=h, hash_type=HashType.PHPASS)
        assert verify("password", target) is True

    def test_verify_wrong(self) -> None:
        from passlib.hash import phpass
        h = phpass.hash("password")
        target = HashTarget(hash_value=h, hash_type=HashType.PHPASS)
        assert verify("wrong", target) is False


class TestVerifyMySQL41:
    def test_verify_correct(self) -> None:
        import hashlib
        pw = "password"
        step1 = hashlib.sha1(pw.encode()).digest()
        step2 = hashlib.sha1(step1).hexdigest().upper()
        h = f"*{step2}"
        target = HashTarget(hash_value=h, hash_type=HashType.MYSQL41)
        assert verify("password", target) is True

    def test_verify_wrong(self) -> None:
        import hashlib
        pw = "password"
        step1 = hashlib.sha1(pw.encode()).digest()
        step2 = hashlib.sha1(step1).hexdigest().upper()
        h = f"*{step2}"
        target = HashTarget(hash_value=h, hash_type=HashType.MYSQL41)
        assert verify("wrong", target) is False


class TestVerifyDjangoPbkdf2:
    def test_verify_correct(self) -> None:
        import base64
        import hashlib
        salt = "testsalt"
        iterations = 260000
        dk = hashlib.pbkdf2_hmac("sha256", b"password", salt.encode(), iterations)
        encoded = base64.b64encode(dk).decode("ascii")
        h = f"pbkdf2_sha256${iterations}${salt}${encoded}"
        target = HashTarget(hash_value=h, hash_type=HashType.DJANGO_PBKDF2)
        assert verify("password", target) is True

    def test_verify_wrong(self) -> None:
        import base64
        import hashlib
        salt = "testsalt"
        iterations = 260000
        dk = hashlib.pbkdf2_hmac("sha256", b"password", salt.encode(), iterations)
        encoded = base64.b64encode(dk).decode("ascii")
        h = f"pbkdf2_sha256${iterations}${salt}${encoded}"
        target = HashTarget(hash_value=h, hash_type=HashType.DJANGO_PBKDF2)
        assert verify("wrong", target) is False


# ---------------------------------------------------------------------------
# Adaptive batch sizing
# ---------------------------------------------------------------------------


class TestAdaptiveBatchSize:
    def test_fast_hash_large_batch(self) -> None:
        from smartcrack.cracker import recommended_batch_size
        assert recommended_batch_size(HashType.MD5) >= 50_000
        assert recommended_batch_size(HashType.NTLM) >= 50_000

    def test_medium_hash_medium_batch(self) -> None:
        from smartcrack.cracker import recommended_batch_size
        assert 1_000 <= recommended_batch_size(HashType.SHA512CRYPT) <= 10_000
        assert 1_000 <= recommended_batch_size(HashType.PHPASS) <= 10_000

    def test_slow_hash_small_batch(self) -> None:
        from smartcrack.cracker import recommended_batch_size
        assert recommended_batch_size(HashType.BCRYPT) <= 1_000
        assert recommended_batch_size(HashType.DCC2) <= 1_000

    def test_memory_hard_tiny_batch(self) -> None:
        from smartcrack.cracker import recommended_batch_size
        assert recommended_batch_size(HashType.ARGON2) <= 100
        assert recommended_batch_size(HashType.YESCRYPT) <= 100

    def test_memory_hard_few_workers(self) -> None:
        from smartcrack.cracker import recommended_max_workers
        workers = recommended_max_workers(HashType.ARGON2)
        assert workers is not None and workers <= 2

    def test_fast_hash_all_workers(self) -> None:
        from smartcrack.cracker import recommended_max_workers
        assert recommended_max_workers(HashType.MD5) is None  # None = all cores


# ---------------------------------------------------------------------------
# Phase 3+4 hash identifier — prefix detection
# ---------------------------------------------------------------------------


class TestPhase3Identification:
    def test_lm_hash_16_hex(self) -> None:
        h = "299bd128c1101fd6"
        results = identify_hash(h)
        assert results[0][0] == HashType.LM

    def test_oracle11g(self) -> None:
        h = "S:2BFCFDF5895369EE10B03217ABCDEF1234567890AABB"
        results = identify_hash(h)
        assert results[0][0] == HashType.ORACLE11G

    def test_postgres_md5(self) -> None:
        import hashlib
        h = "md5" + hashlib.md5(b"passworduser").hexdigest()
        results = identify_hash(h)
        assert results[0][0] == HashType.POSTGRES_MD5

    def test_netntlmv1(self) -> None:
        # NetNTLMv1: user::hostname:lm_response:nt_response (4 colons, not 5+)
        h = "user::hostname:lmresp:ntresp"
        results = identify_hash(h)
        assert results[0][0] == HashType.NETNTLMV1

    def test_postgres_scram(self) -> None:
        h = "SCRAM-SHA-256$4096:salt$storedkey:serverkey"
        results = identify_hash(h)
        assert results[0][0] == HashType.POSTGRES_SCRAM


class TestPhase4Identification:
    def test_keepass(self) -> None:
        h = "$keepass$*2*6000*hash"
        results = identify_hash(h)
        assert results[0][0] == HashType.KEEPASS

    def test_wpa2_pmkid(self) -> None:
        h = "WPA*01*4d4fe7aac3a2cecab195321ceb99a7d0*fc690c158264"
        results = identify_hash(h)
        assert results[0][0] == HashType.WPA2_PMKID

    def test_ms_office(self) -> None:
        h = "$office$*2013*100000*256*hash"
        results = identify_hash(h)
        assert results[0][0] == HashType.MS_OFFICE

    def test_pdf(self) -> None:
        h = "$pdf$4*4*128*hash"
        results = identify_hash(h)
        assert results[0][0] == HashType.PDF

    def test_rar5(self) -> None:
        h = "$RAR5$*0*salt*hash"
        results = identify_hash(h)
        assert results[0][0] == HashType.RAR5

    def test_sevenzip(self) -> None:
        h = "$7z$0$19$0$hash"
        results = identify_hash(h)
        assert results[0][0] == HashType.SEVENZIP

    def test_bitcoin(self) -> None:
        h = "$bitcoin$96$hash"
        results = identify_hash(h)
        assert results[0][0] == HashType.BITCOIN

    def test_ethereum(self) -> None:
        h = "$ethereum$p*262144*hash"
        results = identify_hash(h)
        assert results[0][0] == HashType.ETHEREUM

    def test_cisco_type8(self) -> None:
        h = "$8$TnGX/fE4KGHOVU$hash"
        results = identify_hash(h)
        assert results[0][0] == HashType.CISCO_TYPE8

    def test_cisco_type9(self) -> None:
        h = "$9$hash"
        results = identify_hash(h)
        assert results[0][0] == HashType.CISCO_TYPE9


# ---------------------------------------------------------------------------
# Phase 3 verification
# ---------------------------------------------------------------------------


class TestVerifyPostgresMd5:
    def test_verify_correct(self) -> None:
        import hashlib
        username = "testuser"
        h = "md5" + hashlib.md5(("password" + username).encode()).hexdigest()
        target = HashTarget(hash_value=h, hash_type=HashType.POSTGRES_MD5, salt=username)
        assert verify("password", target) is True

    def test_verify_wrong(self) -> None:
        import hashlib
        username = "testuser"
        h = "md5" + hashlib.md5(("password" + username).encode()).hexdigest()
        target = HashTarget(hash_value=h, hash_type=HashType.POSTGRES_MD5, salt=username)
        assert verify("wrong", target) is False


# ---------------------------------------------------------------------------
# Phase 3+4 adaptive batch sizing
# ---------------------------------------------------------------------------


class TestPhase34BatchSizing:
    def test_phase3_fast_types(self) -> None:
        from smartcrack.cracker import recommended_batch_size
        assert recommended_batch_size(HashType.LM) >= 50_000
        assert recommended_batch_size(HashType.POSTGRES_MD5) >= 50_000

    def test_phase4_slow_types(self) -> None:
        from smartcrack.cracker import recommended_batch_size
        assert recommended_batch_size(HashType.KEEPASS) <= 1_000
        assert recommended_batch_size(HashType.MS_OFFICE) <= 1_000
        assert recommended_batch_size(HashType.BITCOIN) <= 1_000

    def test_cisco_type9_memory_hard(self) -> None:
        from smartcrack.cracker import recommended_batch_size, recommended_max_workers
        assert recommended_batch_size(HashType.CISCO_TYPE9) <= 100
        workers = recommended_max_workers(HashType.CISCO_TYPE9)
        assert workers is not None and workers <= 2


# ---------------------------------------------------------------------------
# Hashcat mode mapping completeness
# ---------------------------------------------------------------------------


class TestHashcatModesComplete:
    def test_all_phase3_modes(self) -> None:
        from smartcrack.hashcat_compat import resolve_hashcat_mode
        assert resolve_hashcat_mode(3000) == HashType.LM
        assert resolve_hashcat_mode(5500) == HashType.NETNTLMV1
        assert resolve_hashcat_mode(1100) == HashType.DCC1
        assert resolve_hashcat_mode(112) == HashType.ORACLE11G
        assert resolve_hashcat_mode(12) == HashType.POSTGRES_MD5

    def test_all_phase4_modes(self) -> None:
        from smartcrack.hashcat_compat import resolve_hashcat_mode
        assert resolve_hashcat_mode(13400) == HashType.KEEPASS
        assert resolve_hashcat_mode(22000) == HashType.WPA2_PMKID
        assert resolve_hashcat_mode(9600) == HashType.MS_OFFICE
        assert resolve_hashcat_mode(13000) == HashType.RAR5
        assert resolve_hashcat_mode(11300) == HashType.BITCOIN
        assert resolve_hashcat_mode(9200) == HashType.CISCO_TYPE8
        assert resolve_hashcat_mode(9300) == HashType.CISCO_TYPE9


# ---------------------------------------------------------------------------
# Additional verify tests — all newly implemented algorithms
# ---------------------------------------------------------------------------


class TestVerifyLdapSsha:
    def test_verify_correct(self) -> None:
        from passlib.hash import ldap_salted_sha1
        h = ldap_salted_sha1.hash("password")
        target = HashTarget(hash_value=h, hash_type=HashType.LDAP_SSHA)
        assert verify("password", target) is True

    def test_verify_wrong(self) -> None:
        from passlib.hash import ldap_salted_sha1
        h = ldap_salted_sha1.hash("password")
        target = HashTarget(hash_value=h, hash_type=HashType.LDAP_SSHA)
        assert verify("wrong", target) is False


class TestVerifyDcc2:
    def test_verify_correct(self) -> None:
        from passlib.hash import msdcc2
        h = msdcc2.hash("password", user="admin")
        target = HashTarget(hash_value=h, hash_type=HashType.DCC2, salt="admin")
        assert verify("password", target) is True

    def test_verify_wrong(self) -> None:
        from passlib.hash import msdcc2
        h = msdcc2.hash("password", user="admin")
        target = HashTarget(hash_value=h, hash_type=HashType.DCC2, salt="admin")
        assert verify("wrong", target) is False


class TestVerifyOracle11g:
    def test_verify_correct(self) -> None:
        from passlib.hash import oracle11
        h = oracle11.hash("password")
        target = HashTarget(hash_value=h, hash_type=HashType.ORACLE11G)
        assert verify("password", target) is True

    def test_verify_wrong(self) -> None:
        from passlib.hash import oracle11
        h = oracle11.hash("password")
        target = HashTarget(hash_value=h, hash_type=HashType.ORACLE11G)
        assert verify("wrong", target) is False


class TestVerifyScrypt:
    def test_verify_correct(self) -> None:
        from passlib.hash import scrypt
        h = scrypt.using(rounds=4).hash("password")
        target = HashTarget(hash_value=h, hash_type=HashType.SCRYPT)
        assert verify("password", target) is True

    def test_verify_wrong(self) -> None:
        from passlib.hash import scrypt
        h = scrypt.using(rounds=4).hash("password")
        target = HashTarget(hash_value=h, hash_type=HashType.SCRYPT)
        assert verify("wrong", target) is False


class TestVerifyDrupal7:
    def test_verify_correct(self) -> None:
        from smartcrack.hashers import _verify_drupal7
        # Generate a Drupal7 hash manually
        import hashlib as _hl
        _ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        from smartcrack.hashers import _drupal7_base64_encode
        salt = "abcdefgh"
        cost_char = "C"  # 2^10 = 1024 iterations
        iterations = 1 << _ITOA64.index(cost_char)
        digest = _hl.sha512((salt + "password").encode("utf-8")).digest()
        for _ in range(iterations):
            digest = _hl.sha512(digest + "password".encode("utf-8")).digest()
        encoded = _drupal7_base64_encode(digest)
        h = f"$S${cost_char}{salt}{encoded[:43]}"
        assert _verify_drupal7("password", h) is True
        assert _verify_drupal7("wrong", h) is False


class TestVerifyLm:
    def test_verify_correct(self) -> None:
        from passlib.hash import lmhash
        h = lmhash.hash("PASSWORD")
        target = HashTarget(hash_value=h, hash_type=HashType.LM)
        assert verify("PASSWORD", target) is True

    def test_verify_wrong(self) -> None:
        from passlib.hash import lmhash
        h = lmhash.hash("PASSWORD")
        target = HashTarget(hash_value=h, hash_type=HashType.LM)
        assert verify("WRONG", target) is False


# ---------------------------------------------------------------------------
# Cisco, macOS, WPA2, SCRAM, NetNTLMv2 verifiers
# ---------------------------------------------------------------------------


class TestVerifyCiscoType8:
    def test_verify_correct(self) -> None:
        import hashlib
        import base64
        salt = "TnGX/fE4KGHOVU"
        dk = hashlib.pbkdf2_hmac("sha256", b"password", salt.encode(), 20000, dklen=32)
        encoded = base64.b64encode(dk).decode().rstrip("=")
        h = f"$8${salt}${encoded}"
        target = HashTarget(hash_value=h, hash_type=HashType.CISCO_TYPE8)
        assert verify("password", target) is True

    def test_verify_wrong(self) -> None:
        import hashlib
        import base64
        salt = "TnGX/fE4KGHOVU"
        dk = hashlib.pbkdf2_hmac("sha256", b"password", salt.encode(), 20000, dklen=32)
        encoded = base64.b64encode(dk).decode().rstrip("=")
        h = f"$8${salt}${encoded}"
        target = HashTarget(hash_value=h, hash_type=HashType.CISCO_TYPE8)
        assert verify("wrong", target) is False


class TestVerifyCiscoType9:
    def test_verify_correct(self) -> None:
        import hashlib
        import base64
        salt = "jhSb2e"
        dk = hashlib.scrypt(b"password", salt=salt.encode(), n=16384, r=1, p=1, dklen=32)
        encoded = base64.b64encode(dk).decode().rstrip("=")
        h = f"$9${salt}${encoded}"
        target = HashTarget(hash_value=h, hash_type=HashType.CISCO_TYPE9)
        assert verify("password", target) is True

    def test_verify_wrong(self) -> None:
        import hashlib
        import base64
        salt = "jhSb2e"
        dk = hashlib.scrypt(b"password", salt=salt.encode(), n=16384, r=1, p=1, dklen=32)
        encoded = base64.b64encode(dk).decode().rstrip("=")
        h = f"$9${salt}${encoded}"
        target = HashTarget(hash_value=h, hash_type=HashType.CISCO_TYPE9)
        assert verify("wrong", target) is False


class TestVerifyPostgresScram:
    def test_verify_correct(self) -> None:
        import hashlib
        import hmac as _hmac
        import base64
        salt = b"somesalt1234"
        iterations = 4096
        salted_pw = hashlib.pbkdf2_hmac("sha256", b"password", salt, iterations, dklen=32)
        client_key = _hmac.new(salted_pw, b"Client Key", hashlib.sha256).digest()
        stored_key = hashlib.sha256(client_key).digest()
        server_key = _hmac.new(salted_pw, b"Server Key", hashlib.sha256).digest()
        h = f"SCRAM-SHA-256${iterations}:{base64.b64encode(salt).decode()}${base64.b64encode(stored_key).decode()}:{base64.b64encode(server_key).decode()}"
        target = HashTarget(hash_value=h, hash_type=HashType.POSTGRES_SCRAM)
        assert verify("password", target) is True

    def test_verify_wrong(self) -> None:
        import hashlib
        import hmac as _hmac
        import base64
        salt = b"somesalt1234"
        iterations = 4096
        salted_pw = hashlib.pbkdf2_hmac("sha256", b"password", salt, iterations, dklen=32)
        client_key = _hmac.new(salted_pw, b"Client Key", hashlib.sha256).digest()
        stored_key = hashlib.sha256(client_key).digest()
        server_key = _hmac.new(salted_pw, b"Server Key", hashlib.sha256).digest()
        h = f"SCRAM-SHA-256${iterations}:{base64.b64encode(salt).decode()}${base64.b64encode(stored_key).decode()}:{base64.b64encode(server_key).decode()}"
        target = HashTarget(hash_value=h, hash_type=HashType.POSTGRES_SCRAM)
        assert verify("wrong", target) is False


class TestVerifyMacosPbkdf2:
    def test_verify_correct(self) -> None:
        import hashlib
        import binascii
        salt = binascii.unhexlify("aabbccdd11223344")
        iterations = 1000
        dk = hashlib.pbkdf2_hmac("sha512", b"password", salt, iterations, dklen=64)
        h = f"$ml${iterations}${salt.hex()}${dk.hex()}"
        target = HashTarget(hash_value=h, hash_type=HashType.MACOS_PBKDF2)
        assert verify("password", target) is True

    def test_verify_wrong(self) -> None:
        import hashlib
        import binascii
        salt = binascii.unhexlify("aabbccdd11223344")
        iterations = 1000
        dk = hashlib.pbkdf2_hmac("sha512", b"password", salt, iterations, dklen=64)
        h = f"$ml${iterations}${salt.hex()}${dk.hex()}"
        target = HashTarget(hash_value=h, hash_type=HashType.MACOS_PBKDF2)
        assert verify("wrong", target) is False


# ---------------------------------------------------------------------------
# Stub types (identify-only, delegate to hashcat)
# ---------------------------------------------------------------------------


class TestContainerTypes:
    """Container format verifiers — real implementations, not stubs."""

    def test_rar5_verify(self) -> None:
        """RAR5: PBKDF2-SHA256 + XOR-fold check."""
        from smartcrack.hashers import _verify_rar5
        import hashlib
        salt = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
        lg2cnt = 15  # 2^15 = 32768 iterations
        base_count = 1 << lg2cnt
        pw = "password".encode("utf-8")
        v2 = hashlib.pbkdf2_hmac("sha256", pw, salt, base_count + 32, dklen=32)
        pswcheck = bytearray(8)
        for i in range(32):
            pswcheck[i % 8] ^= v2[i]
        # rar2john format: $RAR5$*type*salt*lg2cnt*iv*pswcheck
        h = f"$RAR5$*0*{salt.hex()}*{lg2cnt}*{'00' * 16}*{bytes(pswcheck).hex()}"
        assert _verify_rar5("password", h) is True
        assert _verify_rar5("wrong", h) is False

    def test_ethereum_pbkdf2_verify(self) -> None:
        """Ethereum PBKDF2: key derivation + Keccak-256 MAC."""
        import hashlib
        from Crypto.Hash import keccak as _keccak
        salt = b"ethereum_salt_32_bytes_for_test!!"
        c = 1000  # Low for test speed
        pw = "password".encode("utf-8")
        dk = hashlib.pbkdf2_hmac("sha256", pw, salt, c, dklen=32)
        # Fake ciphertext
        ciphertext = b"\xaa" * 32
        mac_input = dk[16:32] + ciphertext
        k = _keccak.new(digest_bits=256)
        k.update(mac_input)
        mac = k.digest()
        h = f"$ethereum$p*{c}*{salt.hex()}*{ciphertext.hex()}*{mac.hex()}"
        target = HashTarget(hash_value=h, hash_type=HashType.ETHEREUM)
        assert verify("password", target) is True
        assert verify("wrong", target) is False

    def test_pdf_r5_verify(self) -> None:
        """PDF R5: SHA-256(password + validation_salt) == U[:32]."""
        import hashlib
        from smartcrack.hashers import _verify_pdf
        validation_salt = b"valsalt8"  # 8 bytes
        key_salt = b"keysalt8"  # 8 bytes
        pw = "password".encode("utf-8")
        u_hash = hashlib.sha256(pw + validation_salt).digest()
        u_entry = u_hash + validation_salt + key_salt  # 48 bytes
        # Format: V*R*bits*P*enc_meta*id_len*id_hex*u_len*u_hex*o_len*o_hex
        h = f"$pdf$5*5*256*0*0*0*00*48*{u_entry.hex()}*48*{'00' * 48}"
        assert _verify_pdf("password", h) is True
        assert _verify_pdf("wrong", h) is False

    def test_malformed_hashes_dont_crash(self) -> None:
        """All verifiers return False on garbage, never crash."""
        for ht in HashType:
            if ht == HashType.UNKNOWN:
                continue
            target = HashTarget(hash_value="garbage", hash_type=ht)
            assert verify("password", target) is False


# ---------------------------------------------------------------------------
# Fill all remaining gaps — every type must have correct+reject test
# ---------------------------------------------------------------------------


class TestVerifyBitcoin:
    def test_correct(self) -> None:
        import hashlib
        from Crypto.Cipher import AES
        salt = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        rounds = 10
        d = hashlib.sha512(b"password" + salt).digest()
        for _ in range(rounds - 1):
            d = hashlib.sha512(d).digest()
        key = d[:32]
        master_key = b"\xaa" * 32
        padded = master_key + (b"\x10" * 16)
        iv = b"\x00" * 16
        enc = AES.new(key, AES.MODE_CBC, iv).encrypt(padded)
        h = f"$bitcoin$48*{enc.hex()}*8*{salt.hex()}*{rounds}*0"
        assert verify("password", HashTarget(hash_value=h, hash_type=HashType.BITCOIN)) is True

    def test_wrong(self) -> None:
        import hashlib
        from Crypto.Cipher import AES
        salt = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        rounds = 10
        d = hashlib.sha512(b"password" + salt).digest()
        for _ in range(rounds - 1):
            d = hashlib.sha512(d).digest()
        key = d[:32]
        master_key = b"\xaa" * 32
        padded = master_key + (b"\x10" * 16)
        iv = b"\x00" * 16
        enc = AES.new(key, AES.MODE_CBC, iv).encrypt(padded)
        h = f"$bitcoin$48*{enc.hex()}*8*{salt.hex()}*{rounds}*0"
        assert verify("wrong", HashTarget(hash_value=h, hash_type=HashType.BITCOIN)) is False


class TestVerifySevenzip:
    def test_correct(self) -> None:
        import hashlib
        import struct
        import zlib
        from Crypto.Cipher import AES
        cost = 5
        pw_utf16 = "password".encode("utf-16-le")
        ctx = hashlib.sha256()
        for i in range(1 << cost):
            ctx.update(pw_utf16)
            ctx.update(struct.pack("<Q", i))
        key = ctx.digest()
        test_data = b"Hello World 7-Zip test data!!"
        dec_len = len(test_data)
        crc = zlib.crc32(test_data) & 0xFFFFFFFF
        padded = test_data + b"\x00" * (32 - len(test_data))
        iv = b"\x00" * 16
        enc = AES.new(key, AES.MODE_CBC, iv).encrypt(padded)
        h = f"$7z$0${cost}$0$$16${iv.hex()}${crc}${len(enc)}${dec_len}${enc.hex()}"
        assert verify("password", HashTarget(hash_value=h, hash_type=HashType.SEVENZIP)) is True

    def test_wrong(self) -> None:
        import hashlib
        import struct
        import zlib
        from Crypto.Cipher import AES
        cost = 5
        pw_utf16 = "password".encode("utf-16-le")
        ctx = hashlib.sha256()
        for i in range(1 << cost):
            ctx.update(pw_utf16)
            ctx.update(struct.pack("<Q", i))
        key = ctx.digest()
        test_data = b"Hello World 7-Zip test data!!"
        dec_len = len(test_data)
        crc = zlib.crc32(test_data) & 0xFFFFFFFF
        padded = test_data + b"\x00" * (32 - len(test_data))
        iv = b"\x00" * 16
        enc = AES.new(key, AES.MODE_CBC, iv).encrypt(padded)
        h = f"$7z$0${cost}$0$$16${iv.hex()}${crc}${len(enc)}${dec_len}${enc.hex()}"
        assert verify("wrong", HashTarget(hash_value=h, hash_type=HashType.SEVENZIP)) is False


class TestVerifyNtlmv2:
    def _make_hash(self, pw: str) -> str:
        import binascii
        import hmac as _hmac
        from smartcrack.hashers import _compute_ntlm
        u = "admin"
        d = "DOMAIN"
        sc = b"\x01" * 8
        blob = b"\xaa" * 24
        nt = binascii.unhexlify(_compute_ntlm(pw))
        rk = _hmac.new(nt, (u.upper() + d).encode("utf-16-le"), "md5").digest()
        proof = _hmac.new(rk, sc + blob, "md5").digest()
        return f"{u}::{d}:{sc.hex()}:{proof.hex()}:{blob.hex()}"

    def test_correct(self) -> None:
        h = self._make_hash("password")
        assert verify("password", HashTarget(hash_value=h, hash_type=HashType.NETNTLMV2)) is True

    def test_wrong(self) -> None:
        h = self._make_hash("password")
        assert verify("wrong", HashTarget(hash_value=h, hash_type=HashType.NETNTLMV2)) is False


class TestVerifyWpa2:
    def _make_hash(self, pw: str) -> str:
        import hashlib
        import hmac as _hmac
        essid = b"Test"
        mac_ap = b"\xaa" * 6
        mac_sta = b"\xbb" * 6
        pmk = hashlib.pbkdf2_hmac("sha1", pw.encode(), essid, 4096, dklen=32)
        pmkid = _hmac.new(pmk, b"PMK Name" + mac_ap + mac_sta, hashlib.sha1).hexdigest()[:32]
        return f"WPA*01*{pmkid}*{mac_ap.hex()}*{mac_sta.hex()}*{essid.hex()}"

    def test_correct(self) -> None:
        h = self._make_hash("password")
        assert verify("password", HashTarget(hash_value=h, hash_type=HashType.WPA2_PMKID)) is True

    def test_wrong(self) -> None:
        h = self._make_hash("password")
        assert verify("wrong", HashTarget(hash_value=h, hash_type=HashType.WPA2_PMKID)) is False


class TestVerifyKeepass:
    def _make_hash(self, pw: str) -> str:
        import hashlib
        from Crypto.Cipher import AES
        rounds = 10
        ts = b"\x01" * 32
        ms = b"\x02" * 32
        iv = b"\x03" * 16
        ck = hashlib.sha256(hashlib.sha256(pw.encode()).digest()).digest()
        t = bytearray(ck)
        c = AES.new(ts, AES.MODE_ECB)
        for _ in range(rounds):
            t[:16] = c.encrypt(bytes(t[:16]))
            t[16:] = c.encrypt(bytes(t[16:]))
        mk = hashlib.sha256(ms + hashlib.sha256(bytes(t)).digest()).digest()
        ss = b"\xde\xad" * 16
        ed = AES.new(mk, AES.MODE_CBC, iv).encrypt(ss)
        return f"$keepass$*2*{rounds}*0*{ms.hex()}*{ts.hex()}*{iv.hex()}*{ss.hex()}*{ed.hex()}"

    def test_correct(self) -> None:
        h = self._make_hash("password")
        assert verify("password", HashTarget(hash_value=h, hash_type=HashType.KEEPASS)) is True

    def test_wrong(self) -> None:
        h = self._make_hash("password")
        assert verify("wrong", HashTarget(hash_value=h, hash_type=HashType.KEEPASS)) is False


class TestVerifyMsOffice:
    def _make_hash(self, pw: str) -> str:
        import hashlib
        from Crypto.Cipher import AES
        spin = 100
        salt = b"\x04" * 16
        hh = hashlib.sha1(salt + pw.encode("utf-16-le")).digest()
        for i in range(spin):
            hh = hashlib.sha1(i.to_bytes(4, "little") + hh).digest()
        dk = hashlib.sha1(hh + b"\x00\x00\x00\x00").digest()[:16]
        vf = b"\xfe" * 16
        c = AES.new(dk, AES.MODE_ECB)
        ev = c.encrypt(vf)
        vh = hashlib.sha1(vf).digest() + b"\x00" * 12
        eh = c.encrypt(vh[:16]) + c.encrypt(vh[16:])
        return f"$office$*2007*{spin}*128*16*{salt.hex()}*{ev.hex()}*{eh.hex()}"

    def test_correct(self) -> None:
        h = self._make_hash("password")
        assert verify("password", HashTarget(hash_value=h, hash_type=HashType.MS_OFFICE)) is True

    def test_wrong(self) -> None:
        h = self._make_hash("password")
        assert verify("wrong", HashTarget(hash_value=h, hash_type=HashType.MS_OFFICE)) is False


class TestVerifyKerberosAsrep:
    def _make_hash(self, pw: str) -> str:
        import binascii
        import hmac as _hmac
        from Crypto.Cipher import ARC4
        from smartcrack.hashers import _compute_ntlm
        nt = binascii.unhexlify(_compute_ntlm(pw))
        k1 = _hmac.new(nt, b"\x08\x00\x00\x00", "md5").digest()
        ed = b"\x30" * 64
        ck = _hmac.new(k1, ed, "md5").digest()
        k3 = _hmac.new(k1, ck, "md5").digest()
        ee = ARC4.new(k3).encrypt(ed)
        return f"$krb5asrep$23$user@DOMAIN:{ck.hex()}${ee.hex()}"

    def test_correct(self) -> None:
        h = self._make_hash("password")
        assert verify("password", HashTarget(hash_value=h, hash_type=HashType.KERBEROS_ASREP)) is True

    def test_wrong(self) -> None:
        h = self._make_hash("password")
        assert verify("wrong", HashTarget(hash_value=h, hash_type=HashType.KERBEROS_ASREP)) is False


class TestVerifyKerberosTgs:
    def _make_hash(self, pw: str) -> str:
        import binascii
        import hmac as _hmac
        from Crypto.Cipher import ARC4
        from smartcrack.hashers import _compute_ntlm
        nt = binascii.unhexlify(_compute_ntlm(pw))
        k1 = _hmac.new(nt, b"\x02\x00\x00\x00", "md5").digest()
        tp = b"\x30" * 64
        tc = _hmac.new(k1, tp, "md5").digest()
        k3 = _hmac.new(k1, tc, "md5").digest()
        te = ARC4.new(k3).encrypt(tp)
        return f"$krb5tgs$23$*user$DOMAIN$http/srv$*{tc.hex()}${te.hex()}"

    def test_correct(self) -> None:
        h = self._make_hash("password")
        assert verify("password", HashTarget(hash_value=h, hash_type=HashType.KERBEROS_TGS)) is True

    def test_wrong(self) -> None:
        h = self._make_hash("password")
        assert verify("wrong", HashTarget(hash_value=h, hash_type=HashType.KERBEROS_TGS)) is False


class TestVerifyNetntlmv1:
    def _make_hash(self, pw: str) -> str:
        import binascii
        from Crypto.Cipher import DES
        from smartcrack.hashers import _compute_ntlm, _des_expand_key
        nt_hash = binascii.unhexlify(_compute_ntlm(pw))
        padded = nt_hash.ljust(21, b"\x00")
        server_challenge = b"\x11\x22\x33\x44\x55\x66\x77\x88"
        response = b""
        for i in range(3):
            key_7 = padded[i * 7:(i + 1) * 7]
            key_8 = _des_expand_key(key_7)
            cipher = DES.new(key_8, DES.MODE_ECB)
            response += cipher.encrypt(server_challenge)
        return f"user::HOST:{'00' * 24}:{response.hex()}:{server_challenge.hex()}"

    def test_correct(self) -> None:
        h = self._make_hash("password")
        assert verify("password", HashTarget(hash_value=h, hash_type=HashType.NETNTLMV1)) is True

    def test_wrong(self) -> None:
        h = self._make_hash("password")
        assert verify("wrong", HashTarget(hash_value=h, hash_type=HashType.NETNTLMV1)) is False


class TestVerifyOracle12c:
    def test_correct(self) -> None:
        import hashlib
        salt = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a"
        dk = hashlib.pbkdf2_hmac("sha512", b"password", salt, 4096, dklen=64)
        h = f"T:{salt.hex().upper()}:{dk.hex().upper()}"
        assert verify("password", HashTarget(hash_value=h, hash_type=HashType.ORACLE12C)) is True

    def test_wrong(self) -> None:
        import hashlib
        salt = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a"
        dk = hashlib.pbkdf2_hmac("sha512", b"password", salt, 4096, dklen=64)
        h = f"T:{salt.hex().upper()}:{dk.hex().upper()}"
        assert verify("wrong", HashTarget(hash_value=h, hash_type=HashType.ORACLE12C)) is False


class TestVerifyYescrypt:
    def test_correct(self) -> None:
        import hashlib
        from smartcrack.hashers import _yescrypt_b64encode
        salt = "testsalt"
        # Params j9T: '9' -> n=2^9=512, r=32, p=1
        dk = hashlib.scrypt(b"password", salt=salt.encode(), n=512, r=32, p=1, dklen=32)
        encoded = _yescrypt_b64encode(dk)
        h = f"$y$j9T${salt}${encoded}"
        assert verify("password", HashTarget(hash_value=h, hash_type=HashType.YESCRYPT)) is True

    def test_wrong(self) -> None:
        import hashlib
        from smartcrack.hashers import _yescrypt_b64encode
        salt = "testsalt"
        dk = hashlib.scrypt(b"password", salt=salt.encode(), n=512, r=32, p=1, dklen=32)
        encoded = _yescrypt_b64encode(dk)
        h = f"$y$j9T${salt}${encoded}"
        assert verify("wrong", HashTarget(hash_value=h, hash_type=HashType.YESCRYPT)) is False


class TestVerifySha224:
    def test_correct(self) -> None:
        import hashlib
        h = hashlib.sha224(b"password").hexdigest()
        assert verify("password", HashTarget(hash_value=h, hash_type=HashType.SHA224)) is True

    def test_wrong(self) -> None:
        import hashlib
        h = hashlib.sha224(b"password").hexdigest()
        assert verify("wrong", HashTarget(hash_value=h, hash_type=HashType.SHA224)) is False


class TestVerifySha384:
    def test_correct(self) -> None:
        import hashlib
        h = hashlib.sha384(b"password").hexdigest()
        assert verify("password", HashTarget(hash_value=h, hash_type=HashType.SHA384)) is True

    def test_wrong(self) -> None:
        import hashlib
        h = hashlib.sha384(b"password").hexdigest()
        assert verify("wrong", HashTarget(hash_value=h, hash_type=HashType.SHA384)) is False


class TestVerifyMssql2012:
    def test_correct(self) -> None:
        import hashlib
        salt = b"\x01\x02\x03\x04"
        pw_utf16 = "password".encode("utf-16-le")
        hash_hex = hashlib.sha512(pw_utf16 + salt).hexdigest().upper()
        h = f"0x0200{salt.hex().upper()}{hash_hex}"
        assert verify("password", HashTarget(hash_value=h, hash_type=HashType.MSSQL2012)) is True

    def test_wrong(self) -> None:
        import hashlib
        salt = b"\x01\x02\x03\x04"
        pw_utf16 = "password".encode("utf-16-le")
        hash_hex = hashlib.sha512(pw_utf16 + salt).hexdigest().upper()
        h = f"0x0200{salt.hex().upper()}{hash_hex}"
        assert verify("wrong", HashTarget(hash_value=h, hash_type=HashType.MSSQL2012)) is False


class TestVerifyDcc1:
    def test_correct(self) -> None:
        from passlib.hash import msdcc
        h = msdcc.hash("password", user="admin")
        assert verify("password", HashTarget(hash_value=h, hash_type=HashType.DCC1, salt="admin")) is True

    def test_wrong(self) -> None:
        from passlib.hash import msdcc
        h = msdcc.hash("password", user="admin")
        assert verify("wrong", HashTarget(hash_value=h, hash_type=HashType.DCC1, salt="admin")) is False
