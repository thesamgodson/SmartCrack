"""Hash computation and verification."""

from __future__ import annotations

import hashlib
from typing import Callable

import argon2
import bcrypt as bcrypt_lib
from passlib.hash import (
    md5_crypt as _md5_crypt,
    sha256_crypt as _sha256_crypt,
    sha512_crypt as _sha512_crypt,
    phpass as _phpass,
    ldap_salted_sha1 as _ldap_ssha,
    oracle11 as _oracle11,
    msdcc2 as _msdcc2,
)

from smartcrack.models import HashTarget, HashType

HASH_FUNCTIONS: dict[HashType, Callable[[bytes], hashlib._Hash]] = {
    HashType.MD5: hashlib.md5,
    HashType.SHA1: hashlib.sha1,
    HashType.SHA224: hashlib.sha224,
    HashType.SHA256: hashlib.sha256,
    HashType.SHA384: hashlib.sha384,
    HashType.SHA512: hashlib.sha512,
}

_SPECIAL_TYPES = frozenset({
    HashType.BCRYPT, HashType.ARGON2, HashType.NTLM,
    HashType.MD5CRYPT, HashType.SHA256CRYPT, HashType.SHA512CRYPT,
    HashType.PHPASS, HashType.DJANGO_PBKDF2, HashType.MYSQL41, HashType.MSSQL2012,
    HashType.LM, HashType.NETNTLMV1, HashType.DCC1, HashType.ORACLE11G, HashType.POSTGRES_MD5,
    HashType.LDAP_SSHA, HashType.DCC2, HashType.SCRYPT, HashType.DRUPAL7, HashType.ORACLE12C,
    HashType.CISCO_TYPE8, HashType.CISCO_TYPE9, HashType.MACOS_PBKDF2, HashType.WPA2_PMKID,
    HashType.POSTGRES_SCRAM, HashType.NETNTLMV2, HashType.KERBEROS_ASREP,
    HashType.KERBEROS_TGS, HashType.KEEPASS, HashType.MS_OFFICE, HashType.PDF,
    HashType.RAR5, HashType.SEVENZIP, HashType.BITCOIN, HashType.ETHEREUM, HashType.YESCRYPT,
})


def _compute_bcrypt(plaintext: str) -> str:
    """Compute a bcrypt hash of plaintext."""
    return bcrypt_lib.hashpw(plaintext.encode("utf-8"), bcrypt_lib.gensalt()).decode("utf-8")


def _verify_bcrypt(plaintext: str, hash_value: str) -> bool:
    """Verify plaintext against a bcrypt hash."""
    try:
        return bcrypt_lib.checkpw(plaintext.encode("utf-8"), hash_value.encode("utf-8"))
    except Exception:
        return False


def _compute_argon2(plaintext: str) -> str:
    """Compute an argon2 hash of plaintext."""
    ph = argon2.PasswordHasher()
    return ph.hash(plaintext)


def _verify_argon2(plaintext: str, hash_value: str) -> bool:
    """Verify plaintext against an argon2 hash."""
    ph = argon2.PasswordHasher()
    try:
        return ph.verify(hash_value, plaintext)
    except argon2.exceptions.VerifyMismatchError:
        return False
    except Exception:
        return False


def _md4(data: bytes) -> str:
    """Pure-Python MD4 digest per RFC 1320, returned as lowercase hex string.

    MD4 is no longer available in OpenSSL 3+ (Python 3.14's hashlib),
    so we implement it directly.
    """
    import struct

    def _rol(x: int, n: int) -> int:
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    # Padding
    msg = bytearray(data)
    orig_bit_len = len(data) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0x00)
    msg += struct.pack("<Q", orig_bit_len)

    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    for off in range(0, len(msg), 64):
        X = list(struct.unpack("<16I", msg[off : off + 64]))
        aa, bb, cc, dd = a, b, c, d

        # Round 1 — F(b,c,d) = (b & c) | (~b & d)
        def R1(a: int, b: int, c: int, d: int, k: int, s: int) -> int:
            return _rol((a + ((b & c) | (~b & d)) + X[k]) & 0xFFFFFFFF, s)

        for k, s in [(0, 3), (1, 7), (2, 11), (3, 19),
                     (4, 3), (5, 7), (6, 11), (7, 19),
                     (8, 3), (9, 7), (10, 11), (11, 19),
                     (12, 3), (13, 7), (14, 11), (15, 19)]:
            a = R1(a, b, c, d, k, s)
            a, b, c, d = d, a, b, c

        # Round 2 — G(b,c,d) = (b & c) | (b & d) | (c & d)
        def R2(a: int, b: int, c: int, d: int, k: int, s: int) -> int:
            return _rol((a + ((b & c) | (b & d) | (c & d)) + X[k] + 0x5A827999) & 0xFFFFFFFF, s)

        for k, s in [(0, 3), (4, 5), (8, 9), (12, 13),
                     (1, 3), (5, 5), (9, 9), (13, 13),
                     (2, 3), (6, 5), (10, 9), (14, 13),
                     (3, 3), (7, 5), (11, 9), (15, 13)]:
            a = R2(a, b, c, d, k, s)
            a, b, c, d = d, a, b, c

        # Round 3 — H(b,c,d) = b ^ c ^ d
        def R3(a: int, b: int, c: int, d: int, k: int, s: int) -> int:
            return _rol((a + (b ^ c ^ d) + X[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s)

        for k, s in [(0, 3), (8, 9), (4, 11), (12, 15),
                     (2, 3), (10, 9), (6, 11), (14, 15),
                     (1, 3), (9, 9), (5, 11), (13, 15),
                     (3, 3), (11, 9), (7, 11), (15, 15)]:
            a = R3(a, b, c, d, k, s)
            a, b, c, d = d, a, b, c

        a = (a + aa) & 0xFFFFFFFF
        b = (b + bb) & 0xFFFFFFFF
        c = (c + cc) & 0xFFFFFFFF
        d = (d + dd) & 0xFFFFFFFF

    return struct.pack("<4I", a, b, c, d).hex()


def _compute_ntlm(plaintext: str) -> str:
    """Compute NTLM hash (MD4 of UTF-16LE encoded plaintext)."""
    return _md4(plaintext.encode("utf-16-le"))


def _verify_ntlm(plaintext: str, hash_value: str) -> bool:
    """Verify plaintext against an NTLM hash."""
    return _compute_ntlm(plaintext) == hash_value.lower()


def _verify_md5crypt(plaintext: str, hash_value: str) -> bool:
    try:
        return _md5_crypt.verify(plaintext, hash_value)
    except Exception:
        return False


def _verify_sha256crypt(plaintext: str, hash_value: str) -> bool:
    try:
        return _sha256_crypt.verify(plaintext, hash_value)
    except Exception:
        return False


def _verify_sha512crypt(plaintext: str, hash_value: str) -> bool:
    try:
        return _sha512_crypt.verify(plaintext, hash_value)
    except Exception:
        return False


def _verify_phpass(plaintext: str, hash_value: str) -> bool:
    try:
        return _phpass.verify(plaintext, hash_value)
    except Exception:
        return False


def _verify_django_pbkdf2(plaintext: str, hash_value: str) -> bool:
    """Verify Django PBKDF2-SHA256 format: pbkdf2_sha256$iterations$salt$hash."""
    try:
        import base64
        parts = hash_value.split("$")
        if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
            return False
        iterations = int(parts[1])
        salt = parts[2]
        stored_hash = parts[3]
        dk = hashlib.pbkdf2_hmac("sha256", plaintext.encode("utf-8"), salt.encode("utf-8"), iterations)
        computed = base64.b64encode(dk).decode("ascii").rstrip("=")
        stored_clean = stored_hash.rstrip("=")
        return computed == stored_clean
    except Exception:
        return False


def _verify_mysql41(plaintext: str, hash_value: str) -> bool:
    """Verify MySQL 4.1/5 hash: *SHA1(SHA1(password))."""
    try:
        clean = hash_value.lstrip("*")
        step1 = hashlib.sha1(plaintext.encode("utf-8")).digest()
        step2 = hashlib.sha1(step1).hexdigest().upper()
        return step2 == clean.upper()
    except Exception:
        return False


def _verify_mssql2012(plaintext: str, hash_value: str) -> bool:
    """Verify MSSQL 2012+ hash: 0x0200 + 4-byte-salt + SHA512(pass+salt)."""
    try:
        clean = hash_value
        if clean.lower().startswith("0x"):
            clean = clean[2:]
        if not clean.startswith("0200"):
            return False
        salt_hex = clean[4:12]
        stored_hash_hex = clean[12:]
        salt = bytes.fromhex(salt_hex)
        computed = hashlib.sha512(plaintext.encode("utf-16-le") + salt).hexdigest().upper()
        return computed == stored_hash_hex.upper()
    except Exception:
        return False


def _verify_lm(plaintext: str, hash_value: str) -> bool:
    """Verify LM hash. LM converts to uppercase, pads/truncates to 14 chars, splits into two 7-byte DES keys."""
    try:
        from passlib.hash import lmhash
        return lmhash.verify(plaintext, hash_value)
    except Exception:
        return False


def _verify_postgres_md5(plaintext: str, hash_value: str) -> bool:
    """PostgreSQL md5: 'md5' + md5(password + username). Username is in salt field."""
    try:
        if not hash_value.startswith("md5"):
            return False
        # Requires username in salt — handled by verify() dispatch
        return False
    except Exception:
        return False


def _verify_ldap_ssha(plaintext: str, hash_value: str) -> bool:
    try:
        return _ldap_ssha.verify(plaintext, hash_value)
    except Exception:
        return False


def _verify_dcc2(plaintext: str, hash_value: str, username: str = "") -> bool:
    """DCC2: mscash v2. Username is required (from salt field)."""
    try:
        return _msdcc2.verify(plaintext, hash_value, user=username)
    except Exception:
        return False


def _verify_oracle11g(plaintext: str, hash_value: str) -> bool:
    try:
        return _oracle11.verify(plaintext, hash_value)
    except Exception:
        return False


def _verify_scrypt(plaintext: str, hash_value: str) -> bool:
    """Verify scrypt hash. Supports passlib format."""
    try:
        from passlib.hash import scrypt as _passlib_scrypt
        return _passlib_scrypt.verify(plaintext, hash_value)
    except Exception:
        return False


def _verify_drupal7(plaintext: str, hash_value: str) -> bool:
    """Verify Drupal7 hash ($S$ prefix). Uses iterated SHA512."""
    try:
        if not hash_value.startswith("$S$"):
            return False
        import hashlib as _hl
        # Drupal7 phpass variant: $S$ + cost_char + 8-char-salt + hash
        # cost_char maps to iteration count via itoa64
        _ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        cost_char = hash_value[3]
        iterations = 1 << _ITOA64.index(cost_char)
        salt = hash_value[4:12]
        # Compute: iterate SHA512
        digest = _hl.sha512((salt + plaintext).encode("utf-8")).digest()
        for _ in range(iterations):
            digest = _hl.sha512(digest + plaintext.encode("utf-8")).digest()
        # Encode with custom base64
        stored_hash = hash_value[12:]
        computed = _drupal7_base64_encode(digest)
        return computed[:len(stored_hash)] == stored_hash
    except Exception:
        return False


def _drupal7_base64_encode(data: bytes) -> str:
    """Drupal7's custom base64 encoding (different from standard base64)."""
    _ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    output = ""
    count = len(data)
    i = 0
    while i < count:
        value = data[i]
        i += 1
        output += _ITOA64[value & 0x3F]
        if i < count:
            value |= data[i] << 8
        output += _ITOA64[(value >> 6) & 0x3F]
        if i >= count:
            break
        i += 1
        if i < count:
            value |= data[i] << 16
        output += _ITOA64[(value >> 12) & 0x3F]
        if i >= count:
            break
        i += 1
        output += _ITOA64[(value >> 18) & 0x3F]
    return output


def _verify_cisco_type8(plaintext: str, hash_value: str) -> bool:
    """Verify Cisco Type 8 hash: $8$salt$hash (PBKDF2-SHA256, 20000 iterations)."""
    try:
        parts = hash_value.split("$")
        if len(parts) != 4 or parts[1] != "8":
            return False
        salt = parts[2]
        stored = parts[3]
        import base64
        dk = hashlib.pbkdf2_hmac(
            "sha256", plaintext.encode("utf-8"), salt.encode("utf-8"), 20000, dklen=32
        )
        computed = base64.b64encode(dk).decode("ascii").rstrip("=")
        return computed == stored.rstrip("=")
    except Exception:
        return False


def _verify_cisco_type9(plaintext: str, hash_value: str) -> bool:
    """Verify Cisco Type 9 hash: $9$salt$hash (scrypt N=16384, r=1, p=1)."""
    try:
        parts = hash_value.split("$")
        if len(parts) != 4 or parts[1] != "9":
            return False
        salt = parts[2]
        stored = parts[3]
        import base64
        dk = hashlib.scrypt(
            plaintext.encode("utf-8"), salt=salt.encode("utf-8"), n=16384, r=1, p=1, dklen=32
        )
        computed = base64.b64encode(dk).decode("ascii").rstrip("=")
        return computed == stored.rstrip("=")
    except Exception:
        return False


def _verify_macos_pbkdf2(plaintext: str, hash_value: str) -> bool:
    """Verify macOS PBKDF2-SHA512 hash: $ml$iterations$salt_hex$hash_hex."""
    try:
        import binascii
        parts = hash_value.split("$")
        if len(parts) < 4:
            return False
        iterations = int(parts[2]) if parts[1] == "ml" else int(parts[1])
        salt_hex = parts[3] if parts[1] == "ml" else parts[2]
        stored_hex = parts[4] if len(parts) > 4 else parts[3]
        salt = binascii.unhexlify(salt_hex)
        dk = hashlib.pbkdf2_hmac(
            "sha512", plaintext.encode("utf-8"), salt, iterations,
            dklen=len(binascii.unhexlify(stored_hex)),
        )
        return dk.hex() == stored_hex.lower()
    except Exception:
        return False


def _verify_wpa2_pmkid(plaintext: str, hash_value: str) -> bool:
    """Verify WPA2 PMKID: WPA*type*pmkid*mac_ap*mac_sta*essid_hex."""
    try:
        import hmac as _hmac
        import binascii
        parts = hash_value.split("*")
        if len(parts) < 5 or parts[0] != "WPA":
            return False
        pmkid_hex = parts[2]
        mac_ap = binascii.unhexlify(parts[3])
        mac_sta = binascii.unhexlify(parts[4])
        essid = binascii.unhexlify(parts[5]) if len(parts) > 5 else b""
        pmk = hashlib.pbkdf2_hmac("sha1", plaintext.encode("utf-8"), essid, 4096, dklen=32)
        computed = _hmac.new(pmk, b"PMK Name" + mac_ap + mac_sta, hashlib.sha1).hexdigest()[:32]
        return computed == pmkid_hex.lower()
    except Exception:
        return False


def _verify_postgres_scram(plaintext: str, hash_value: str) -> bool:
    """Verify PostgreSQL SCRAM-SHA-256: SCRAM-SHA-256$iterations:salt_b64$StoredKey:ServerKey."""
    try:
        import hmac as _hmac
        import base64
        prefix, rest = hash_value.split("$", 1)
        if prefix != "SCRAM-SHA-256":
            return False
        params, keys = rest.split("$")
        iter_str, salt_b64 = params.split(":")
        iterations = int(iter_str)
        salt = base64.b64decode(salt_b64)
        stored_key_b64, _server_key_b64 = keys.split(":")
        salted_password = hashlib.pbkdf2_hmac(
            "sha256", plaintext.encode("utf-8"), salt, iterations, dklen=32
        )
        client_key = _hmac.new(salted_password, b"Client Key", hashlib.sha256).digest()
        computed_stored_key = hashlib.sha256(client_key).digest()
        return base64.b64encode(computed_stored_key).decode() == stored_key_b64
    except Exception:
        return False


def _verify_netntlmv1(plaintext: str, hash_value: str) -> bool:
    """Verify NetNTLMv1: DES-based challenge response.

    Format: user::hostname:lm_response:nt_response:server_challenge
    The nt_response is DES(NTLM_hash, server_challenge).
    """
    try:
        import binascii
        from Crypto.Cipher import DES
        parts = hash_value.split(":")
        if len(parts) < 5:
            return False
        nt_response = binascii.unhexlify(parts[4]) if len(parts[4]) >= 48 else binascii.unhexlify(parts[3])
        server_challenge = binascii.unhexlify(parts[-1]) if len(parts[-1]) == 16 else binascii.unhexlify(parts[3])
        nt_hash = binascii.unhexlify(_compute_ntlm(plaintext))
        # Pad NT hash to 21 bytes, split into 3 x 7-byte DES keys
        padded = nt_hash.ljust(21, b"\x00")
        response = b""
        for i in range(3):
            key_7 = padded[i * 7:(i + 1) * 7]
            # Expand 7-byte key to 8-byte DES key with parity bits
            key_8 = _des_expand_key(key_7)
            cipher = DES.new(key_8, DES.MODE_ECB)
            response += cipher.encrypt(server_challenge[:8])
        return response == nt_response[:24]
    except Exception:
        return False


def _des_expand_key(key_7: bytes) -> bytes:
    """Expand a 7-byte key to an 8-byte DES key with parity bits."""
    k = int.from_bytes(key_7.ljust(7, b"\x00"), "big")
    expanded = []
    for i in range(8):
        shift = 56 - i * 7
        b = ((k >> shift) & 0xFE) if shift >= 0 else ((k << -shift) & 0xFE)
        expanded.append(b)
    return bytes(expanded)


def _verify_netntlmv2(plaintext: str, hash_value: str) -> bool:
    """Verify NetNTLMv2: user::domain:server_challenge:ntproofstr:blob."""
    try:
        import hmac as _hmac
        import binascii
        parts = hash_value.split(":")
        if len(parts) < 6:
            return False
        username = parts[0]
        domain = parts[2]
        server_challenge = binascii.unhexlify(parts[3])
        nt_proof_str = binascii.unhexlify(parts[4])
        blob = binascii.unhexlify(parts[5])
        # NTHash = MD4(UTF16LE(password))
        nt_hash = bytes.fromhex(_compute_ntlm(plaintext))
        # ResponseKeyNT = HMAC-MD5(NTHash, UNICODE(upper(username) + domain))
        identity = (username.upper() + domain).encode("utf-16-le")
        response_key = _hmac.new(nt_hash, identity, "md5").digest()
        # NTProofStr = HMAC-MD5(ResponseKeyNT, server_challenge + blob)
        computed = _hmac.new(response_key, server_challenge + blob, "md5").digest()
        return computed == nt_proof_str
    except Exception:
        return False


def _verify_kerberos_asrep(plaintext: str, hash_value: str) -> bool:
    """Verify Kerberos AS-REP etype 23 (RC4-HMAC). Requires pycryptodome for RC4."""
    try:
        from Crypto.Cipher import ARC4
        import hmac as _hmac
        import binascii
        # Parse: $krb5asrep$23$user@domain:checksum$edata2
        if not hash_value.startswith("$krb5asrep$23$"):
            return False
        rest = hash_value[len("$krb5asrep$23$"):]
        _user_part, hash_part = rest.split(":", 1)
        checksum_hex = hash_part[:32]
        edata2_hex = hash_part[33:]  # skip the $ separator
        checksum = binascii.unhexlify(checksum_hex)
        edata2 = binascii.unhexlify(edata2_hex)
        # Key = NTLM hash
        nt_hash = bytes.fromhex(_compute_ntlm(plaintext))
        # K1 = HMAC-MD5(NTHash, usage_number=8 for AS-REP)
        k1 = _hmac.new(nt_hash, b"\x08\x00\x00\x00", "md5").digest()
        # K3 = HMAC-MD5(K1, checksum)
        k3 = _hmac.new(k1, checksum, "md5").digest()
        # Decrypt edata2 with RC4(K3)
        cipher = ARC4.new(k3)
        decrypted = cipher.decrypt(edata2)
        # Verify: HMAC-MD5(K1, decrypted) should equal checksum
        computed_checksum = _hmac.new(k1, decrypted, "md5").digest()
        return computed_checksum == checksum
    except Exception:
        return False


def _verify_kerberos_tgs(plaintext: str, hash_value: str) -> bool:
    """Verify Kerberos TGS-REP etype 23 (RC4-HMAC)."""
    try:
        from Crypto.Cipher import ARC4
        import hmac as _hmac
        import binascii
        # Parse: $krb5tgs$23$*user$realm$spn$*checksum$edata2
        if not hash_value.startswith("$krb5tgs$23$"):
            return False
        rest = hash_value[len("$krb5tgs$23$"):]
        # Find the hash data after the last *
        parts = rest.split("$")
        # Last two parts are checksum and edata2
        if len(parts) < 2:
            return False
        checksum_hex = parts[-2][-32:] if len(parts[-2]) >= 32 else parts[-2]
        edata2_hex = parts[-1]
        if len(checksum_hex) != 32 or len(edata2_hex) < 32:
            return False
        checksum = binascii.unhexlify(checksum_hex)
        edata2 = binascii.unhexlify(edata2_hex)
        nt_hash = binascii.unhexlify(_compute_ntlm(plaintext))
        # K1 = HMAC-MD5(NTHash, usage=2 for TGS)
        k1 = _hmac.new(nt_hash, b"\x02\x00\x00\x00", "md5").digest()
        k3 = _hmac.new(k1, checksum, "md5").digest()
        cipher = ARC4.new(k3)
        decrypted = cipher.decrypt(edata2)
        computed_checksum = _hmac.new(k1, decrypted, "md5").digest()
        return computed_checksum == checksum
    except Exception:
        return False


def _verify_keepass(plaintext: str, hash_value: str) -> bool:
    """KeePass KDBX2/3: AES-KDF composite key + AES-CBC decrypt + stream-start check."""
    try:
        import hashlib
        import binascii
        from Crypto.Cipher import AES
        parts = hash_value.split("*")
        if len(parts) < 9 or not parts[0].startswith("$keepass$"):
            return False
        # parts: [0]=$keepass$, [1]=version, [2]=rounds, [3]=algo,
        #         [4]=master_seed, [5]=transform_seed, [6]=iv, [7]=stream_start, [8]=enc_data
        rounds = int(parts[2])
        master_seed = binascii.unhexlify(parts[4])
        transform_seed = binascii.unhexlify(parts[5])
        iv = binascii.unhexlify(parts[6])
        stream_start = binascii.unhexlify(parts[7])
        enc_data = binascii.unhexlify(parts[8])
        # Composite key
        ck = hashlib.sha256(plaintext.encode("utf-8")).digest()
        ck = hashlib.sha256(ck).digest()
        # AES transform
        cipher = AES.new(transform_seed, AES.MODE_ECB)
        transformed = bytearray(ck)
        for _ in range(rounds):
            transformed[:16] = cipher.encrypt(bytes(transformed[:16]))
            transformed[16:] = cipher.encrypt(bytes(transformed[16:]))
        tk = hashlib.sha256(bytes(transformed)).digest()
        master_key = hashlib.sha256(master_seed + tk).digest()
        # Decrypt and verify
        cipher2 = AES.new(master_key, AES.MODE_CBC, iv)
        decrypted = cipher2.decrypt(enc_data)
        return decrypted[:len(stream_start)] == stream_start
    except Exception:
        return False


def _verify_ms_office(plaintext: str, hash_value: str) -> bool:
    """MS Office 2007+ uses PBKDF2-SHA1 + AES-128/256 with encrypted verifier.

    Format parsed from $office$*version*spincount*keysize*saltsize*salt*encverifier*enchash.
    """
    try:
        import binascii
        from Crypto.Cipher import AES
        parts = hash_value.split("*")
        if len(parts) < 8 or not parts[0].startswith("$office$"):
            return False
        # parts: [0]=$office$, [1]=version, [2]=spincount, [3]=keysize, [4]=saltsize,
        #         [5]=salt, [6]=enc_verifier, [7]=enc_hash
        spin_count = int(parts[2])
        salt = binascii.unhexlify(parts[5])
        enc_verifier = binascii.unhexlify(parts[6])
        enc_hash = binascii.unhexlify(parts[7])
        # PBKDF2 key derivation
        h = hashlib.sha1(salt + plaintext.encode("utf-16-le")).digest()
        for i in range(spin_count):
            h = hashlib.sha1(i.to_bytes(4, "little") + h).digest()
        derived_key = hashlib.sha1(h + b"\x00\x00\x00\x00").digest()[:16]
        # Decrypt verifier
        cipher = AES.new(derived_key, AES.MODE_ECB)
        decrypted_verifier = cipher.decrypt(enc_verifier[:16])
        decrypted_hash = cipher.decrypt(enc_hash[:32])
        # Verify
        computed_hash = hashlib.sha1(decrypted_verifier).digest()
        return computed_hash == decrypted_hash[:20]
    except Exception:
        return False


_PDF_PAD = bytes([
    0x28,0xBF,0x4E,0x5E, 0x4E,0x75,0x8A,0x41,
    0x64,0x00,0x4E,0x56, 0xFF,0xFA,0x01,0x08,
    0x2E,0x2E,0x00,0xB6, 0xD0,0x68,0x3E,0x80,
    0x2F,0x0C,0xA9,0xFE, 0x64,0x53,0x69,0x7A,
])


def _verify_pdf(plaintext: str, hash_value: str) -> bool:
    """PDF encryption verification for R2-R5."""
    try:
        import hashlib
        import binascii
        from Crypto.Cipher import ARC4
        parts = hash_value.replace("$pdf$", "").split("*")
        if len(parts) < 7:
            return False
        # Format: V*R*bits*P*enc_meta*id_len*id_hex*u_len*u_hex*o_len*o_hex
        _V, R = int(parts[0]), int(parts[1])
        key_bits = int(parts[2])
        P = int(parts[3])
        file_id = binascii.unhexlify(parts[6]) if len(parts) > 6 and parts[6] != "00" else b""
        u_entry = binascii.unhexlify(parts[8]) if len(parts) > 8 else b""
        o_entry = binascii.unhexlify(parts[10]) if len(parts) > 10 else b""
        key_len = key_bits // 8
        pw = (plaintext.encode("latin-1") + _PDF_PAD)[:32]
        p_bytes = P.to_bytes(4, "little", signed=True)
        if R == 2:
            md5_input = pw + o_entry + p_bytes + file_id
            key = hashlib.md5(md5_input).digest()[:key_len]
            computed_u = ARC4.new(key).encrypt(_PDF_PAD)
            return computed_u == u_entry[:32]
        elif R in (3, 4):
            h = hashlib.md5(pw + o_entry + p_bytes + file_id).digest()
            for _ in range(50):
                h = hashlib.md5(h[:key_len]).digest()
            key = h[:key_len]
            check = hashlib.md5(_PDF_PAD + file_id).digest()
            for i in range(20):
                xored = bytes(b ^ i for b in key)
                check = ARC4.new(xored).encrypt(check)
            return check == u_entry[:16]
        elif R >= 5:
            pw_bytes = plaintext.encode("utf-8")[:127]
            validation_salt = u_entry[32:40]
            computed = hashlib.sha256(pw_bytes + validation_salt).digest()
            return computed == u_entry[:32]
        return False
    except Exception:
        return False


def _verify_rar5(plaintext: str, hash_value: str) -> bool:
    """RAR5: three PBKDF2-SHA256 calls, XOR-fold check."""
    try:
        import hashlib
        import binascii
        cleaned = hash_value.replace("$RAR5$", "").lstrip("*")
        parts = cleaned.split("*")
        if len(parts) < 4:
            return False
        # Skip leading type field if present (single digit like "0")
        off = 1 if len(parts[0]) <= 2 and parts[0].isdigit() else 0
        salt = binascii.unhexlify(parts[off])
        lg2cnt = int(parts[off + 1])
        pswcheck_stored = binascii.unhexlify(parts[off + 3])
        base_count = 1 << lg2cnt
        pw = plaintext.encode("utf-8")
        v2 = hashlib.pbkdf2_hmac("sha256", pw, salt, base_count + 32, dklen=32)
        pswcheck = bytearray(8)
        for i in range(32):
            pswcheck[i % 8] ^= v2[i]
        return bytes(pswcheck) == pswcheck_stored[:8]
    except Exception:
        return False


def _verify_sevenzip(plaintext: str, hash_value: str) -> bool:
    """7-Zip: SHA-256 iterated key derivation + AES-256-CBC + CRC32 check."""
    try:
        import hashlib
        import struct
        import binascii
        import zlib
        from Crypto.Cipher import AES
        parts = hash_value.replace("$7z$", "").split("$")
        if len(parts) < 8:
            return False
        int(parts[0])
        cost = int(parts[1])
        salt = binascii.unhexlify(parts[3]) if int(parts[2]) > 0 else b""
        iv = binascii.unhexlify(parts[5]) if int(parts[4]) > 0 else b"\x00" * 16
        expected_crc = int(parts[6]) & 0xFFFFFFFF
        dec_len = int(parts[8]) if len(parts) > 8 else int(parts[7])
        enc_data = binascii.unhexlify(parts[9]) if len(parts) > 9 else binascii.unhexlify(parts[8])
        # Key derivation
        rounds = 1 << cost
        pw_utf16 = plaintext.encode("utf-16-le")
        ctx = hashlib.sha256()
        for i in range(rounds):
            ctx.update(salt)
            ctx.update(pw_utf16)
            ctx.update(struct.pack("<Q", i))
        key = ctx.digest()
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(enc_data)
        computed_crc = zlib.crc32(decrypted[:dec_len]) & 0xFFFFFFFF
        return computed_crc == expected_crc
    except Exception:
        return False


def _verify_bitcoin(plaintext: str, hash_value: str) -> bool:
    """Bitcoin wallet.dat: SHA-512 iterated + AES-256-CBC + PKCS7 padding check."""
    try:
        import hashlib
        import binascii
        from Crypto.Cipher import AES
        parts = hash_value.replace("$bitcoin$", "").split("*")
        if len(parts) < 4:
            return False
        enc_master = binascii.unhexlify(parts[1]) if len(parts[0]) <= 3 else binascii.unhexlify(parts[0])
        cry_salt = binascii.unhexlify(parts[3]) if len(parts) > 3 else binascii.unhexlify(parts[2])
        cry_rounds = int(parts[4]) if len(parts) > 4 else int(parts[3])
        pw = plaintext.encode("utf-8")
        d = hashlib.sha512(pw + cry_salt).digest()
        for _ in range(cry_rounds - 1):
            d = hashlib.sha512(d).digest()
        key = d[:32]
        block_iv = enc_master[-32:-16]
        last_block = enc_master[-16:]
        cipher = AES.new(key, AES.MODE_CBC, block_iv)
        decrypted = cipher.decrypt(last_block)
        pad_val = decrypted[-1]
        if pad_val < 1 or pad_val > 16:
            return False
        return decrypted[-pad_val:] == bytes([pad_val] * pad_val)
    except Exception:
        return False


def _verify_ethereum(plaintext: str, hash_value: str) -> bool:
    """Ethereum keystore: PBKDF2/scrypt + Keccak-256 MAC verification."""
    try:
        import hashlib
        import binascii
        from Crypto.Hash import keccak as _keccak
        parts = hash_value.replace("$ethereum$", "").split("*")
        if len(parts) < 5:
            return False
        kdf_type = parts[0]  # 'p' = PBKDF2, 's' = scrypt
        c = int(parts[1])
        salt = binascii.unhexlify(parts[2])
        ciphertext = binascii.unhexlify(parts[3])
        stored_mac = binascii.unhexlify(parts[4])
        pw = plaintext.encode("utf-8")
        if kdf_type == "p":
            dk = hashlib.pbkdf2_hmac("sha256", pw, salt, c, dklen=32)
        elif kdf_type == "s":
            dk = hashlib.scrypt(pw, salt=salt, n=c, r=8, p=1, dklen=32)
        else:
            return False
        mac_input = dk[16:32] + ciphertext
        k = _keccak.new(digest_bits=256)
        k.update(mac_input)
        computed_mac = k.digest()
        return computed_mac == stored_mac
    except Exception:
        return False


def _verify_yescrypt(plaintext: str, hash_value: str) -> bool:
    """Yescrypt ($y$): modern KDF used in Debian 11+, Ubuntu 22+.

    Strategy: try system crypt() first (Linux), fall back to pure-Python
    scrypt-based approximation for the common parameter set.
    """
    try:
        import crypt
        return crypt.crypt(plaintext, hash_value) == hash_value
    except ImportError:
        pass
    # Pure-Python fallback using hashlib.scrypt
    # Parse $y$params$salt$hash
    try:
        import hashlib
        if not hash_value.startswith("$y$"):
            return False
        parts = hash_value.split("$")
        if len(parts) < 5:
            return False
        # parts: ['', 'y', 'params', 'salt', 'hash']
        params = parts[2]
        salt = parts[3]
        stored_hash = parts[4]
        # Parse params: first char = flavor, remaining = cost encoding
        # Common: j9T = flavor j, N=2^11=2048, r=8, p=1 (approx)
        # The exact encoding is complex — use scrypt with reasonable defaults
        # yescrypt j flavor with default params: N=4096, r=32, p=1
        n = 4096
        r = 32
        p = 1
        if len(params) >= 2:
            # Second char encodes N: '9'=2^9=512... varies by implementation
            cost_char = params[1] if len(params) > 1 else "9"
            n_log2 = ord(cost_char) - ord("0") if cost_char.isdigit() else 11
            n = 1 << max(n_log2, 4)
        dk = hashlib.scrypt(
            plaintext.encode("utf-8"),
            salt=salt.encode("utf-8"),
            n=n, r=r, p=p, dklen=32,
        )
        # yescrypt uses a custom base64 encoding (./0-9A-Za-z)
        # Compare derived key with stored hash
        computed = _yescrypt_b64encode(dk)
        return computed[:len(stored_hash)] == stored_hash
    except Exception:
        return False


def _yescrypt_b64encode(data: bytes) -> str:
    """Encode bytes using yescrypt's custom base64 (./0-9A-Za-z)."""
    _ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    output = ""
    i = 0
    while i < len(data):
        c1 = data[i]
        i += 1
        output += _ITOA64[c1 & 0x3F]
        if i >= len(data):
            output += _ITOA64[(c1 >> 6) & 0x3F]
            break
        c2 = data[i]
        i += 1
        output += _ITOA64[((c1 >> 6) | (c2 << 2)) & 0x3F]
        if i >= len(data):
            output += _ITOA64[(c2 >> 4) & 0x3F]
            break
        c3 = data[i]
        i += 1
        output += _ITOA64[((c2 >> 4) | (c3 << 4)) & 0x3F]
        output += _ITOA64[(c3 >> 2) & 0x3F]
    return output


def _verify_oracle12c(plaintext: str, hash_value: str) -> bool:
    """Oracle 12c+: PBKDF2-SHA512 with T: prefix format.

    Format: T:salt_hex:hash_hex (from ora2john or similar tools).
    """
    try:
        import hashlib
        import binascii
        if not hash_value.upper().startswith("T:"):
            return False
        parts = hash_value.split(":")
        if len(parts) < 3:
            return False
        salt = binascii.unhexlify(parts[1])
        stored = parts[2].lower()
        dk = hashlib.pbkdf2_hmac("sha512", plaintext.encode("utf-8"), salt, 4096, dklen=64)
        return dk.hex() == stored
    except Exception:
        return False


def compute_hash(plaintext: str, hash_type: HashType, salt: str = "") -> str:
    """Compute hash of plaintext+salt for the given algorithm."""
    if hash_type == HashType.BCRYPT:
        return _compute_bcrypt(plaintext + salt)
    if hash_type == HashType.ARGON2:
        return _compute_argon2(plaintext + salt)
    if hash_type == HashType.NTLM:
        return _compute_ntlm(plaintext + salt)
    hash_fn = HASH_FUNCTIONS.get(hash_type)
    if hash_fn is None:
        raise ValueError(f"Unsupported hash type for computation: {hash_type}")
    return hash_fn((plaintext + salt).encode("utf-8")).hexdigest()


def verify(plaintext: str, target: HashTarget) -> bool:
    """Check if plaintext matches the target hash."""
    if target.hash_type == HashType.UNKNOWN:
        return False
    if target.hash_type == HashType.MD5CRYPT:
        return _verify_md5crypt(plaintext + target.salt, target.hash_value)
    if target.hash_type == HashType.SHA256CRYPT:
        return _verify_sha256crypt(plaintext + target.salt, target.hash_value)
    if target.hash_type == HashType.SHA512CRYPT:
        return _verify_sha512crypt(plaintext + target.salt, target.hash_value)
    if target.hash_type == HashType.PHPASS:
        return _verify_phpass(plaintext + target.salt, target.hash_value)
    if target.hash_type == HashType.DJANGO_PBKDF2:
        return _verify_django_pbkdf2(plaintext, target.hash_value)
    if target.hash_type == HashType.MYSQL41:
        return _verify_mysql41(plaintext + target.salt, target.hash_value)
    if target.hash_type == HashType.MSSQL2012:
        return _verify_mssql2012(plaintext, target.hash_value)
    if target.hash_type == HashType.POSTGRES_MD5:
        import hashlib as _hl
        # PostgreSQL: md5(password + username), stored as "md5" + hex
        computed = "md5" + _hl.md5((plaintext + target.salt).encode()).hexdigest()
        return computed == target.hash_value.lower()
    if target.hash_type == HashType.LM:
        return _verify_lm(plaintext, target.hash_value)
    if target.hash_type == HashType.BCRYPT:
        return _verify_bcrypt(plaintext + target.salt, target.hash_value)
    if target.hash_type == HashType.ARGON2:
        return _verify_argon2(plaintext + target.salt, target.hash_value)
    if target.hash_type == HashType.NTLM:
        return _verify_ntlm(plaintext + target.salt, target.hash_value)
    if target.hash_type == HashType.LDAP_SSHA:
        return _verify_ldap_ssha(plaintext, target.hash_value)
    if target.hash_type == HashType.DCC2:
        return _verify_dcc2(plaintext, target.hash_value, username=target.salt)
    if target.hash_type == HashType.ORACLE11G:
        return _verify_oracle11g(plaintext, target.hash_value)
    if target.hash_type == HashType.SCRYPT:
        return _verify_scrypt(plaintext, target.hash_value)
    if target.hash_type == HashType.DRUPAL7:
        return _verify_drupal7(plaintext, target.hash_value)
    if target.hash_type == HashType.CISCO_TYPE8:
        return _verify_cisco_type8(plaintext, target.hash_value)
    if target.hash_type == HashType.CISCO_TYPE9:
        return _verify_cisco_type9(plaintext, target.hash_value)
    if target.hash_type == HashType.MACOS_PBKDF2:
        return _verify_macos_pbkdf2(plaintext, target.hash_value)
    if target.hash_type == HashType.WPA2_PMKID:
        return _verify_wpa2_pmkid(plaintext, target.hash_value)
    if target.hash_type == HashType.POSTGRES_SCRAM:
        return _verify_postgres_scram(plaintext, target.hash_value)
    if target.hash_type == HashType.NETNTLMV2:
        return _verify_netntlmv2(plaintext, target.hash_value)
    if target.hash_type == HashType.KERBEROS_ASREP:
        return _verify_kerberos_asrep(plaintext, target.hash_value)
    if target.hash_type == HashType.KERBEROS_TGS:
        return _verify_kerberos_tgs(plaintext, target.hash_value)
    if target.hash_type == HashType.MS_OFFICE:
        return _verify_ms_office(plaintext, target.hash_value)
    if target.hash_type == HashType.YESCRYPT:
        return _verify_yescrypt(plaintext, target.hash_value)
    if target.hash_type in (
        HashType.KEEPASS, HashType.PDF, HashType.RAR5,
        HashType.SEVENZIP, HashType.BITCOIN, HashType.ETHEREUM,
    ):
        # Container formats — delegate to hashcat
        _container_verifiers = {
            HashType.KEEPASS: _verify_keepass,
            HashType.PDF: _verify_pdf,
            HashType.RAR5: _verify_rar5,
            HashType.SEVENZIP: _verify_sevenzip,
            HashType.BITCOIN: _verify_bitcoin,
            HashType.ETHEREUM: _verify_ethereum,
        }
        verifier = _container_verifiers.get(target.hash_type)
        return verifier(plaintext, target.hash_value) if verifier else False
    if target.hash_type == HashType.DCC1:
        try:
            from passlib.hash import msdcc
            return msdcc.verify(plaintext, target.hash_value, user=target.salt)
        except Exception:
            return False
    if target.hash_type == HashType.NETNTLMV1:
        return _verify_netntlmv1(plaintext, target.hash_value)
    if target.hash_type == HashType.ORACLE12C:
        return _verify_oracle12c(plaintext, target.hash_value)
    if target.hash_type == HashType.YESCRYPT:
        return _verify_yescrypt(plaintext, target.hash_value)
    hash_fn = HASH_FUNCTIONS.get(target.hash_type)
    if hash_fn is None:
        return False
    return hash_fn((plaintext + target.salt).encode("utf-8")).hexdigest() == target.hash_value.lower()


def verify_any(plaintext: str, target: HashTarget) -> HashType | None:
    """Try all supported hash types, return the matching one or None."""
    types_to_try = target.possible_types if target.possible_types else tuple(HASH_FUNCTIONS) + tuple(_SPECIAL_TYPES)
    salted = plaintext + target.salt
    encoded = salted.encode("utf-8")
    target_lower = target.hash_value.lower()

    for hash_type in types_to_try:
        if hash_type in _SPECIAL_TYPES:
            # Special types use their own verify logic
            temp_target = HashTarget(hash_value=target.hash_value, hash_type=hash_type, salt=target.salt)
            if verify(plaintext, temp_target):
                return hash_type
            continue
        hash_fn = HASH_FUNCTIONS.get(hash_type)
        if hash_fn is None:
            continue
        if hash_fn(encoded).hexdigest() == target_lower:
            return hash_type
    return None
