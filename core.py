"""
ncr_cipher/core.py
Combinatorics-based symmetric encryption — NCR2 format.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import secrets
from pathlib import Path
from typing import Optional

# ── Public constants ────────────────────────────────────────────────────────
VERSION = "2.2.0"
M = 340282366920938463463374607431768211297   # 128-bit prime
_NCR_HEADER = b"NCR2"


# ── Exceptions ───────────────────────────────────────────────────────────────
class NCRError(Exception):
    """Base: wrong key or corrupted data."""


class NCRAuthError(NCRError):
    """HMAC verification failed — file may have been tampered with."""


class NCRFormatError(NCRError):
    """Not a valid NCR2 blob."""


# ── Math helpers ─────────────────────────────────────────────────────────────
def _nCr(n: int, r: int) -> int:
    """Exact binomial coefficient via math.comb (Python 3.8+)."""
    if r < 0 or r > n:
        return 0
    return math.comb(n, r)


# ── KDF ──────────────────────────────────────────────────────────────────────
def _derive(password: bytes, salt: bytes,
            N: int = 131072, r: int = 8, p: int = 1) -> tuple[int, int, bytes, bytes]:
    """
    scrypt(password, salt) → 80 bytes
      [0:8]   → n1  = (int % 2**20) + 511
      [8:16]  → n2  = (int % 2**20) + 511
      [16:48] → stream_key (32 bytes)
      [48:80] → hmac_key   (32 bytes)
    """
    raw = hashlib.scrypt(password, salt=salt, n=N, r=r, p=p, dklen=80)
    n1 = (int.from_bytes(raw[0:8],  "big") % (2 ** 20)) + 511
    n2 = (int.from_bytes(raw[8:16], "big") % (2 ** 20)) + 511
    stream_key = raw[16:48]
    hmac_key   = raw[48:80]
    return n1, n2, stream_key, hmac_key


# ── Stream salt ───────────────────────────────────────────────────────────────
def _stream_salt(stream_key: bytes, position: int) -> int:
    """S_i = HMAC-SHA256(stream_key, i) mod M"""
    idx = position.to_bytes(8, "big")
    h = hmac.new(stream_key, idx, hashlib.sha256).digest()
    return int.from_bytes(h, "big") % M


# ── Core encrypt / decrypt ────────────────────────────────────────────────────
def _encrypt_bytes(data: bytes, n1: int, n2: int,
                   stream_key: bytes, iv: bytes) -> list[int]:
    """Encrypt bytes → list of ciphertext integers."""
    c_prev = int.from_bytes(iv, "big") % M
    result = []
    for i, b in enumerate(data):
        p     = (_nCr(n1, b) + _nCr(n2, b)) % M
        s_i   = _stream_salt(stream_key, i)
        c_i   = (p + s_i + c_prev) % M
        result.append(c_i)
        c_prev = c_i
    return result


def _decrypt_bytes(blocks: list[int], n1: int, n2: int,
                   stream_key: bytes, iv: bytes) -> bytes:
    """Decrypt list of ciphertext integers → bytes."""
    c_prev = int.from_bytes(iv, "big") % M
    out = bytearray()
    for i, c_i in enumerate(blocks):
        s_i = _stream_salt(stream_key, i)
        p   = (c_i - s_i - c_prev) % M
        # Invert: find b in [0,255] such that (nCr(n1,b)+nCr(n2,b)) % M == p
        found = False
        for b in range(256):
            if (_nCr(n1, b) + _nCr(n2, b)) % M == p:
                out.append(b)
                found = True
                break
        if not found:
            raise NCRError("Decryption failed: no valid byte found (wrong key?)")
        c_prev = c_i
    return bytes(out)


# ── NCRKey ────────────────────────────────────────────────────────────────────
class NCRKey:
    """
    Holds the derived key material for NCR2 encrypt/decrypt operations.

    Create via:
        key = NCRKey.generate(b"my password")
        key = NCRKey.load("abc.key", b"my password")
    """

    def __init__(self, n1: int, n2: int, stream_key: bytes, hmac_key: bytes,
                 salt: bytes, N: int, r: int = 8, p: int = 1):
        self._n1         = n1
        self._n2         = n2
        self._stream_key = stream_key
        self._hmac_key   = hmac_key
        self._salt       = salt
        self._N          = N
        self._r          = r
        self._p          = p

    # ── Constructors ──────────────────────────────────────────────────────────
    @classmethod
    def generate(cls, password: bytes, N: int = 131072) -> "NCRKey":
        """Derive a fresh key from *password* (new random salt)."""
        salt = secrets.token_bytes(32)
        n1, n2, sk, hk = _derive(password, salt, N=N)
        return cls(n1, n2, sk, hk, salt, N)

    @classmethod
    def load(cls, path, password: bytes, N: Optional[int] = None) -> "NCRKey":
        """Load key file and derive key material from *password*."""
        path = Path(path)
        try:
            meta = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            raise NCRFormatError(f"Cannot read key file: {exc}") from exc

        if meta.get("version") != 2:
            raise NCRFormatError("Key file version mismatch (expected 2)")

        salt = bytes.fromhex(meta["salt"])
        kdf_N = N if N is not None else meta.get("N", 131072)
        r     = meta.get("r", 8)
        p     = meta.get("p", 1)
        n1, n2, sk, hk = _derive(password, salt, N=kdf_N, r=r, p=p)
        return cls(n1, n2, sk, hk, salt, kdf_N, r, p)

    def save(self, path) -> None:
        """Write key metadata (no key material) to *path*."""
        path = Path(path)
        meta = {
            "version": 2,
            "salt": self._salt.hex(),
            "N": self._N,
            "r": self._r,
            "p": self._p,
        }
        path.write_text(json.dumps(meta, indent=2))
        # chmod 600 on POSIX
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

    # ── Crypto ────────────────────────────────────────────────────────────────
    def encrypt(self, data: bytes) -> bytes:
        """Encrypt *data* → NCR2 blob (bytes)."""
        iv      = secrets.token_bytes(16)
        blocks  = _encrypt_bytes(data, self._n1, self._n2, self._stream_key, iv)
        iv_hex  = iv.hex()
        body    = "|" + ":".join(f"{b:x}" for b in blocks)
        tag     = hmac.new(self._hmac_key,
                           (iv_hex + ":" + body).encode(), hashlib.sha256).hexdigest()
        blob    = "\n".join([_NCR_HEADER.decode(), iv_hex, tag, body])
        return blob.encode()

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt NCR2 blob → original bytes."""
        try:
            text   = ciphertext.decode()
            lines  = text.split("\n")
            if len(lines) < 4:
                raise NCRFormatError("Too few lines in NCR2 blob")
            header, iv_hex, stored_tag, body = lines[0], lines[1], lines[2], lines[3]
        except UnicodeDecodeError as exc:
            raise NCRFormatError("NCR2 blob is not valid UTF-8") from exc

        if header != "NCR2":
            raise NCRFormatError(f"Bad header: {header!r}")

        # Constant-time HMAC check
        computed = hmac.new(self._hmac_key,
                            (iv_hex + ":" + body).encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(computed, stored_tag):
            raise NCRAuthError("HMAC verification failed — wrong key or tampered file")

        iv     = bytes.fromhex(iv_hex)
        raw    = body.lstrip("|")
        blocks = [int(h, 16) for h in raw.split(":")] if raw else []
        return _decrypt_bytes(blocks, self._n1, self._n2, self._stream_key, iv)

    # ── File helpers ──────────────────────────────────────────────────────────
    def encrypt_file(self, src, dst=None) -> Path:
        """Encrypt *src*; write to *dst* (default: src + '.ncr')."""
        src = Path(src)
        dst = Path(dst) if dst else src.with_suffix(src.suffix + ".ncr")
        dst.write_bytes(self.encrypt(src.read_bytes()))
        return dst

    def decrypt_file(self, src, dst=None) -> Path:
        """Decrypt *src*; write to *dst* (default: src without '.ncr')."""
        src = Path(src)
        if dst is None:
            name = src.name
            dst  = src.parent / (name[:-4] if name.endswith(".ncr") else name + ".dec")
        dst = Path(dst)
        dst.write_bytes(self.decrypt(src.read_bytes()))
        return dst

    # ── Repr ──────────────────────────────────────────────────────────────────
    def __repr__(self) -> str:
        prefix = self._salt.hex()[:8]
        return f"<NCRKey salt={prefix}… N={self._N}>"
