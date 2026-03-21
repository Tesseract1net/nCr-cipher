"""
tests/test_core.py — pytest suite for ncr_cipher.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from ncr_cipher import NCRKey, NCRError, NCRAuthError, NCRFormatError
from ncr_cipher.core import _derive


# ── Shared fixture (N=2**14 for speed) ───────────────────────────────────────
@pytest.fixture(scope="session")
def key():
    return NCRKey.generate(b"test-password", N=2**14)


@pytest.fixture(scope="session")
def key2():
    return NCRKey.generate(b"other-password", N=2**14)


# ── Round-trip ────────────────────────────────────────────────────────────────
def test_roundtrip_simple(key):
    plain = b"Hello, World!"
    assert key.decrypt(key.encrypt(plain)) == plain


def test_roundtrip_all_256_bytes(key):
    data = bytes(range(256))
    assert key.decrypt(key.encrypt(data)) == data


def test_roundtrip_unicode_utf8(key):
    data = "Héllo Wörld — привет 🌍".encode()
    assert key.decrypt(key.encrypt(data)) == data


def test_roundtrip_empty(key):
    assert key.decrypt(key.encrypt(b"")) == b""


def test_roundtrip_long(key):
    data = b"A" * 1024
    assert key.decrypt(key.encrypt(data)) == data


# ── CBC avalanche ─────────────────────────────────────────────────────────────
def test_cbc_avalanche(key):
    """Changing byte 6 should change all ciphertext blocks from position 6 onward."""
    plain = b"abcdefghijklmnopqrstuvwxyz"
    ct1 = key.encrypt(plain)
    # Flip a byte in the body of the ciphertext (after header/iv/hmac lines)
    lines = ct1.decode().split("\n")
    blocks = lines[3].lstrip("|").split(":")
    # Modify block at index 6
    blocks[6] = format(int(blocks[6], 16) ^ 0xFF, "x")
    lines[3] = "|" + ":".join(blocks)
    # Recompute HMAC so we get past auth (use same key internals for this test)
    import hashlib, hmac as _hmac
    iv_hex = lines[1]
    body   = lines[3]
    tag    = _hmac.new(key._hmac_key, (iv_hex + ":" + body).encode(), hashlib.sha256).hexdigest()
    lines[2] = tag
    ct2 = "\n".join(lines).encode()
    # Decryption should fail because byte 6 CBC chain is broken — or produce different output
    try:
        result = key.decrypt(ct2)
        # If it decrypts (unlikely), every byte from index 6 onward must differ
        for i in range(6, len(plain)):
            assert result[i] != plain[i], f"Byte {i} unchanged — no avalanche"
    except NCRError:
        pass  # Also acceptable: decryption fails entirely


# ── Non-determinism ───────────────────────────────────────────────────────────
def test_same_plaintext_different_ciphertext(key):
    ct1 = key.encrypt(b"same plaintext")
    ct2 = key.encrypt(b"same plaintext")
    assert ct1 != ct2, "Random IV must make each encryption unique"


# ── Auth / error paths ────────────────────────────────────────────────────────
def test_wrong_password_raises(key):
    ct  = key.encrypt(b"secret data")
    bad = NCRKey.generate(b"wrong", N=2**14)
    with pytest.raises(NCRError):
        bad.decrypt(ct)


def test_tampered_ciphertext_raises_auth_error(key):
    ct = bytearray(key.encrypt(b"secret data"))
    # Flip a bit in the HMAC line (line 2, position 10)
    lines = ct.decode().split("\n")
    hmac_line = bytearray(lines[2].encode())
    hmac_line[10] = ord("f") if hmac_line[10] != ord("f") else ord("0")
    lines[2] = hmac_line.decode()
    with pytest.raises(NCRAuthError):
        key.decrypt("\n".join(lines).encode())


def test_tampered_body_raises_auth_error(key):
    ct    = key.encrypt(b"hello")
    lines = ct.decode().split("\n")
    # Append garbage to body
    lines[3] += ":deadbeef"
    with pytest.raises(NCRAuthError):
        key.decrypt("\n".join(lines).encode())


def test_bad_format_raises_format_error(key):
    with pytest.raises(NCRFormatError):
        key.decrypt(b"GARBAGE NOT NCR2")


def test_bad_format_wrong_header(key):
    ct    = key.encrypt(b"x")
    lines = ct.decode().split("\n")
    lines[0] = "NCR1"
    with pytest.raises(NCRFormatError):
        key.decrypt("\n".join(lines).encode())


# ── Save / load round-trip ────────────────────────────────────────────────────
def test_save_load_roundtrip():
    with tempfile.TemporaryDirectory() as tmp:
        keyfile = Path(tmp) / "test.key"
        pw      = b"save-load-password"
        key1    = NCRKey.generate(pw, N=2**14)
        key1.save(keyfile)

        key2 = NCRKey.load(keyfile, pw)
        plain = b"save/load round-trip"
        ct    = key1.encrypt(plain)
        assert key2.decrypt(ct) == plain


def test_save_load_wrong_password():
    with tempfile.TemporaryDirectory() as tmp:
        keyfile = Path(tmp) / "test.key"
        key1 = NCRKey.generate(b"correct", N=2**14)
        key1.save(keyfile)
        key2 = NCRKey.load(keyfile, b"wrong", N=2**14)
        ct   = key1.encrypt(b"data")
        with pytest.raises(NCRError):
            key2.decrypt(ct)


def test_bad_keyfile_raises_format_error():
    with tempfile.TemporaryDirectory() as tmp:
        bad = Path(tmp) / "bad.key"
        bad.write_text("not json")
        with pytest.raises(NCRFormatError):
            NCRKey.load(bad, b"pw")


# ── KDF determinism and range ─────────────────────────────────────────────────
def test_kdf_deterministic():
    salt  = b"\x00" * 32
    pw    = b"determinism"
    r1    = _derive(pw, salt, N=2**14)
    r2    = _derive(pw, salt, N=2**14)
    assert r1 == r2


def test_kdf_n1_n2_valid_range():
    import secrets
    for _ in range(10):
        salt = secrets.token_bytes(32)
        n1, n2, _, _ = _derive(b"test", salt, N=2**14)
        assert 511 <= n1 < 511 + 2**20, f"n1={n1} out of range"
        assert 511 <= n2 < 511 + 2**20, f"n2={n2} out of range"


def test_kdf_different_passwords_differ():
    salt = b"\xAB" * 32
    r1 = _derive(b"alpha", salt, N=2**14)
    r2 = _derive(b"beta",  salt, N=2**14)
    assert r1 != r2


# ── File helpers ──────────────────────────────────────────────────────────────
def test_encrypt_decrypt_file(key):
    with tempfile.TemporaryDirectory() as tmp:
        src  = Path(tmp) / "plain.bin"
        data = bytes(range(256)) * 4
        src.write_bytes(data)
        enc = key.encrypt_file(src)
        assert enc == Path(str(src) + ".ncr")
        dec = key.decrypt_file(enc, Path(tmp) / "out.bin")
        assert dec.read_bytes() == data


# ── repr ──────────────────────────────────────────────────────────────────────
def test_repr(key):
    r = repr(key)
    assert "NCRKey" in r
    assert "salt=" in r
