"""
ncr_cipher/cli.py — Command-line interface for ncr-cipher.

Usage:
  ncr --keygen  abc.key
  ncr --lock    file.txt   --key abc.key
  ncr --unlock  file.ncr   --key abc.key
  ncr --bench
  ncr --test
  ncr --version
"""
from __future__ import annotations

import argparse
import getpass
import itertools
import os
import sys
import tempfile
import threading
import time
from pathlib import Path

try:
    from ncr_cipher.core import NCRKey, NCRError, NCRAuthError, NCRFormatError, VERSION
except ImportError:
    from core import NCRKey, NCRError, NCRAuthError, NCRFormatError, VERSION

# ── Colour helpers ────────────────────────────────────────────────────────────
_COLOUR = sys.stderr.isatty()


def _c(code: str, text: str) -> str:
    if not _COLOUR:
        return text
    codes = {"green": "32", "cyan": "36", "yellow": "33", "red": "31", "bold": "1"}
    return f"\033[{codes.get(code, '0')}m{text}\033[0m"


def ok(msg: str)   -> None: print(_c("green",  f"✓ {msg}"), file=sys.stderr)
def info(msg: str) -> None: print(_c("cyan",   f"· {msg}"), file=sys.stderr)
def warn(msg: str) -> None: print(_c("yellow", f"⚠ {msg}"), file=sys.stderr)
def err(msg: str)  -> None: print(_c("red",    f"✗ {msg}"), file=sys.stderr)


# ── Spinner ───────────────────────────────────────────────────────────────────
_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


class Spinner:
    def __init__(self, label: str):
        self._label  = label
        self._stop   = threading.Event()
        self._thread = threading.Thread(target=self._spin, daemon=True)

    def _spin(self) -> None:
        if not _COLOUR:
            print(f"· {self._label}…", file=sys.stderr)
            return
        for ch in itertools.cycle(_FRAMES):
            if self._stop.is_set():
                break
            print(f"\r{_c('cyan', ch)} {self._label}…", end="", file=sys.stderr, flush=True)
            time.sleep(0.08)
        print("\r" + " " * (len(self._label) + 6) + "\r", end="", file=sys.stderr, flush=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *_):
        self._stop.set()
        self._thread.join()


# ── Password helpers ──────────────────────────────────────────────────────────
def _get_password(confirm: bool = False) -> bytes:
    pw = getpass.getpass("Password: ")
    if not pw:
        err("Password cannot be empty.")
        sys.exit(1)
    if confirm:
        pw2 = getpass.getpass("Confirm password: ")
        if pw != pw2:
            err("Passwords do not match.")
            sys.exit(1)
    return pw.encode()


# ── Sub-commands ──────────────────────────────────────────────────────────────
def cmd_keygen(args: argparse.Namespace) -> int:
    dest = Path(args.keygen)
    if dest.exists():
        warn(f"{dest} already exists — overwriting.")
    pw = _get_password(confirm=True)
    with Spinner("Deriving key"):
        key = NCRKey.generate(pw)
    key.save(dest)
    ok(f"Key saved → {dest}")
    return 0


def cmd_lock(args: argparse.Namespace) -> int:
    if not args.key:
        err("--key <keyfile> is required for --lock.")
        return 1
    src = Path(args.lock)
    if not src.exists():
        err(f"File not found: {src}")
        return 1
    pw = _get_password()
    with Spinner("Deriving key"):
        key = NCRKey.load(args.key, pw)
    dst = Path(args.output) if args.output else Path(str(src) + ".ncr")
    with Spinner(f"Encrypting {src.name}"):
        out = key.encrypt_file(src, dst)
    ok(f"Locked → {out}")
    return 0


def cmd_unlock(args: argparse.Namespace) -> int:
    if not args.key:
        err("--key <keyfile> is required for --unlock.")
        return 1
    src = Path(args.unlock)
    if not src.exists():
        err(f"File not found: {src}")
        return 1
    pw = _get_password()
    with Spinner("Deriving key"):
        key = NCRKey.load(args.key, pw)
    dst = Path(args.output) if args.output else None
    with Spinner(f"Decrypting {src.name}"):
        try:
            out = key.decrypt_file(src, dst)
        except NCRAuthError as e:
            err(f"Authentication failed: {e}")
            return 1
        except NCRError as e:
            err(f"Decryption error: {e}")
            return 1
    ok(f"Unlocked → {out}")
    return 0


def cmd_bench() -> int:
    import time as _time
    info("Benchmark (N=2**14 for speed)")
    pw = b"bench-password"

    t0 = _time.perf_counter()
    key = NCRKey.generate(pw, N=2**14)
    kdf_ms = (_time.perf_counter() - t0) * 1000
    print(f"  KDF time        : {kdf_ms:.1f} ms", file=sys.stderr)

    for size in (256, 1024, 4096, 16384):
        data = os.urandom(size)
        t0   = _time.perf_counter()
        ct   = key.encrypt(data)
        enc_ms = (_time.perf_counter() - t0) * 1000
        print(f"  Encrypt {size:>5}B  : {enc_ms:.1f} ms  "
              f"({size/enc_ms*1000/1024:.1f} KB/s)", file=sys.stderr)
    return 0


def cmd_test() -> int:
    """Mini self-test suite (no pytest required)."""
    import traceback as _tb

    PASS = _c("green", "PASS")
    FAIL = _c("red",   "FAIL")
    failed = 0

    def run(name: str, fn):
        nonlocal failed
        try:
            fn()
            print(f"  {PASS}  {name}", file=sys.stderr)
        except Exception as exc:  # noqa: BLE001
            print(f"  {FAIL}  {name}: {exc}", file=sys.stderr)
            _tb.print_exc(file=sys.stderr)
            failed += 1

    key = NCRKey.generate(b"test", N=2**14)

    def t_roundtrip():
        assert key.decrypt(key.encrypt(b"Hello, World!")) == b"Hello, World!"

    def t_empty():
        assert key.decrypt(key.encrypt(b"")) == b""

    def t_all_bytes():
        data = bytes(range(256))
        assert key.decrypt(key.encrypt(data)) == data

    def t_unicode():
        data = "привет мир 🌍".encode()
        assert key.decrypt(key.encrypt(data)) == data

    def t_random_iv():
        ct1 = key.encrypt(b"same")
        ct2 = key.encrypt(b"same")
        assert ct1 != ct2

    def t_wrong_password():
        ct = key.encrypt(b"secret")
        bad = NCRKey.generate(b"wrong", N=2**14)
        try:
            bad.decrypt(ct)
            raise AssertionError("Should have raised NCRError")
        except NCRError:
            pass

    def t_tamper():
        ct = bytearray(key.encrypt(b"secret"))
        ct[60] ^= 0xFF
        try:
            key.decrypt(bytes(ct))
            raise AssertionError("Should have raised NCRAuthError")
        except NCRAuthError:
            pass

    def t_bad_format():
        try:
            key.decrypt(b"GARBAGE DATA")
            raise AssertionError("Should have raised NCRFormatError")
        except NCRFormatError:
            pass

    for name, fn in [
        ("Round-trip",        t_roundtrip),
        ("Empty input",       t_empty),
        ("All 256 bytes",     t_all_bytes),
        ("Unicode UTF-8",     t_unicode),
        ("Random IV",         t_random_iv),
        ("Wrong password",    t_wrong_password),
        ("Tampered HMAC",     t_tamper),
        ("Bad format",        t_bad_format),
    ]:
        run(name, fn)

    if failed:
        err(f"{failed} test(s) FAILED")
        return 1
    ok("All tests passed")
    return 0


# ── Argument parser ───────────────────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ncr",
        description="ncr-cipher — combinatorics-based file encryption",
    )
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--keygen",  metavar="KEYFILE", help="Generate a new key file")
    g.add_argument("--lock",    metavar="FILE",    help="Encrypt FILE")
    g.add_argument("--unlock",  metavar="FILE",    help="Decrypt FILE")
    g.add_argument("--bench",   action="store_true")
    g.add_argument("--test",    action="store_true")
    g.add_argument("--version", action="store_true")
    p.add_argument("--key",     metavar="KEYFILE", help="Key file (required for --lock/--unlock)")
    p.add_argument("--output",  metavar="FILE",    help="Output path override")
    return p


def main() -> None:
    try:
        if len(sys.argv) == 1:
            # No arguments — launch GUI instead
            import subprocess
            import os
            gui = os.path.join(os.path.dirname(__file__), "gui.py")
            subprocess.Popen([sys.executable, gui])
            return
        args = build_parser().parse_args()
        if args.version:
            print(f"ncr-cipher {VERSION}")
            sys.exit(0)
        if args.keygen:
            sys.exit(cmd_keygen(args))
        elif args.lock:
            sys.exit(cmd_lock(args))
        elif args.unlock:
            sys.exit(cmd_unlock(args))
        elif args.bench:
            sys.exit(cmd_bench())
        elif args.test:
            sys.exit(cmd_test())
    except KeyboardInterrupt:
        print("", file=sys.stderr)
        warn("Interrupted.")
        sys.exit(130)
    except Exception as exc:  # noqa: BLE001
        err(str(exc))
        sys.exit(1)


if __name__ == "__main__":
    main()
