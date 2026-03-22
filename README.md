# ncr-cipher

**Production-grade file encryption CLI & GUI** — a single `ncr` command available everywhere in your terminal after installation, on Windows, macOS, and Linux. Also comes with a modern desktop GUI.

Built on the **NCR3 cipher** — a combinatorics-based encryption scheme using binomial coefficients (nCr) as a trapdoor, with CBC chaining, HMAC-SHA3-256 authentication, and scrypt KDF.

---

## Installation

### CLI (Command Line)

```bash
pip install ncr-cipher
```

Or download and run the Windows installer — adds `ncr` to your PATH automatically.

After install, `ncr` is available in any terminal — CMD, PowerShell, bash, zsh, fish.

### GUI (Desktop App)

Download `ncr-gui.exe` from [Releases](https://github.com/Tesseract1net/nCr-cipher/releases) — no installation needed, just double-click and run.

---

## GUI

The NCR Cipher GUI provides a clean desktop interface for all encryption operations with dark and light mode support.

**Features:**
- 🔑 Key Generator — create key files with adjustable KDF strength
- 🔒 Encrypt — lock any file with optional key file + password
- 🔓 Decrypt — restore NCR3 and NCR2 files
- ✔ Verify HMAC — check file integrity without decrypting
- ℹ File Info — inspect NCR file metadata without a password
- ⚡ Benchmark — measure KDF time and encryption speed
- ✦ Self Tests — verify the cipher implementation
- ☀/☾ Dark and light mode toggle

**Download:** `ncr-gui.exe` from [Releases](https://github.com/Tesseract1net/nCr-cipher/releases)

---

## CLI Quick Start

```bash
# Generate a key file (do this once)
ncr --keygen mykey.key

# Encrypt a file  → creates secret.txt.ncr3
ncr --lock secret.txt --key mykey.key

# Decrypt it back
ncr --unlock secret.txt.ncr3 --key mykey.key

# Verify file integrity without decrypting
ncr --verify secret.txt.ncr3 --key mykey.key

# Show file metadata (no password needed)
ncr --info secret.txt.ncr3
```

---

## All Commands

| Command | Description |
|---|---|
| `ncr --keygen <keyfile>` | Generate a new encrypted key file |
| `ncr --lock <file> --key <k>` | Encrypt a file |
| `ncr --unlock <file> --key <k>` | Decrypt a file |
| `ncr --verify <file> --key <k>` | Check HMAC without decrypting — exits 0 (OK) or 1 (TAMPERED) |
| `ncr --info <file>` | Show NCR version, IV, block count, file size |
| `ncr --bench` | Benchmark KDF time + encrypt speed at multiple sizes |
| `ncr --test` | Run internal self-tests — exits 0 (pass) or 1 (fail) |
| `ncr --version` | Print version |

---

## Flags

| Flag | Description |
|---|---|
| `--key, -k <file>` | Key file for lock / unlock / verify |
| `--out, -o <path>` | Output path override |
| `--inplace, -i` | Overwrite the original file instead of creating new |
| `--silent, -s` | No output except fatal errors (for shell scripts) |
| `--force, -f` | Overwrite output without confirmation prompt |
| `--pow <1-5>` | KDF strength preset (default 3). Higher = slower but stronger. |

### `--pow` levels

| Level | Speed | RAM | Time |
|---|---|---|---|
| 1 | Fast | 16 MB | ~0.1s |
| 2 | Moderate | 32 MB | ~0.3s |
| 3 | **Default** | 64 MB | ~1s |
| 4 | Strong | 256 MB | ~4s |
| 5 | Maximum | 1 GB | ~16s |

---

## Python API

```python
from ncr_cipher import core

# Encrypt bytes directly
ct = core.encrypt(b"hello world", b"my password", strength=3)
pt = core.decrypt(ct, b"my password")

# Generate / load key files
kf = core.generate_keyfile(b"my password", strength=3)
passphrase = core.load_keyfile(kf, b"my password")

# Verify HMAC without decrypting
ok = core.verify_hmac(ct, b"my password")   # True / False

# Parse header without password
hdr = core.parse_header(ct)
# hdr = {"version": "NCR3", "strength": 3, "iv": "...", "block_count": 11, ...}
```

---

## The NCR3 Cipher

```
For each byte b at position i:
  k_i  = BLAKE2b(stream_key, i) mod 256          ← per-byte key mixing
  P    = (nCr(n1,b) × nCr(n2,255-b) + nCr(n3, b XOR k_i)) mod M
  S_i  = HMAC-SHA3-256(stream_key, i) mod M       ← CBC stream salt
  C_i  = (P + S_i + C_{i-1}) mod M                ← CBC chaining

M    = 2¹²⁷ − 1  (Mersenne prime)
n1, n2, n3 = secret integers derived from password via scrypt
```

Security layers:
- **Triple nCr trapdoor** — attacker must find all 3 secret integers
- **CBC chaining** — 1-bit change cascades through entire ciphertext
- **BLAKE2b stream** — same byte encrypts differently at every position
- **scrypt KDF** — brute-forcing passwords is expensive
- **HMAC-SHA3-256** — any modification detected before decryption

Backwards compatible: reads NCR2 files (read-only).

---

## Requirements

- Python 3.9+ (CLI / API)
- **Zero external dependencies** — stdlib only
- GUI: Windows exe — no Python needed

---

## License

MIT — see [LICENSE](LICENSE)

