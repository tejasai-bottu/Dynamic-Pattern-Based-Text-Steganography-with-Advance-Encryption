#!/usr/bin/env python3
"""
stego_v2.py — Unicode Steganography V2
=======================================
Encrypt pipeline:
    file → zlib compress → AES-256-GCM → compact binary payload
         → base-N invisible Unicode encoding → even-spread embedding → .txt

Decrypt pipeline:
    .txt → extract invisible symbols → length prefix bootstrap
         → base-N decode → AES-256-GCM decrypt → decompress → original file

Key improvements over V1
  ✓  AES-256-GCM (authenticated encryption) — replaces AES-CBC
  ✓  PBKDF2-HMAC-SHA256 (200 000 iters) — replaces raw key repetition
  ✓  Adaptive zlib compression before encryption (skipped when not beneficial)
  ✓  Direct bytes → base-N Unicode — eliminates the "010101…" binary-string stage
  ✓  Three validated alphabet profiles: SAFE (10), EXTENDED (26), MAX (122)
  ✓  Key-derived Fisher-Yates permutation of the validated alphabet
  ✓  Compact binary payload header (MAGIC · version · flags · profile · extension
                                     · payload length · salt · nonce)
  ✓  Bootstrap-safe decryption: fixed unkeyed length prefix encodes
      (profile_id, total_bytes) so decryption never has to guess
  ✓  Capacity check before embedding — rejects impossible payloads early
  ✓  Even-spread sequential embedding — no whole-text permutation

Requirements:  pip install pycryptodome
Usage (interactive):   python stego_v2.py
Usage (CLI):           python stego_v2.py encrypt --help
                       python stego_v2.py decrypt --help
                       python stego_v2.py test
"""

from __future__ import annotations

import argparse
import hashlib
import math
import os
import struct
import sys
import tempfile
import zlib
from typing import Tuple

# ── dependency check ──────────────────────────────────────────────────────────
try:
    from Crypto.Cipher import AES
except ImportError:
    sys.exit(
        "ERROR: pycryptodome is required.\n"
        "  Install: pip install pycryptodome"
    )


# =============================================================================
# §1  CRYPTOGRAPHY — AES-256-GCM + PBKDF2
# =============================================================================

_SALT_LEN  = 16   # bytes
_NONCE_LEN = 12   # bytes (GCM recommended)
_TAG_LEN   = 16   # bytes (GCM auth tag)
_KEY_LEN   = 32   # bytes (AES-256)
_KDF_ITER  = 200_000


def _derive_key(password: str, salt: bytes) -> bytes:
    """PBKDF2-HMAC-SHA256 → 256-bit AES key."""
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        _KDF_ITER,
        _KEY_LEN,
    )


def _aes_encrypt(plaintext: bytes, password: str
                 ) -> Tuple[bytes, bytes, bytes, bytes]:
    """
    AES-256-GCM encrypt.
    Returns (salt, nonce, ciphertext, auth_tag).
    """
    salt  = os.urandom(_SALT_LEN)
    nonce = os.urandom(_NONCE_LEN)
    key   = _derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return salt, nonce, ciphertext, tag


def _aes_decrypt(salt: bytes, nonce: bytes, ciphertext: bytes,
                 tag: bytes, password: str) -> bytes:
    """
    AES-256-GCM decrypt + authenticate.
    Raises ValueError on tag mismatch (wrong password or corruption).
    """
    key    = _derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        return cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        raise ValueError(
            "Authentication failed — wrong password or corrupted payload."
        )


# =============================================================================
# §2  COMPRESSION — Adaptive zlib
# =============================================================================

_FLAG_COMPRESSED = 0x01


def _compress(data: bytes) -> Tuple[bytes, bool]:
    """
    Compress with zlib level-9.
    Returns (result_bytes, was_compressed).
    Skips compression when it would increase size (e.g. already-compressed formats).
    """
    compressed = zlib.compress(data, level=9)
    if len(compressed) < len(data):
        return compressed, True
    return data, False


def _decompress(data: bytes) -> bytes:
    return zlib.decompress(data)


# =============================================================================
# §3  ALPHABET PROFILES
# =============================================================================
#
#  Three tiers of invisible Unicode characters, validated conceptually by category:
#
#  SAFE (10):     Zero-width / invisible format characters with universal support.
#  EXTENDED (26): SAFE + 16 variation selectors (VS1–VS16, U+FE00–U+FE0F).
#  MAX (122):     EXTENDED + 96 Unicode tag characters (U+E0020–U+E007F).
#
#  The key NEVER determines which characters belong to a profile (that is a
#  property of the character and environment).  The key only determines the
#  permutation of the validated set used during encoding.
#

PROFILE_SAFE     = 0
PROFILE_EXTENDED = 1
PROFILE_MAX      = 2

PROFILE_NAMES: dict = {
    PROFILE_SAFE:     "SAFE",
    PROFILE_EXTENDED: "EXTENDED",
    PROFILE_MAX:      "MAX",
}

# ── SAFE: 10 universally-supported invisible characters ───────────────────────
_SAFE_CHARS: list = [
    "\u200B",  # ZERO WIDTH SPACE
    "\u200C",  # ZERO WIDTH NON-JOINER
    "\u200D",  # ZERO WIDTH JOINER
    "\u2060",  # WORD JOINER
    "\u2061",  # FUNCTION APPLICATION (invisible math)
    "\u2062",  # INVISIBLE TIMES
    "\u2063",  # INVISIBLE SEPARATOR
    "\u2064",  # INVISIBLE PLUS
    "\uFEFF",  # ZERO WIDTH NO-BREAK SPACE
    "\u00AD",  # SOFT HYPHEN
]

# ── EXTENDED: + 16 variation selectors (VS1–VS16) ─────────────────────────────
_VS_CHARS: list = [chr(cp) for cp in range(0xFE00, 0xFE10)]  # 16 chars

# ── MAX: + 96 Unicode tag characters ──────────────────────────────────────────
_TAG_CHARS: list = [chr(cp) for cp in range(0xE0020, 0xE0080)]  # 96 chars

_EXTENDED_CHARS = _SAFE_CHARS + _VS_CHARS          # 26 chars
_MAX_CHARS      = _EXTENDED_CHARS + _TAG_CHARS     # 122 chars

_PROFILE_CHARS: dict = {
    PROFILE_SAFE:     _SAFE_CHARS,
    PROFILE_EXTENDED: _EXTENDED_CHARS,
    PROFILE_MAX:      _MAX_CHARS,
}

# Union of every character we ever embed — used for extraction
_ALL_STEGO_CHARS: frozenset = frozenset(
    ch for lst in _PROFILE_CHARS.values() for ch in lst
)


def _is_stego(ch: str) -> bool:
    return ch in _ALL_STEGO_CHARS


def _strip_stego(text: str) -> str:
    """Remove every stego invisible character from text."""
    return "".join(ch for ch in text if not _is_stego(ch))


def _get_profile_chars(profile_id: int) -> list:
    if profile_id not in _PROFILE_CHARS:
        raise ValueError(f"Unknown profile_id: {profile_id}")
    return list(_PROFILE_CHARS[profile_id])


def _keyed_alphabet(profile_id: int, password: str) -> list:
    """
    Return the profile's character list permuted deterministically by the key.
    Uses Fisher-Yates with per-index SHA-256 sub-keys for uniform randomness.
    """
    chars = _get_profile_chars(profile_id)
    seed  = hashlib.sha256(b"stego:v2:alpha:" + password.encode()).digest()
    n     = len(chars)
    for i in range(n - 1, 0, -1):
        h = hashlib.sha256(seed + struct.pack(">I", i)).digest()
        j = int.from_bytes(h[:4], "big") % (i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return chars


def profile_info(profile_id: int) -> dict:
    """Return a summary dict for display."""
    chars = _get_profile_chars(profile_id)
    n     = len(chars)
    bps   = math.log2(n) if n > 1 else 0.0
    return {
        "id":           profile_id,
        "name":         PROFILE_NAMES[profile_id],
        "size":         n,
        "bits_per_sym": round(bps, 3),
    }


# =============================================================================
# §4  BASE-N ENCODING / DECODING
# =============================================================================
#
#  Core efficiency gain: treat encrypted bytes as a large integer and express it
#  in base-N using the invisible alphabet — no intermediate "010101…" string.
#
#  For N=10  (SAFE):     log2(10) ≈ 3.32 bits/symbol
#  For N=26  (EXTENDED): log2(26) ≈ 4.70 bits/symbol  (+42% vs SAFE)
#  For N=122 (MAX):      log2(122) ≈ 6.93 bits/symbol  (+109% vs SAFE)
#

def _encode_base_n(data: bytes, alphabet: list) -> str:
    """
    Encode arbitrary bytes → invisible Unicode string.
    Produces exactly ceil(8·len(data) / log2(N)) symbols (fixed-width output).
    """
    n = len(alphabet)
    if n < 2:
        raise ValueError("Alphabet must have ≥ 2 symbols.")
    if not data:
        return ""
    bits_per_sym = math.log2(n)
    num_syms     = math.ceil(8 * len(data) / bits_per_sym)
    value        = int.from_bytes(data, "big")
    digits: list = []
    for _ in range(num_syms):
        digits.append(value % n)
        value //= n
    digits.reverse()
    return "".join(alphabet[d] for d in digits)


def _decode_base_n(symbols: str, alphabet: list, num_bytes: int) -> bytes:
    """
    Decode invisible Unicode string → bytes.
    num_bytes MUST match the value used during encoding (stored in the payload header).
    Handles leading-zero bytes correctly via big-endian integer reconstruction.
    """
    n           = len(alphabet)
    char_to_idx = {c: i for i, c in enumerate(alphabet)}
    value       = 0
    for ch in symbols:
        if ch in char_to_idx:
            value = value * n + char_to_idx[ch]
    try:
        return value.to_bytes(num_bytes, "big")
    except OverflowError:
        raise ValueError(
            "Decoded value overflows expected byte count — data may be corrupted."
        )


# =============================================================================
# §5  BINARY PAYLOAD FORMAT
# =============================================================================
#
#  Layout (all multi-byte integers big-endian):
#
#  ┌────────────────────────────────────────────────────────┐
#  │  MAGIC      4 B    b'STGV'                            │
#  │  VERSION    1 B    currently 2                         │
#  │  FLAGS      1 B    bit 0 = compressed                  │
#  │  PROFILE_ID 1 B    0=SAFE 1=EXTENDED 2=MAX             │
#  │  EXT_LEN    1 B    length of file extension string     │
#  │  EXT        N B    file extension (no dot, e.g. "pdf") │
#  │  CRYPT_LEN  4 B    len(ciphertext) + TAG_LEN           │
#  │  SALT      16 B    KDF salt                            │
#  │  NONCE     12 B    AES-GCM nonce                       │
#  │  CIPHERTEXT ? B    AES-GCM ciphertext                  │
#  │  AUTH_TAG  16 B    AES-GCM authentication tag          │
#  └────────────────────────────────────────────────────────┘
#

_MAGIC   = b"STGV"
_VERSION = 2


def _build_payload(flags: int, profile_id: int, extension: str,
                   salt: bytes, nonce: bytes,
                   ciphertext: bytes, tag: bytes) -> bytes:
    ext_b     = extension.encode("utf-8")
    crypt_len = len(ciphertext) + _TAG_LEN
    return (
        _MAGIC
        + struct.pack("B", _VERSION)
        + struct.pack("B", flags)
        + struct.pack("B", profile_id)
        + struct.pack("B", len(ext_b))
        + ext_b
        + struct.pack(">I", crypt_len)
        + salt
        + nonce
        + ciphertext
        + tag
    )


def _parse_payload(data: bytes) -> dict:
    """Parse binary payload. Returns all header fields plus ciphertext and tag."""
    off = 0

    magic = data[off:off+4];   off += 4
    if magic != _MAGIC:
        raise ValueError(f"Bad MAGIC: {magic!r}  (wrong password?)")

    ver = data[off];           off += 1
    if ver != _VERSION:
        raise ValueError(f"Unsupported format version {ver}")

    flags      = data[off];    off += 1
    profile_id = data[off];    off += 1
    ext_len    = data[off];    off += 1
    extension  = data[off:off+ext_len].decode("utf-8"); off += ext_len
    crypt_len  = struct.unpack(">I", data[off:off+4])[0]; off += 4
    salt       = data[off:off+_SALT_LEN];   off += _SALT_LEN
    nonce      = data[off:off+_NONCE_LEN];  off += _NONCE_LEN
    ciphertext = data[off:off + crypt_len - _TAG_LEN]
    tag        = data[off + crypt_len - _TAG_LEN : off + crypt_len]

    return {
        "flags":      flags,
        "profile_id": profile_id,
        "extension":  extension,
        "salt":       salt,
        "nonce":      nonce,
        "ciphertext": ciphertext,
        "tag":        tag,
    }


# =============================================================================
# §6  INVISIBLE SYMBOL STREAM: EMBEDDING & EXTRACTION
# =============================================================================
#
#  The invisible symbol stream consists of two concatenated parts:
#
#  ┌────────────────────────────────────────────────────────────────┐
#  │  LENGTH PREFIX  (always _PREFIX_SYMS symbols)                  │
#  │  Encoded with the FIXED, unkeyed SAFE alphabet.               │
#  │  Contains: profile_id (1 B) + total_payload_bytes (4 B)       │
#  │  Purpose: bootstrap — lets the decoder find profile + length  │
#  │           without needing to know the key alphabet first.     │
#  ├────────────────────────────────────────────────────────────────┤
#  │  MAIN PAYLOAD  (variable symbols)                              │
#  │  Encoded with the KEY-PERMUTED alphabet for the declared      │
#  │  profile.  Contains the full binary_payload bytes.            │
#  └────────────────────────────────────────────────────────────────┘
#
#  Both parts are concatenated, then spread evenly through the cover text
#  at inter-character gap positions (one invisible symbol per gap).
#

_PREFIX_PAYLOAD_LEN = 5  # 1 byte profile_id + 4 bytes uint32

# Number of SAFE-alphabet symbols needed to encode _PREFIX_PAYLOAD_LEN bytes
_PREFIX_SYMS: int = math.ceil(
    8 * _PREFIX_PAYLOAD_LEN / math.log2(len(_SAFE_CHARS))
)  # = 13 with len=10


# ── length prefix helpers ─────────────────────────────────────────────────────

def _encode_prefix(profile_id: int, total_bytes: int) -> str:
    """Encode (profile_id, total_bytes) → fixed _PREFIX_SYMS invisible symbols."""
    raw = struct.pack("B", profile_id) + struct.pack(">I", total_bytes)
    s   = _encode_base_n(raw, _SAFE_CHARS)   # unkeyed, always consistent
    assert len(s) == _PREFIX_SYMS, (
        f"Prefix symbol count mismatch: got {len(s)}, expected {_PREFIX_SYMS}"
    )
    return s


def _decode_prefix(symbols: str) -> Tuple[int, int]:
    """Decode _PREFIX_SYMS symbols → (profile_id, total_bytes)."""
    raw         = _decode_base_n(symbols, _SAFE_CHARS, _PREFIX_PAYLOAD_LEN)
    profile_id  = raw[0]
    total_bytes = struct.unpack(">I", raw[1:5])[0]
    return profile_id, total_bytes


# ── capacity ──────────────────────────────────────────────────────────────────

def capacity_bytes(cover_text: str, profile_id: int) -> int:
    """
    Return the maximum binary payload size (bytes) that can be hidden in
    cover_text using the given profile, accounting for the prefix overhead.
    """
    clean   = _strip_stego(cover_text)
    n_gaps  = max(0, len(clean) - 1)          # inter-character gap count
    usable  = max(0, n_gaps - _PREFIX_SYMS)   # gaps available for payload
    n_alpha = len(_get_profile_chars(profile_id))
    bps     = math.log2(n_alpha) if n_alpha > 1 else 0.0
    return int(usable * bps / 8)


# ── gap index computation ─────────────────────────────────────────────────────

def _gap_indices(n_sym: int, n_gaps: int) -> list:
    """
    Return n_sym evenly-spaced gap indices in [0, n_gaps-1].
    Gap index g means "insert invisible char after clean[g]".
    Guaranteed to return n_sym distinct indices when n_sym <= n_gaps.

    Proof of distinctness: consecutive terms differ by floor(n_gaps/n_sym) >= 1
    because n_gaps >= n_sym.
    """
    if n_sym == 0:
        return []
    return [int(i * n_gaps / n_sym) for i in range(n_sym)]


# ── embed ─────────────────────────────────────────────────────────────────────

def _embed_symbols(cover_text: str, all_symbols: str) -> str:
    """
    Spread all_symbols evenly through cover_text at inter-character gaps.
    Cover text is first stripped of any pre-existing stego chars.
    """
    clean  = _strip_stego(cover_text)
    n_sym  = len(all_symbols)
    n_gaps = len(clean) - 1

    if n_sym == 0:
        return clean
    if n_sym > n_gaps:
        raise ValueError(
            f"Cover text too short: {n_gaps} gaps available, "
            f"{n_sym} symbols to embed.  Provide a longer cover text."
        )

    gaps    = _gap_indices(n_sym, n_gaps)
    gap_map = {g: all_symbols[i] for i, g in enumerate(gaps)}

    result: list = []
    for i, ch in enumerate(clean):
        result.append(ch)
        if i in gap_map:
            result.append(gap_map[i])
    return "".join(result)


def embed_payload(cover_text: str, binary_payload: bytes,
                  profile_id: int, password: str) -> str:
    """
    Full encode pipeline: binary_payload → invisible symbol stream → stego text.
    """
    alphabet     = _keyed_alphabet(profile_id, password)
    prefix_syms  = _encode_prefix(profile_id, len(binary_payload))
    payload_syms = _encode_base_n(binary_payload, alphabet)
    return _embed_symbols(cover_text, prefix_syms + payload_syms)


# ── extract ───────────────────────────────────────────────────────────────────

def _extract_symbols(stego_text: str) -> str:
    """Return all stego invisible characters from stego_text, in document order."""
    return "".join(ch for ch in stego_text if _is_stego(ch))


def extract_payload(stego_text: str, password: str) -> bytes:
    """
    Full decode pipeline: stego text → binary_payload bytes.

    Bootstrap sequence:
      1. Extract all invisible chars in document order.
      2. Decode first _PREFIX_SYMS symbols using the fixed SAFE alphabet
         → learn profile_id and total payload bytes.
      3. Build the key-permuted alphabet for the declared profile.
      4. Decode the next N symbols → total payload bytes.
    """
    invisible = _extract_symbols(stego_text)

    if len(invisible) < _PREFIX_SYMS:
        raise ValueError(
            f"Found only {len(invisible)} invisible symbols — "
            f"need at least {_PREFIX_SYMS}.  Is this really a stego file?"
        )

    # ── step 1: bootstrap ────────────────────────────────────────────────
    profile_id, total_bytes = _decode_prefix(invisible[:_PREFIX_SYMS])

    if profile_id not in _PROFILE_CHARS:
        raise ValueError(
            f"Decoded profile_id={profile_id} is invalid.  "
            "Wrong password or corrupted prefix."
        )

    # ── step 2: main payload decode ──────────────────────────────────────
    alphabet     = _keyed_alphabet(profile_id, password)
    bps          = math.log2(len(alphabet))
    n_payload_sym = math.ceil(8 * total_bytes / bps)

    payload_window = invisible[_PREFIX_SYMS : _PREFIX_SYMS + n_payload_sym]

    if len(payload_window) < n_payload_sym:
        raise ValueError(
            f"Incomplete payload symbols: expected {n_payload_sym}, "
            f"got {len(payload_window)}.  Stego text may be truncated or corrupted."
        )

    return _decode_base_n(payload_window, alphabet, total_bytes)


# =============================================================================
# §7  TOP-LEVEL WORKFLOWS
# =============================================================================

def encrypt_file_to_stego(
    input_path:  str,
    password:    str,
    cover_text:  str,
    output_path: str,
    profile_id:  int  = PROFILE_SAFE,
    verbose:     bool = True,
) -> bool:
    """
    Encrypt a file and embed it invisibly into cover_text.
    Saves the stego text to output_path (always as .txt).
    Returns True on success.
    """

    def log(msg: str) -> None:
        if verbose: print(f"  [+] {msg}")

    def err(msg: str) -> None:
        print(f"  [!] {msg}", file=sys.stderr)

    # ── 1. Read source file ───────────────────────────────────────────────
    try:
        with open(input_path, "rb") as fh:
            file_data = fh.read()
    except OSError as exc:
        err(f"Cannot read input file: {exc}"); return False

    extension = os.path.splitext(input_path)[1].lstrip(".")
    log(f"Input: {len(file_data):,} bytes  extension='.{extension}'")

    # ── 2. Compress ───────────────────────────────────────────────────────
    compressed, was_compressed = _compress(file_data)
    flags = _FLAG_COMPRESSED if was_compressed else 0
    if was_compressed:
        ratio = len(compressed) / len(file_data) * 100
        log(f"Compressed: {len(compressed):,} bytes ({ratio:.1f}% of original)")
    else:
        log("Compression skipped (not beneficial — already-compressed format?)")

    # ── 3. AES-256-GCM encrypt ────────────────────────────────────────────
    log(f"Encrypting  [PBKDF2 {_KDF_ITER // 1000}k iters + AES-256-GCM] ...")
    salt, nonce, ciphertext, tag = _aes_encrypt(compressed, password)
    log(f"Ciphertext: {len(ciphertext):,} bytes + {_TAG_LEN}-B auth tag")

    # ── 4. Build compact binary payload ───────────────────────────────────
    binary_payload = _build_payload(
        flags, profile_id, extension, salt, nonce, ciphertext, tag
    )
    log(
        f"Binary payload: {len(binary_payload):,} bytes  "
        f"(header + ciphertext + tag)"
    )

    # ── 5. Capacity check ─────────────────────────────────────────────────
    cap = capacity_bytes(cover_text, profile_id)
    if len(binary_payload) > cap:
        err(
            f"Insufficient cover capacity!\n"
            f"    Payload  : {len(binary_payload):,} bytes\n"
            f"    Available: {cap:,} bytes  "
            f"[profile {PROFILE_NAMES[profile_id]}]\n"
            f"    → Use a longer cover text or a higher-capacity profile."
        )
        return False

    util = len(binary_payload) / cap * 100 if cap > 0 else 100.0
    log(
        f"Cover capacity ({PROFILE_NAMES[profile_id]}): {cap:,} bytes  "
        f"— utilization {util:.1f}%"
    )

    # ── 6. Embed ──────────────────────────────────────────────────────────
    log("Embedding invisible symbols into cover text ...")
    stego = embed_payload(cover_text, binary_payload, profile_id, password)
    n_syms = sum(1 for ch in stego if _is_stego(ch))
    log(
        f"Embedded {n_syms:,} invisible symbols "
        f"into {len(stego):,}-char stego text"
    )

    # ── 7. Save ───────────────────────────────────────────────────────────
    out = os.path.splitext(output_path)[0] + ".txt"
    try:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(stego)
    except OSError as exc:
        err(f"Cannot write output file: {exc}"); return False

    log(f"Saved: {out}")
    return True


def decrypt_stego_file(
    stego_path:  str,
    password:    str,
    output_path: str,
    verbose:     bool = True,
) -> bool:
    """
    Extract and decrypt the hidden file from a stego .txt.
    The output file extension is recovered automatically from the payload header.
    Returns True on success.
    """

    def log(msg: str) -> None:
        if verbose: print(f"  [+] {msg}")

    def err(msg: str) -> None:
        print(f"  [!] {msg}", file=sys.stderr)

    # ── 1. Read stego file ────────────────────────────────────────────────
    try:
        with open(stego_path, "r", encoding="utf-8") as fh:
            stego_text = fh.read()
    except OSError as exc:
        err(f"Cannot read stego file: {exc}"); return False

    n_invisible = sum(1 for ch in stego_text if _is_stego(ch))
    log(f"Read {len(stego_text):,} chars  ({n_invisible:,} invisible symbols)")

    if n_invisible == 0:
        err("No invisible stego symbols found — is this really a stego file?")
        return False

    # ── 2. Extract binary payload (bootstrap-safe) ────────────────────────
    log("Extracting payload symbols and decoding ...")
    try:
        binary_payload = extract_payload(stego_text, password)
    except ValueError as exc:
        err(f"Extraction error: {exc}"); return False

    log(f"Extracted binary payload: {len(binary_payload):,} bytes")

    # ── 3. Parse compact header ───────────────────────────────────────────
    try:
        info = _parse_payload(binary_payload)
    except (ValueError, struct.error) as exc:
        err(f"Header parse failed: {exc}"); return False

    pname = PROFILE_NAMES.get(info["profile_id"], f"#{info['profile_id']}")
    log(
        f"Profile={pname}  "
        f"extension='.{info['extension']}'  "
        f"compressed={bool(info['flags'] & _FLAG_COMPRESSED)}"
    )

    # ── 4. AES-256-GCM decrypt ────────────────────────────────────────────
    log("Decrypting ...")
    try:
        decrypted = _aes_decrypt(
            info["salt"], info["nonce"],
            info["ciphertext"], info["tag"],
            password,
        )
    except ValueError as exc:
        err(f"Decryption failed: {exc}"); return False

    log(f"Decrypted: {len(decrypted):,} bytes")

    # ── 5. Decompress if needed ───────────────────────────────────────────
    if info["flags"] & _FLAG_COMPRESSED:
        log("Decompressing ...")
        decrypted = _decompress(decrypted)
        log(f"Decompressed: {len(decrypted):,} bytes")

    # ── 6. Write output with recovered extension ──────────────────────────
    base  = os.path.splitext(output_path)[0]
    ext   = info["extension"]
    final = f"{base}.{ext}" if ext else base

    try:
        with open(final, "wb") as fh:
            fh.write(decrypted)
    except OSError as exc:
        err(f"Cannot write output file: {exc}"); return False

    log(f"Saved: {final}")
    return True


# =============================================================================
# §8  UTILITIES & SELF-TEST
# =============================================================================

def print_profiles() -> None:
    safe_bps = math.log2(len(_SAFE_CHARS))
    print(f"\n  {'ID':<4} {'Profile':<12} {'Chars':>6} {'Bits/sym':>10} {'vs SAFE':>9}")
    print(f"  {'─'*4} {'─'*12} {'─'*6} {'─'*10} {'─'*9}")
    for pid in (PROFILE_SAFE, PROFILE_EXTENDED, PROFILE_MAX):
        info = profile_info(pid)
        mult = info["bits_per_sym"] / safe_bps
        print(
            f"  {pid:<4} {info['name']:<12} {info['size']:>6} "
            f"{info['bits_per_sym']:>10.3f} {mult:>8.2f}×"
        )
    print(f"\n  Length prefix overhead: {_PREFIX_SYMS} symbols (fixed)")
    print()


def estimate_cover_chars(file_bytes: int, profile_id: int,
                         compression_ratio: float = 0.65) -> int:
    """
    Estimate minimum cover text character count for the given file size.
    compression_ratio: assumed fraction after zlib (0.65 is conservative).
    """
    n_alpha  = len(_get_profile_chars(profile_id))
    bps      = math.log2(n_alpha)
    # header overhead (conservative): ~60 bytes
    payload  = int(file_bytes * compression_ratio) + 60
    n_syms   = math.ceil(8 * payload / bps) + _PREFIX_SYMS
    return n_syms + 2   # +2: we need (n_syms) gaps → (n_syms+1) chars minimum


def self_test(verbose: bool = True) -> bool:
    """Round-trip self-test for all three profiles. Returns True if all pass."""

    def log(msg: str) -> None:
        if verbose: print(f"    {msg}")

    print("\n  ── SELF-TEST ──────────────────────────────────────────────")
    password  = "TestP@ssw0rd!"
    test_data = b"The quick brown fox jumps over the lazy dog. " * 20 + os.urandom(80)

    # A cover text long enough for all profiles
    cover = (
        "In the beginning God created the heaven and the earth.  "
        "And the earth was without form, and void; and darkness was upon "
        "the face of the deep.  And the Spirit of God moved upon the face "
        "of the waters.  And God said, Let there be light: and there was light."
    ) * 40   # ~7 500 chars

    all_ok = True

    for profile_id in (PROFILE_SAFE, PROFILE_EXTENDED, PROFILE_MAX):
        pname = PROFILE_NAMES[profile_id]
        print(f"\n  Profile: {pname}")

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tf:
            tf.write(test_data)
            in_path = tf.name

        stego_path = in_path + "_stego.txt"
        out_base   = in_path + "_recovered"

        try:
            ok = encrypt_file_to_stego(
                in_path, password, cover, stego_path,
                profile_id, verbose=verbose,
            )
            if not ok:
                print(f"    [✗] Encryption failed"); all_ok = False; continue

            ok = decrypt_stego_file(
                stego_path, password, out_base, verbose=verbose,
            )
            if not ok:
                print(f"    [✗] Decryption failed"); all_ok = False; continue

            recovered_path = out_base + ".bin"
            with open(recovered_path, "rb") as fh:
                recovered = fh.read()

            if recovered == test_data:
                print(f"    [✓] Round-trip OK — {len(test_data):,} bytes verified")
            else:
                print(f"    [✗] Data mismatch!")
                all_ok = False

        finally:
            for p in [in_path, stego_path, out_base + ".bin"]:
                try:
                    os.remove(p)
                except OSError:
                    pass

    print(f"\n  {'All tests passed ✓' if all_ok else 'Some tests FAILED ✗'}")
    return all_ok


# =============================================================================
# §9  CLI — Interactive menu + argparse
# =============================================================================

_BANNER = r"""
  ╔══════════════════════════════════════════════════════════════╗
  ║      U N I C O D E   S T E G A N O G R A P H Y   V 2       ║
  ║   AES-256-GCM · PBKDF2-SHA256 · Base-N · Adaptive Profiles  ║
  ╚══════════════════════════════════════════════════════════════╝"""


def _read_cover_interactive() -> str:
    print("\n  Cover text source:")
    print("    [1] Load from file")
    print("    [2] Type / paste  (end with a line containing only '---')")
    src = input("  Choice [1/2]: ").strip()

    if src == "1":
        path = input("  Cover text file: ").strip()
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return fh.read()
        except OSError as exc:
            sys.exit(f"  [!] Cannot open cover file: {exc}")

    print("  Enter / paste cover text (finish with '---' on its own line):")
    lines: list = []
    while True:
        ln = input()
        if ln.strip() == "---":
            break
        lines.append(ln)
    return "\n".join(lines)


def _menu_encrypt() -> None:
    print("\n  ── ENCRYPT ──────────────────────────────────────────────────")
    password = input("  Password: ").strip()
    if not password:
        print("  [!] Password cannot be empty."); return

    in_path = input("  Input file to hide: ").strip()
    if not os.path.isfile(in_path):
        print(f"  [!] File not found: {in_path}"); return

    cover = _read_cover_interactive()

    print_profiles()
    p = input("  Profile [0=SAFE / 1=EXTENDED / 2=MAX, default 0]: ").strip()
    profile_id = int(p) if p in ("0", "1", "2") else PROFILE_SAFE

    file_sz = os.path.getsize(in_path)
    cap     = capacity_bytes(cover, profile_id)
    print(
        f"\n  Estimated payload after compress+encrypt: "
        f"~{int(file_sz * 0.65) + 60:,} bytes"
    )
    print(f"  Cover capacity [{PROFILE_NAMES[profile_id]}]: {cap:,} bytes")
    if int(file_sz * 0.65) + 60 > cap:
        print(
            "  [!] Cover text may be too short.  "
            "Consider a longer text or a higher profile."
        )

    out_path = input("  Output path (saved as .txt): ").strip()
    print()
    ok = encrypt_file_to_stego(in_path, password, cover, out_path, profile_id)
    print(f"\n  {'✓ Encryption complete!' if ok else '✗ Encryption failed.'}")


def _menu_decrypt() -> None:
    print("\n  ── DECRYPT ──────────────────────────────────────────────────")
    password   = input("  Password: ").strip()
    stego_path = input("  Stego .txt file: ").strip()
    if not os.path.isfile(stego_path):
        print(f"  [!] File not found: {stego_path}"); return
    out_path = input("  Output path (extension auto-detected): ").strip()
    print()
    ok = decrypt_stego_file(stego_path, password, out_path)
    print(f"\n  {'✓ Decryption complete!' if ok else '✗ Decryption failed.'}")


def _menu_info() -> None:
    print_profiles()
    s = input(
        "  Enter a file size in bytes to estimate required cover text "
        "(or Enter to skip): "
    ).strip()
    if s.isdigit():
        file_bytes = int(s)
        print(f"\n  Minimum cover text characters for a {file_bytes:,}-byte file:")
        for pid in (PROFILE_SAFE, PROFILE_EXTENDED, PROFILE_MAX):
            n = estimate_cover_chars(file_bytes, pid)
            print(f"    {PROFILE_NAMES[pid]:12s}: ≥ {n:,} characters")
    print()


def _interactive_menu() -> None:
    print(_BANNER)
    print()
    print("  [1]  Encrypt file  →  stego text")
    print("  [2]  Decrypt stego text  →  original file")
    print("  [3]  Profile & capacity info")
    print("  [4]  Self-test (round-trip benchmark)")
    print("  [Q]  Quit")
    choice = input("\n  Choice: ").strip().upper()

    dispatch = {
        "1": _menu_encrypt,
        "2": _menu_decrypt,
        "3": _menu_info,
        "4": lambda: self_test(verbose=True),
    }
    if choice in dispatch:
        dispatch[choice]()
    elif choice == "Q":
        sys.exit(0)
    else:
        print("  Invalid choice.")


def _build_argparser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stego_v2",
        description="Unicode Steganography V2 — hide files inside plain text",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python stego_v2.py encrypt secret.pdf cover.txt output --password mykey\n"
            "  python stego_v2.py decrypt output.txt recovered --password mykey\n"
            "  python stego_v2.py info --profile 2 --filesize 50000\n"
            "  python stego_v2.py test\n"
        ),
    )
    sub = parser.add_subparsers(dest="cmd")

    # ── encrypt ──
    enc = sub.add_parser("encrypt", help="Encrypt a file into a stego text")
    enc.add_argument("input",   help="File to hide")
    enc.add_argument("cover",   help="Cover text file (.txt)")
    enc.add_argument("output",  help="Output path (saved as .txt)")
    enc.add_argument("-p", "--password", required=True, help="Encryption password")
    enc.add_argument(
        "--profile", type=int, choices=[0, 1, 2], default=PROFILE_SAFE,
        metavar="N",
        help="Alphabet profile: 0=SAFE (10 chars), 1=EXTENDED (26), 2=MAX (122).  Default 0.",
    )
    enc.add_argument("-q", "--quiet", action="store_true", help="Suppress progress output")

    # ── decrypt ──
    dec = sub.add_parser("decrypt", help="Decrypt a stego text to recover the original file")
    dec.add_argument("stego",   help="Stego .txt file")
    dec.add_argument("output",  help="Output path (extension auto-detected from payload)")
    dec.add_argument("-p", "--password", required=True, help="Decryption password")
    dec.add_argument("-q", "--quiet", action="store_true", help="Suppress progress output")

    # ── info ──
    inf = sub.add_parser("info", help="Show alphabet profile details")
    inf.add_argument(
        "--profile", type=int, choices=[0, 1, 2], default=None,
        metavar="N", help="Specific profile to query (default: all)",
    )
    inf.add_argument(
        "--filesize", type=int, default=None,
        metavar="BYTES", help="Estimate required cover size for this file size",
    )

    # ── test ──
    sub.add_parser("test", help="Run a full round-trip self-test for all profiles")

    return parser


def main() -> None:
    # If arguments are provided, use argparse; otherwise fall back to the menu.
    if len(sys.argv) > 1:
        parser = _build_argparser()
        args   = parser.parse_args()

        if args.cmd == "encrypt":
            try:
                with open(args.cover, "r", encoding="utf-8") as fh:
                    cover = fh.read()
            except OSError as exc:
                sys.exit(f"[!] Cannot read cover file: {exc}")
            ok = encrypt_file_to_stego(
                args.input, args.password, cover, args.output,
                args.profile, verbose=not args.quiet,
            )
            sys.exit(0 if ok else 1)

        elif args.cmd == "decrypt":
            ok = decrypt_stego_file(
                args.stego, args.password, args.output,
                verbose=not args.quiet,
            )
            sys.exit(0 if ok else 1)

        elif args.cmd == "info":
            print(_BANNER)
            if args.profile is not None:
                pids = [args.profile]
            else:
                pids = [PROFILE_SAFE, PROFILE_EXTENDED, PROFILE_MAX]

            print_profiles()

            if args.filesize:
                print(f"  Minimum cover text chars for {args.filesize:,}-byte file:")
                for pid in pids:
                    n = estimate_cover_chars(args.filesize, pid)
                    print(f"    {PROFILE_NAMES[pid]:12s}: ≥ {n:,} chars")
                print()

        elif args.cmd == "test":
            ok = self_test(verbose=True)
            sys.exit(0 if ok else 1)

        else:
            _build_argparser().print_help()

    else:
        _interactive_menu()


if __name__ == "__main__":
    main()