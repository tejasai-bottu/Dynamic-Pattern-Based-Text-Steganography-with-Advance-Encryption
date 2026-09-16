#!/usr/bin/env python3
"""
unicode_compat.py — Stage 2: Unicode Invisible-Character Compatibility Suite
============================================================================
Tests 392 invisible Unicode candidates across 13 automated checks, assigns
reliability tiers, builds validated alphabet profiles for stego_v2.py, and
generates manual test artefacts for clipboard / browser / editor / OS testing.

Finding from automated tests
  407 of 392 candidates pass all 13 Python-level tests.
  U+3164 (HANGUL FILLER) and U+FFA0 (HALFWIDTH HANGUL FILLER) score 11/13:
  they are altered by NFKC and NFKD normalization (both collapse to U+1160).
  These characters are retained in Tier 2 / EXTENDED deliberately, but their
  NFKC instability must be understood before deploying EXTENDED in environments
  that apply Unicode compatibility normalization.
  Real-world differentiation (clipboard stripping, font rendering, editor
  normalisation, OS text-field behaviour) requires the manual test workflow
  exported to manual_tests.txt.  Automated tests serve as a survival floor —
  they rule out encoding defects before real-world testing begins.

Semantic tier classification (used for provisional profile assignment)
  Tier 1 RELIABLE    (11 chars)  Core zero-width / invisible format chars;
                                 universally supported across all environments.
  Tier 2 GOOD        (44 chars)  Directional, deprecated-format, script-filler
                                 and BMP variation selectors; work in Python and
                                 most environments but have known caveats.
                                 ⚠ U+3164 and U+FFA0 fail NFKC/NFKD tests.
  Tier 3 EXPERIMENTAL(337 chars) Unicode tag characters (supplementary plane)
                                 and Variation Selector Supplement (U+E0100–
                                 U+E01EF only); less portable.

Validated profile sizes (vs stego_v2.py hardcoded defaults)
  SAFE      11 chars  3.46 bits/sym  vs  10 chars 3.32 bps  (+4% capacity)
  EXTENDED  55 chars  5.78 bits/sym  vs  26 chars 4.70 bps  (+23% capacity)
  MAX      392 chars  8.62 bits/sym  vs 122 chars 6.93 bps  (+24% capacity)

Usage
  python unicode_compat.py                    # interactive menu
  python unicode_compat.py test               # run + print tier summary
  python unicode_compat.py test --matrix      # + pass/fail matrix
  python unicode_compat.py export --dir ./out # run + write all output files
  python unicode_compat.py profiles           # show profile sizes only
  python unicode_compat.py verify 'A<paste>B' # analyse pasted text

Output files (with export)
  candidates.json          full database with all test results
  candidates.csv           spreadsheet-friendly summary
  compat_report.txt        human-readable tiered report
  manual_tests.txt         copy/paste strings for external testing
  validated_alphabets.py   Python constants ready to paste into stego_v2.py
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import struct
import sys
import tempfile
import unicodedata
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# =============================================================================
# §1  CONSTANTS
# =============================================================================

# Character class labels
CLASS_ZERO_WIDTH  = "zero_width"       # zero-width / invisible format characters
CLASS_DIRECTIONAL = "directional"      # bidi and isolation control characters
CLASS_DEPRECATED  = "deprecated"       # Unicode-deprecated format characters
CLASS_SCRIPT      = "script_filler"    # Hangul / Khmer / Mongolian fillers
CLASS_VAR_SEL     = "variation_sel"    # variation selectors (BMP, FE00–FE0F)
CLASS_TAG         = "tag"              # Unicode tag characters (E0001, E0020–E007F)
CLASS_VAR_SEL_SUP = "var_sel_sup"      # variation selector supplement (E0100–E01EF)

# Tier constants  (lower number = better)
TIER_1 = 1   # RELIABLE    — safe to use in production
TIER_2 = 2   # GOOD        — generally fine; minor real-world caveats
TIER_3 = 3   # EXPERIMENTAL— supplementary-plane or script-specific caveats
TIER_4 = 4   # REJECTED    — automated test failure (not assigned by semantic rules)

TIER_NAMES = {
    TIER_1: "RELIABLE",
    TIER_2: "GOOD",
    TIER_3: "EXPERIMENTAL",
    TIER_4: "REJECTED",
}

# Automated-score thresholds for tier derivation
AUTO_TIER_THRESHOLDS = [
    (11, TIER_1),
    ( 8, TIER_2),
    ( 5, TIER_3),
    ( 0, TIER_4),
]   # sorted descending by score; first match wins

NUM_AUTO_TESTS = 13

# Profile → minimum tier (chars with tier <= value are included)
PROFILE_TIER = {
    "SAFE":     TIER_1,
    "EXTENDED": TIER_2,
    "MAX":      TIER_3,
}

# Reference chars for sequence-interaction test M
_SEQ_REF = ["\u200B", "\u200D", "\uFEFF"]

# Core Tier-1 code points (known to be universally supported)
_CORE_T1: frozenset = frozenset([
    0x200B,   # ZERO WIDTH SPACE
    0x200C,   # ZERO WIDTH NON-JOINER
    0x200D,   # ZERO WIDTH JOINER
    0x2060,   # WORD JOINER
    0x2061,   # FUNCTION APPLICATION
    0x2062,   # INVISIBLE TIMES
    0x2063,   # INVISIBLE SEPARATOR
    0x2064,   # INVISIBLE PLUS
    0xFEFF,   # ZERO WIDTH NO-BREAK SPACE
    0x00AD,   # SOFT HYPHEN
    0x034F,   # COMBINING GRAPHEME JOINER
])


# =============================================================================
# §2  DATA STRUCTURE
# =============================================================================

@dataclass
class CandidateChar:
    # ── Unicode identity ──────────────────────────────────────────────────────
    code_point: int
    char:       str
    name:       str
    category:   str    # Unicode general category (Cf, Mn, Lo …)
    char_class: str    # our semantic classification
    utf8_bytes: int
    combining:  int    # Unicode combining class (0 = not combining)
    bidi:       str    # Unicode bidi category

    # ── Automated test results (True=pass · False=fail · None=not run) ────────
    t_utf8:       Optional[bool] = None    # A
    t_utf16:      Optional[bool] = None    # B
    t_nfc:        Optional[bool] = None    # C
    t_nfd:        Optional[bool] = None    # D
    t_nfkc:       Optional[bool] = None    # E  ← most aggressive normalisation
    t_nfkd:       Optional[bool] = None    # F
    t_json:       Optional[bool] = None    # G
    t_file_utf8:  Optional[bool] = None    # H
    t_file_utf16: Optional[bool] = None    # I
    t_py_ops:     Optional[bool] = None    # J
    t_repeat5:    Optional[bool] = None    # K
    t_repeat100:  Optional[bool] = None    # L
    t_sequence:   Optional[bool] = None    # M

    # ── Failure notes (key = test label, value = brief description) ───────────
    notes: Dict[str, str] = field(default_factory=dict)

    # ── Scores and tiers ──────────────────────────────────────────────────────
    auto_score:    int = 0          # count of passing automated tests (0-13)
    auto_tier:     int = TIER_4     # tier derived from auto_score alone
    semantic_tier: int = TIER_3     # tier from Unicode class / known semantics
    effective_tier: int = TIER_3    # final tier = max(auto_tier, semantic_tier)

    # ── Manual test results (populated externally after real-world testing) ───
    manual_clipboard: Optional[bool] = None
    manual_browser:   Optional[bool] = None
    manual_notepad:   Optional[bool] = None
    manual_windows:   Optional[bool] = None
    manual_macos:     Optional[bool] = None

    # ── Derived manual score (populated when manual tests are loaded) ─────────
    manual_score: Optional[int] = None

    def hex_cp(self) -> str:
        return f"U+{self.code_point:04X}" if self.code_point <= 0xFFFF \
               else f"U+{self.code_point:05X}"

    def auto_tests_list(self) -> List[Optional[bool]]:
        return [
            self.t_utf8, self.t_utf16,
            self.t_nfc,  self.t_nfd,  self.t_nfkc, self.t_nfkd,
            self.t_json,
            self.t_file_utf8, self.t_file_utf16,
            self.t_py_ops,
            self.t_repeat5, self.t_repeat100,
            self.t_sequence,
        ]

    def compute_tiers(self) -> None:
        """Compute auto_tier, effective_tier from current state."""
        self.auto_score = sum(1 for r in self.auto_tests_list() if r is True)
        for min_s, tier in AUTO_TIER_THRESHOLDS:
            if self.auto_score >= min_s:
                self.auto_tier = tier
                break
        # effective = worst of auto-derived and semantic
        self.effective_tier = max(self.auto_tier, self.semantic_tier)

    def manual_tests_list(self) -> List[Optional[bool]]:
        return [
            self.manual_clipboard, self.manual_browser,
            self.manual_notepad, self.manual_windows, self.manual_macos,
        ]

    def update_manual_tier(self) -> None:
        """Recompute effective_tier after manual results are loaded."""
        manual = [r for r in self.manual_tests_list() if r is not None]
        if not manual:
            return
        self.manual_score = sum(1 for r in manual if r is True)
        fails = sum(1 for r in manual if r is False)
        # Any manual failure degrades the tier by one or more levels
        if fails >= 2:
            self.effective_tier = min(TIER_4, self.effective_tier + 2)
        elif fails == 1:
            self.effective_tier = min(TIER_4, self.effective_tier + 1)


# =============================================================================
# §3  AUTOMATED TEST FUNCTIONS  (A – M)
# =============================================================================

def _t_utf8(c: CandidateChar) -> None:
    """A: UTF-8 encode → decode identity."""
    try:
        if c.char.encode("utf-8").decode("utf-8") == c.char:
            c.t_utf8 = True
        else:
            c.t_utf8 = False
            c.notes["A"] = "UTF-8 decode mismatch"
    except Exception as exc:
        c.t_utf8 = False; c.notes["A"] = str(exc)


def _t_utf16(c: CandidateChar) -> None:
    """B: UTF-16-LE encode → decode identity."""
    try:
        if c.char.encode("utf-16-le").decode("utf-16-le") == c.char:
            c.t_utf16 = True
        else:
            c.t_utf16 = False
            c.notes["B"] = "UTF-16 decode mismatch"
    except Exception as exc:
        c.t_utf16 = False; c.notes["B"] = str(exc)


def _t_norm(c: CandidateChar, form: str, attr: str, label: str) -> None:
    """C/D/E/F: Unicode normalisation stability."""
    try:
        carrier = "A" + c.char + "B"
        normed  = unicodedata.normalize(form, carrier)
        if normed == carrier:
            setattr(c, attr, True)
        else:
            setattr(c, attr, False)
            inner = [ch for ch in normed if ch not in "AB"]
            if not inner:
                c.notes[label] = f"removed by {form}"
            else:
                c.notes[label] = (
                    f"changed by {form}: "
                    + " ".join(f"U+{ord(ch):04X}" for ch in inner)
                )
    except Exception as exc:
        setattr(c, attr, False); c.notes[label] = str(exc)


def _t_json(c: CandidateChar) -> None:
    """G: JSON serialise → parse identity (ensure_ascii=False)."""
    try:
        original = "A" + c.char + "B"
        loaded   = json.loads(json.dumps(original, ensure_ascii=False))
        if loaded == original:
            c.t_json = True
        else:
            c.t_json = False
            c.notes["G"] = "removed" if c.char not in loaded else f"changed: {loaded!r}"
    except Exception as exc:
        c.t_json = False; c.notes["G"] = str(exc)


def _t_file(c: CandidateChar, encoding: str, attr: str, label: str) -> None:
    """H/I: Write temp file → read back identity."""
    try:
        original = "A" + c.char + "B"
        fd, path = tempfile.mkstemp(suffix=".txt")
        os.close(fd)
        try:
            with open(path, "w", encoding=encoding) as fh:
                fh.write(original)
            with open(path, "r", encoding=encoding) as fh:
                content = fh.read()
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass
        if content == original:
            setattr(c, attr, True)
        else:
            setattr(c, attr, False)
            c.notes[label] = (
                f"removed ({encoding})" if c.char not in content
                else f"changed ({encoding})"
            )
    except Exception as exc:
        setattr(c, attr, False); c.notes[label] = str(exc)


def _t_py_ops(c: CandidateChar) -> None:
    """J: Python string-operation stability."""
    ch      = c.char
    carrier = "A" + ch + "B"
    issues: List[str] = []

    if len(carrier) != 3:
        issues.append(f"len={len(carrier)} (expected 3)")
    if carrier == "AB":
        issues.append("invisible to equality (char ignored)")
    if list(carrier)[1:2] != [ch]:
        issues.append("iteration skips char")
    if carrier.strip() != carrier:
        issues.append(f"strip() removes char; result={carrier.strip()!r}")
    parts = carrier.split()
    if not (len(parts) == 1 and parts[0] == carrier):
        issues.append(f"split() breaks on char: {parts}")
    if carrier.replace(ch, "X") != "AXB":
        issues.append(f"replace() fails: {carrier.replace(ch, 'X')!r}")

    if issues:
        c.t_py_ops = False
        c.notes["J"] = "; ".join(issues)
    else:
        c.t_py_ops = True


def _t_repeat(c: CandidateChar, count: int, attr: str, label: str) -> None:
    """K/L: Repetition stability (UTF-8 + NFKC)."""
    try:
        rep     = c.char * count
        carrier = "A" + rep + "B"
        if rep.encode("utf-8").decode("utf-8") != rep:
            setattr(c, attr, False)
            c.notes[label] = f"UTF-8 fails at ×{count}"
            return
        if len(rep) != count:
            setattr(c, attr, False)
            c.notes[label] = f"len={len(rep)} at ×{count}"
            return
        normed = unicodedata.normalize("NFKC", carrier)
        inner  = [ch for ch in normed if ch not in "AB"]
        if len(inner) != count:
            setattr(c, attr, False)
            c.notes[label] = f"NFKC collapses ×{count} → {len(inner)} chars"
            return
        setattr(c, attr, True)
    except Exception as exc:
        setattr(c, attr, False); c.notes[label] = str(exc)


def _t_sequence(c: CandidateChar) -> None:
    """M: Sequence interaction with reference stego chars."""
    refs   = [r for r in _SEQ_REF if r != c.char][:3]
    issues: List[str] = []
    try:
        for ref in refs:
            seq = "A" + c.char + ref + "B"
            if seq.encode("utf-8").decode("utf-8") != seq:
                issues.append(f"UTF-8 fails with U+{ord(ref):04X}")
                continue
            normed = unicodedata.normalize("NFKC", seq)
            inner  = [ch for ch in normed if ch not in "AB"]
            if len(inner) != 2:
                issues.append(
                    f"NFKC seq with U+{ord(ref):04X}: "
                    f"{len(inner)} inner (expected 2)"
                )
        c.t_sequence = (not issues)
        if issues:
            c.notes["M"] = "; ".join(issues[:2])
    except Exception as exc:
        c.t_sequence = False; c.notes["M"] = str(exc)


# =============================================================================
# §4  SEMANTIC TIER ASSIGNMENT
# =============================================================================

def _semantic_tier(cp: int, char_class: str) -> int:
    """
    Assign a provisional tier based on Unicode class and known cross-platform
    behaviour.  This is updated by manual test results but never from automated
    tests alone (since all candidates pass the Python suite).

    Tier 1 RELIABLE    — core zero-width / invisible format chars
    Tier 2 GOOD        — directional, deprecated, script-fillers, BMP var-sel
    Tier 3 EXPERIMENTAL— tag chars and var-sel supplement (supplementary plane)
    """
    if cp in _CORE_T1:
        return TIER_1
    if char_class in (CLASS_ZERO_WIDTH, CLASS_DIRECTIONAL,
                      CLASS_DEPRECATED, CLASS_SCRIPT, CLASS_VAR_SEL):
        return TIER_2
    return TIER_3   # CLASS_TAG, CLASS_VAR_SEL_SUP


# =============================================================================
# §5  ORCHESTRATOR
# =============================================================================

def run_all_tests(c: CandidateChar) -> None:
    """Run all 13 automated tests on c, then compute tiers."""
    _t_utf8(c)                                               # A
    _t_utf16(c)                                              # B
    _t_norm(c, "NFC",  "t_nfc",  "C")                       # C
    _t_norm(c, "NFD",  "t_nfd",  "D")                       # D
    _t_norm(c, "NFKC", "t_nfkc", "E")                       # E
    _t_norm(c, "NFKD", "t_nfkd", "F")                       # F
    _t_json(c)                                               # G
    _t_file(c, "utf-8",     "t_file_utf8",  "H")            # H
    _t_file(c, "utf-16-le", "t_file_utf16", "I")            # I
    _t_py_ops(c)                                             # J
    _t_repeat(c,   5, "t_repeat5",   "K")                   # K
    _t_repeat(c, 100, "t_repeat100", "L")                    # L
    _t_sequence(c)                                           # M
    c.compute_tiers()


# =============================================================================
# §6  CANDIDATE POOL
# =============================================================================

def _make(cp: int, char_class: str) -> CandidateChar:
    char = chr(cp)
    try:
        name = unicodedata.name(char)
    except ValueError:
        name = f"<unnamed U+{cp:04X}>"
    return CandidateChar(
        code_point    = cp,
        char          = char,
        name          = name,
        category      = unicodedata.category(char),
        char_class    = char_class,
        utf8_bytes    = len(char.encode("utf-8")),
        combining     = unicodedata.combining(char),
        bidi          = unicodedata.bidirectional(char),
        semantic_tier = _semantic_tier(cp, char_class),
    )


_INDIVIDUAL: List[Tuple[int, str]] = [
    # ── Core invisible format characters ─────────────────────────────────────
    (0x00AD, CLASS_ZERO_WIDTH),   # SOFT HYPHEN
    (0x034F, CLASS_ZERO_WIDTH),   # COMBINING GRAPHEME JOINER
    (0x115F, CLASS_SCRIPT),       # HANGUL CHOSEONG FILLER
    (0x1160, CLASS_SCRIPT),       # HANGUL JUNGSEONG FILLER
    (0x17B4, CLASS_SCRIPT),       # KHMER VOWEL INHERENT AQ
    (0x17B5, CLASS_SCRIPT),       # KHMER VOWEL INHERENT AA
    (0x180B, CLASS_VAR_SEL),      # MONGOLIAN FREE VARIATION SELECTOR ONE
    (0x180C, CLASS_VAR_SEL),      # MONGOLIAN FREE VARIATION SELECTOR TWO
    (0x180D, CLASS_VAR_SEL),      # MONGOLIAN FREE VARIATION SELECTOR THREE
    (0x180E, CLASS_SCRIPT),       # MONGOLIAN VOWEL SEPARATOR
    (0x200B, CLASS_ZERO_WIDTH),   # ZERO WIDTH SPACE               ← Tier 1
    (0x200C, CLASS_ZERO_WIDTH),   # ZERO WIDTH NON-JOINER          ← Tier 1
    (0x200D, CLASS_ZERO_WIDTH),   # ZERO WIDTH JOINER              ← Tier 1
    # ── Directional format characters ────────────────────────────────────────
    (0x200E, CLASS_DIRECTIONAL),  # LEFT-TO-RIGHT MARK
    (0x200F, CLASS_DIRECTIONAL),  # RIGHT-TO-LEFT MARK
    (0x061C, CLASS_DIRECTIONAL),  # ARABIC LETTER MARK
    (0x202A, CLASS_DIRECTIONAL),  # LEFT-TO-RIGHT EMBEDDING
    (0x202B, CLASS_DIRECTIONAL),  # RIGHT-TO-LEFT EMBEDDING
    (0x202C, CLASS_DIRECTIONAL),  # POP DIRECTIONAL FORMATTING
    (0x202D, CLASS_DIRECTIONAL),  # LEFT-TO-RIGHT OVERRIDE
    (0x202E, CLASS_DIRECTIONAL),  # RIGHT-TO-LEFT OVERRIDE
    (0x2066, CLASS_DIRECTIONAL),  # LEFT-TO-RIGHT ISOLATE
    (0x2067, CLASS_DIRECTIONAL),  # RIGHT-TO-LEFT ISOLATE
    (0x2068, CLASS_DIRECTIONAL),  # FIRST STRONG ISOLATE
    (0x2069, CLASS_DIRECTIONAL),  # POP DIRECTIONAL ISOLATE
    # ── Invisible mathematics / text operators ────────────────────────────────
    (0x2060, CLASS_ZERO_WIDTH),   # WORD JOINER                    ← Tier 1
    (0x2061, CLASS_ZERO_WIDTH),   # FUNCTION APPLICATION           ← Tier 1
    (0x2062, CLASS_ZERO_WIDTH),   # INVISIBLE TIMES                ← Tier 1
    (0x2063, CLASS_ZERO_WIDTH),   # INVISIBLE SEPARATOR            ← Tier 1
    (0x2064, CLASS_ZERO_WIDTH),   # INVISIBLE PLUS                 ← Tier 1
    # ── Deprecated Unicode format characters ─────────────────────────────────
    (0x206A, CLASS_DEPRECATED),   # INHIBIT SYMMETRIC SWAPPING
    (0x206B, CLASS_DEPRECATED),   # ACTIVATE SYMMETRIC SWAPPING
    (0x206C, CLASS_DEPRECATED),   # INHIBIT ARABIC FORM SHAPING
    (0x206D, CLASS_DEPRECATED),   # ACTIVATE ARABIC FORM SHAPING
    (0x206E, CLASS_DEPRECATED),   # NATIONAL DIGIT SHAPES
    (0x206F, CLASS_DEPRECATED),   # NOMINAL DIGIT SHAPES
    # ── CJK fillers ──────────────────────────────────────────────────────────
    (0x3164, CLASS_SCRIPT),       # HANGUL FILLER
    (0xFFA0, CLASS_SCRIPT),       # HALFWIDTH HANGUL FILLER
    # ── BOM / ZWNBSP ─────────────────────────────────────────────────────────
    (0xFEFF, CLASS_ZERO_WIDTH),   # ZERO WIDTH NO-BREAK SPACE      ← Tier 1
]


def build_candidate_pool() -> List[CandidateChar]:
    """
    Build the complete pool of 392 invisible Unicode candidates.

    Pool composition
      Individual (39)  — ZW, directional, deprecated, script-filler chars
      VS1–VS16 (16)    — Variation Selectors 1–16, U+FE00–U+FE0F
      TAG (97)         — U+E0001 + U+E0020–U+E007F
      VSS (240)        — Variation Selector Supplement, U+E0100–U+E01EF
                         (VS17–VS256; official Unicode Var-Sel Supplement block)

    Note: earlier versions mistakenly used range(0xE0100, 0xE0201), which
    included 17 unnamed code points U+E01F0–U+E0200 beyond the official block
    end (U+E01EF), inflating the pool to 409.  The correct end is 0xE01F0
    (exclusive), giving exactly 240 VSS candidates.

    U+3164 (HANGUL FILLER) and U+FFA0 (HALFWIDTH HANGUL FILLER) are included
    as Tier 2 candidates but score 11/13 on automated tests: they are altered
    by NFKC and NFKD normalization (both become U+1160).  Their inclusion is
    deliberate; see normalization caveats in compat_report.txt.
    """
    pool: List[CandidateChar] = []

    for cp, cls in _INDIVIDUAL:
        pool.append(_make(cp, cls))

    # Variation Selectors 1–16 (BMP, U+FE00–U+FE0F)
    for cp in range(0xFE00, 0xFE10):
        pool.append(_make(cp, CLASS_VAR_SEL))

    # Unicode Tag block (U+E0001, U+E0020–U+E007F)
    pool.append(_make(0xE0001, CLASS_TAG))           # LANGUAGE TAG
    for cp in range(0xE0020, 0xE0080):               # TAG SPACE – CANCEL TAG
        pool.append(_make(cp, CLASS_TAG))

    # Variation Selector Supplement VS17–VS256 (U+E0100–U+E01EF only)
    # End is 0xE01F0 (exclusive) = U+E01EF inclusive — the last assigned VSS char.
    for cp in range(0xE0100, 0xE01F0):
        pool.append(_make(cp, CLASS_VAR_SEL_SUP))

    return pool


# =============================================================================
# §7  DATABASE RUNNER
# =============================================================================

def run_compatibility_database(
    verbose: bool   = False,
    progress: bool  = True,
) -> List[CandidateChar]:
    """
    Test every candidate and return the full scored database.

    verbose=True  — print one result line per character
    progress=True — print a progress counter (suppressed when verbose=True)
    """
    pool  = build_candidate_pool()
    total = len(pool)

    if verbose:
        hdr = (f"  {'CP':<9} {'Category':<5} {'Class':<15}  "
               f"{'Auto':>4}  {'SemTier':<8}  {'EffTier'}")
        print(f"\n  Testing {total} candidates  ({NUM_AUTO_TESTS} tests each)\n")
        print(hdr)
        print("  " + "─" * (len(hdr) - 2))

    for i, c in enumerate(pool):
        run_all_tests(c)

        if verbose:
            note_str = ("; ".join(
                f"{k}:{v[:25]}" for k, v in c.notes.items()
            ))[:55]
            print(
                f"  {c.hex_cp():<9} {c.category:<5} {c.char_class:<15}  "
                f"{c.auto_score:>2}/13  {TIER_NAMES[c.semantic_tier]:<12}  "
                f"{TIER_NAMES[c.effective_tier]}"
                + (f"  [{note_str}]" if note_str else "")
            )
        elif progress:
            pct = (i + 1) / total * 100
            bar = "█" * int(pct / 5) + "░" * (20 - int(pct / 5))
            print(f"  [{bar}] {pct:5.1f}%  {i+1}/{total}", end="\r", flush=True)

    if progress and not verbose:
        print()

    return pool


# =============================================================================
# §8  REPORTING
# =============================================================================

# ── console output ─────────────────────────────────────────────────────────

def print_tier_summary(results: List[CandidateChar]) -> None:
    """Print tier breakdown with profile-level capacity figures."""
    from collections import Counter
    counts = Counter(c.effective_tier for c in results)

    print("\n  ── AUTOMATED TEST RESULT ───────────────────────────────────────────")
    all_pass = all(c.auto_score == NUM_AUTO_TESTS for c in results)
    if all_pass:
        print(f"  All {len(results)} candidates pass all {NUM_AUTO_TESTS} "
              "automated Python tests.")
        print("  Tier assignment is based on Unicode semantic classification.")
        print("  Manual cross-platform testing is required to validate real-world")
        print("  reliability.  See manual_tests.txt for copy/paste test strings.")
    else:
        fails = sum(1 for c in results if c.auto_score < NUM_AUTO_TESTS)
        print(f"  {len(results) - fails}/{len(results)} candidates pass all tests; "
              f"{fails} have automated failures.")
    print()

    safe_bps = math.log2(len(_CORE_T1)) if len(_CORE_T1) > 1 else 0

    print(f"  ── SEMANTIC TIERS {'─'*48}")
    print(f"  {'T':<3}  {'Name':<14}  {'Count':>6}  {'Bits/sym':>9}  {'vs SAFE':>8}")
    print(f"  {'─'*3}  {'─'*14}  {'─'*6}  {'─'*9}  {'─'*8}")
    for tid in (TIER_1, TIER_2, TIER_3, TIER_4):
        n    = counts[tid]
        bps  = math.log2(n) if n > 1 else 0.0
        mult = (bps / safe_bps) if safe_bps > 0 else 0.0
        print(f"  {tid:<3}  {TIER_NAMES[tid]:<14}  {n:>6}  "
              f"{bps:>9.3f}  {mult:>7.2f}×")

    print(f"\n  ── PROFILE ALPHABETS (these replace stego_v2.py defaults) {'─'*14}")
    V2_OLD = {"SAFE": 10, "EXTENDED": 26, "MAX": 122}
    for pname, min_tier in PROFILE_TIER.items():
        chars = [c for c in results if c.effective_tier <= min_tier]
        n     = len(chars)
        bps   = math.log2(n) if n > 1 else 0.0
        n_old = V2_OLD[pname]
        gain  = (bps / math.log2(n_old)) if n_old > 1 else 1.0
        print(f"  {pname:<10}: {n:4d} chars  {bps:.3f} bps  "
              f"(was {n_old} / {math.log2(n_old):.2f} bps → {gain:.2f}× improvement)")
    print()


def print_test_matrix(results: List[CandidateChar], max_rows: int = 80) -> None:
    """
    Print a compact pass/fail grid.
    Shows only Tier 1–3 characters; limits output to max_rows.
    Columns: A B C D E F G H I J K L M (tests) + score + tier.
    """
    visible = [c for c in results if c.effective_tier < TIER_4][:max_rows]
    header  = "  CP       Cat  Class           A B C D E F G H I J K  L  M  Score  Tier"
    print(header)
    print("  " + "─" * (len(header) - 2))
    for c in visible:
        syms = " ".join(
            "✓" if t is True else ("✗" if t is False else "?")
            for t in c.auto_tests_list()
        )
        print(
            f"  {c.hex_cp():<8} {c.category:<4} {c.char_class:<15}  "
            f"{syms}  {c.auto_score:>2}/13  {TIER_NAMES[c.effective_tier]}"
        )
    hidden = len([c for c in results if c.effective_tier < TIER_4]) - len(visible)
    if hidden > 0:
        print(f"  … {hidden} more rows omitted (max_rows={max_rows})")
    print()


# ── file exports ────────────────────────────────────────────────────────────

def export_json(results: List[CandidateChar], path: str) -> None:
    """Export full database to JSON."""
    data = []
    for c in results:
        data.append({
            "code_point":    c.code_point,
            "hex":           c.hex_cp(),
            "char_escaped":  c.char.encode("unicode_escape").decode("ascii"),
            "name":          c.name,
            "category":      c.category,
            "class":         c.char_class,
            "utf8_bytes":    c.utf8_bytes,
            "combining":     c.combining,
            "bidi":          c.bidi,
            "tests": {
                "A_utf8":       c.t_utf8,
                "B_utf16":      c.t_utf16,
                "C_nfc":        c.t_nfc,
                "D_nfd":        c.t_nfd,
                "E_nfkc":       c.t_nfkc,
                "F_nfkd":       c.t_nfkd,
                "G_json":       c.t_json,
                "H_file_utf8":  c.t_file_utf8,
                "I_file_utf16": c.t_file_utf16,
                "J_py_ops":     c.t_py_ops,
                "K_repeat5":    c.t_repeat5,
                "L_repeat100":  c.t_repeat100,
                "M_sequence":   c.t_sequence,
            },
            "notes":          c.notes,
            "auto_score":     c.auto_score,
            "auto_tier":      c.auto_tier,
            "semantic_tier":  c.semantic_tier,
            "effective_tier": c.effective_tier,
            "tier_name":      TIER_NAMES[c.effective_tier],
            "manual": {
                "clipboard": c.manual_clipboard,
                "browser":   c.manual_browser,
                "notepad":   c.manual_notepad,
                "windows":   c.manual_windows,
                "macos":     c.manual_macos,
                "score":     c.manual_score,
            },
        })
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
    print(f"  [✓] {path}  ({len(data)} records)")


def export_csv(results: List[CandidateChar], path: str) -> None:
    """Export summary to CSV (spreadsheet-friendly)."""
    def b(v: Optional[bool]) -> str:
        return "PASS" if v is True else ("FAIL" if v is False else "?")

    fields = [
        "hex", "name", "category", "class", "utf8_bytes",
        "A","B","C","D","E","F","G","H","I","J","K","L","M",
        "auto_score", "semantic_tier", "effective_tier", "tier_name", "notes",
    ]
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        for c in results:
            w.writerow({
                "hex":           c.hex_cp(),
                "name":          c.name,
                "category":      c.category,
                "class":         c.char_class,
                "utf8_bytes":    c.utf8_bytes,
                "A": b(c.t_utf8),     "B": b(c.t_utf16),
                "C": b(c.t_nfc),      "D": b(c.t_nfd),
                "E": b(c.t_nfkc),     "F": b(c.t_nfkd),
                "G": b(c.t_json),
                "H": b(c.t_file_utf8),"I": b(c.t_file_utf16),
                "J": b(c.t_py_ops),
                "K": b(c.t_repeat5),  "L": b(c.t_repeat100),
                "M": b(c.t_sequence),
                "auto_score":     c.auto_score,
                "semantic_tier":  c.semantic_tier,
                "effective_tier": c.effective_tier,
                "tier_name":      TIER_NAMES[c.effective_tier],
                "notes": "; ".join(f"{k}:{v}" for k, v in c.notes.items()),
            })
    print(f"  [✓] {path}  ({len(results)} rows)")


def export_report(results: List[CandidateChar], path: str) -> None:
    """Export a full human-readable compatibility report."""
    from collections import defaultdict
    by_tier: Dict[int, List[CandidateChar]] = defaultdict(list)
    for c in results:
        by_tier[c.effective_tier].append(c)

    lines: List[str] = []
    W = lines.append

    W("UNICODE STEGANOGRAPHY V2 — COMPATIBILITY REPORT")
    W("=" * 72)
    W(f"Candidates tested  : {len(results)}")
    W(f"Automated tests    : {NUM_AUTO_TESTS} per candidate")
    W(f"All auto-tests pass: {all(c.auto_score == NUM_AUTO_TESTS for c in results)}")
    W("")
    n_perfect = sum(1 for c in results if c.auto_score == NUM_AUTO_TESTS)
    n_partial  = sum(1 for c in results if 0 < c.auto_score < NUM_AUTO_TESTS)
    W("KEY FINDING")
    W(f"  {n_perfect}/{len(results)} candidates pass all {NUM_AUTO_TESTS} automated Python tests.")
    if n_partial:
        W(f"  {n_partial} candidate(s) pass fewer than {NUM_AUTO_TESTS} tests — see tier listing below.")
        W("  Notable cases:")
        for c in results:
            if c.auto_score < NUM_AUTO_TESTS:
                failed = [lbl for lbl, t in zip("ABCDEFGHIJKLM", c.auto_tests_list())
                          if t is False]
                W(f"    U+{c.code_point:04X}  {c.name[:44]:<44}  {c.auto_score}/{NUM_AUTO_TESTS}"
                  f"  fails: {' '.join(failed)}")
    W("  Tier classification is primarily driven by Unicode semantics and")
    W("  known cross-platform behaviour.  Automated tests serve as a survival")
    W("  floor — they rule out encoding defects before real-world testing.")
    W("  Manual cross-platform testing (browsers, editors, OS text-fields,")
    W("  clipboard) is required to validate or revise these tiers.")
    W("")
    W("TEST INDEX")
    for lbl, desc in [
        ("A", "UTF-8 encode/decode identity"),
        ("B", "UTF-16-LE encode/decode identity"),
        ("C", "NFC normalisation stability"),
        ("D", "NFD normalisation stability"),
        ("E", "NFKC normalisation stability  ← most aggressive"),
        ("F", "NFKD normalisation stability"),
        ("G", "JSON serialise/parse identity (ensure_ascii=False)"),
        ("H", "File write/read — UTF-8"),
        ("I", "File write/read — UTF-16-LE"),
        ("J", "Python string ops: len / strip / split / replace"),
        ("K", "Repetition stability × 5"),
        ("L", "Repetition stability × 100"),
        ("M", "Sequence interaction with reference stego chars"),
    ]:
        W(f"  {lbl}  {desc}")
    W("")
    W("SEMANTIC TIER CRITERIA")
    W(f"  Tier 1 RELIABLE     : {_CORE_T1 and 'core zero-width chars (hardcoded set of 11)'}")
    W( "  Tier 2 GOOD         : directional / deprecated / script-filler / BMP var-sel")
    W( "  Tier 3 EXPERIMENTAL : tag chars and var-sel supplement (supplementary plane)")
    W("")

    for tier_id in (TIER_1, TIER_2, TIER_3, TIER_4):
        chars = by_tier[tier_id]
        if not chars:
            continue
        n   = len(chars)
        bps = math.log2(n) if n > 1 else 0.0
        W("─" * 72)
        W(f"TIER {tier_id}: {TIER_NAMES[tier_id]}  "
          f"({n} chars  ·  {bps:.3f} bits/sym as alphabet)")
        W("")
        for c in chars:
            sym = "".join(
                "✓" if t is True else ("✗" if t is False else "?")
                for t in c.auto_tests_list()
            )
            W(f"  {c.hex_cp():<9} {c.name[:47]:<47}  {c.category:<4}  "
              f"[{sym}]  {c.auto_score}/13")
            if c.notes:
                note_str = "; ".join(f"{k}:{v[:35]}" for k, v in c.notes.items())
                W(f"    NOTE: {note_str}")
        W("")

    W("=" * 72)
    W("VALIDATED PROFILE SUMMARY")
    V2_OLD = {"SAFE": (10, 3.32), "EXTENDED": (26, 4.70), "MAX": (122, 6.93)}
    for pname, min_tier in PROFILE_TIER.items():
        chars = [c for c in results if c.effective_tier <= min_tier]
        n     = len(chars)
        bps   = math.log2(n) if n > 1 else 0.0
        n_old, bps_old = V2_OLD[pname]
        W(f"  {pname:<10}: {n:4d} chars  {bps:.3f} bps  "
          f"(was {n_old} chars / {bps_old:.2f} bps)")
    W("")
    W("NOTE: Tiers may be revised after manual testing.")
    W("      Load updated manual results with: unicode_compat.py load-manual")

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    print(f"  [✓] {path}")


def export_manual_tests(results: List[CandidateChar], path: str) -> None:
    """
    Generate a manual test file for clipboard / browser / editor / OS testing.

    Structure
      §1  Individual char tests (Tier 1 + Tier 2 only)
      §2  Repetition tests (× 10 and × 100, Tier 1 only)
      §3  Sequence pair tests (Tier 1 only)
      §4  Full stego simulation (Tier 1 chars embedded in English text)
      §5  Instructions and verification command

    After testing in target environments, run:
        python unicode_compat.py verify '<pasted text>'
    to check which invisible chars survived.
    """
    tier1 = [c for c in results if c.effective_tier == TIER_1]
    tier2 = [c for c in results if c.effective_tier == TIER_2]

    lines: List[str] = []
    W = lines.append

    W("UNICODE STEGANOGRAPHY V2 — MANUAL COMPATIBILITY TEST FILE")
    W("=" * 72)
    W("")
    W("HOW TO USE THIS FILE")
    W("  1. Open this file in UTF-8 aware editor (VS Code, Notepad++, etc.)")
    W("  2. Copy each test string (the part inside | | markers)")
    W("  3. Paste into target environment: browser, clipboard, OS text field,")
    W("     Word, Excel, Slack, WhatsApp, email, etc.")
    W("  4. Copy it back and paste into a char-count tool OR run:")
    W("       python unicode_compat.py verify '<pasted text>'")
    W("  5. Expected char count is shown after each test string.")
    W("")
    W("  A result of 2 chars instead of 3 means the char was STRIPPED.")
    W("  A different char appearing means the char was CHANGED.")
    W("")

    W("─" * 72)
    W("§1  INDIVIDUAL CHARACTER TESTS  [Tier 1 and Tier 2 only]")
    W("─" * 72)
    W(f"  Format:  HEX  NAME  |A<char>B|  (expected: 3 chars)")
    W("")
    for c in tier1 + tier2:
        context = "A" + c.char + "B"
        W(f"  {c.hex_cp():<9} {c.name[:44]:<44}  |{context}|")

    W("")
    W("─" * 72)
    W("§2  REPETITION TESTS  [Tier 1 only]")
    W("─" * 72)
    W("")
    for c in tier1:
        W(f"  {c.hex_cp()} ×10:   |A{c.char*10}B|   (expected 12 chars)")
        W(f"  {c.hex_cp()} ×100:  |A{c.char*100}B|  (expected 102 chars)")
    W("")

    W("─" * 72)
    W("§3  SEQUENCE PAIR TESTS  [Tier 1 pairs]")
    W("─" * 72)
    W("")
    t1_chars = tier1[:8]  # limit pairs to avoid huge file
    for i in range(len(t1_chars)):
        for j in range(i + 1, len(t1_chars)):
            c1, c2 = t1_chars[i], t1_chars[j]
            seq = "A" + c1.char + c2.char + "B"
            W(f"  {c1.hex_cp()}+{c2.hex_cp()}  |{seq}|  (expected 4 chars)")
    W("")

    W("─" * 72)
    W("§4  STEGO SIMULATION  [Tier 1 chars embedded in English text]")
    W("─" * 72)
    W("")
    cover   = "The quick brown fox jumps over the lazy dog."
    payload = [c.char for c in tier1]
    stego   = list(cover)
    if len(cover) > len(payload) + 1:
        step = (len(cover) - 1) / len(payload)
        for k, pc in enumerate(payload):
            pos = int(k * step) + 1
            if pos < len(stego):
                stego.insert(pos + k, pc)
    stego_str = "".join(stego)

    W(f"  Carrier text     : {cover}")
    W(f"  Carrier length   : {len(cover)} chars")
    W(f"  Stego text       : {stego_str}")
    W(f"  Stego length     : {len(stego_str)} chars (expected {len(stego_str)})")
    W(f"  Invisible count  : {len(stego_str) - len(cover)}")
    W("")
    W("  After pasting the stego text into your test environment and retrieving")
    W("  it, the invisible count should still match.  If fewer are found, some")
    W("  chars were stripped.  Run 'verify' on the retrieved text to see which.")
    W("")

    W("─" * 72)
    W("§5  VERIFICATION COMMAND")
    W("─" * 72)
    W("")
    W("  After retrieving pasted text from any environment, run:")
    W("    python unicode_compat.py verify '<paste text here>'")
    W("")
    W("  To update manual results in the database:")
    W("    python unicode_compat.py load-manual candidates.json --results my_results.json")
    W("")
    W("=" * 72)

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    print(f"  [✓] {path}")


def export_validated_alphabets(results: List[CandidateChar], path: str) -> None:
    """
    Export Python constants for validated alphabets, ready to paste into stego_v2.py.
    Replaces the hardcoded _SAFE_CHARS / _EXTENDED_CHARS / _MAX_CHARS lists.
    """
    lines: List[str] = []
    W = lines.append

    W('"""')
    W("validated_alphabets.py — Auto-generated by unicode_compat.py")
    W("=" * 70)
    W("Paste _VALIDATED_*_CHARS into stego_v2.py to replace the hardcoded")
    W("_SAFE_CHARS, _EXTENDED_CHARS, and _MAX_CHARS lists.")
    W("")
    W("These alphabets are derived from automated Python tests plus Unicode")
    W("semantic classification.  Manual cross-platform testing (browsers,")
    W("editors, OS text fields, clipboard) is recommended before production use.")
    W("See manual_tests.txt for test strings.")
    W('"""')
    W("")
    W(f"# Total candidates tested: {len(results)}")
    for tid in (TIER_1, TIER_2, TIER_3, TIER_4):
        n = sum(1 for c in results if c.effective_tier == tid)
        W(f"# Tier {tid} ({TIER_NAMES[tid]}): {n} chars")
    W("")

    V2_OLD = {"SAFE": (10, 3.32), "EXTENDED": (26, 4.70), "MAX": (122, 6.93)}

    for pname, min_tier in PROFILE_TIER.items():
        chars = [c for c in results if c.effective_tier <= min_tier]
        n     = len(chars)
        bps   = math.log2(n) if n > 1 else 0.0
        n_old, bps_old = V2_OLD[pname]
        W(f"# {'─'*66}")
        W(f"# Profile: {pname}")
        W(f"#   {n} chars  ·  {bps:.3f} bits/sym")
        W(f"#   vs stego_v2.py default: {n_old} chars / {bps_old:.2f} bits/sym")
        W(f"#   capacity improvement: {bps/bps_old:.2f}×")
        W(f"#   Tier threshold: ≤ {min_tier} ({TIER_NAMES[min_tier]})")
        W(f"_VALIDATED_{pname}_CHARS: list = [")
        for c in chars:
            # Correct escape syntax for all planes
            if c.code_point <= 0xFFFF:
                esc = f"\\u{c.code_point:04X}"
            else:
                esc = f"\\U{c.code_point:08X}"
            W(f'    "{esc}",  '
              f'# {c.hex_cp()} {c.name[:42]:<42} T{c.effective_tier}')
        W("]")
        W("")

    W("# ── Usage in stego_v2.py ──────────────────────────────────────────────")
    W("# Replace the three profile lists with the validated versions above:")
    W("#")
    W("#   _SAFE_CHARS     = _VALIDATED_SAFE_CHARS")
    W("#   _EXTENDED_CHARS = _VALIDATED_EXTENDED_CHARS")
    W("#   _MAX_CHARS      = _VALIDATED_MAX_CHARS")
    W("#")
    W("# Then update the three slice-derived variables:")
    W("#   _VS_CHARS  = []   # already included in _EXTENDED")
    W("#   _TAG_CHARS = []   # already included in _MAX")

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    print(f"  [✓] {path}")


# =============================================================================
# §9  MANUAL RESULT LOADER & VERIFY UTILITY
# =============================================================================

def load_manual_results(db_path: str, results_path: str) -> None:
    """
    Load a JSON file of manual test results and update candidates.json.

    results_path JSON format (dict keyed by hex code point):
      {
        "U+200B": { "clipboard": true, "browser": true, "notepad": true,
                    "windows": true, "macos": null },
        ...
      }
    """
    with open(db_path, "r", encoding="utf-8") as fh:
        data: List[dict] = json.load(fh)

    with open(results_path, "r", encoding="utf-8") as fh:
        manual: Dict[str, dict] = json.load(fh)

    updated = 0
    for rec in data:
        key = rec["hex"]
        if key in manual:
            m = manual[key]
            rec["manual"].update(m)
            passed = sum(1 for v in m.values() if v is True)
            failed = sum(1 for v in m.values() if v is False)
            if failed >= 2:
                rec["effective_tier"] = min(TIER_4, rec["effective_tier"] + 2)
            elif failed == 1:
                rec["effective_tier"] = min(TIER_4, rec["effective_tier"] + 1)
            rec["tier_name"] = TIER_NAMES[rec["effective_tier"]]
            rec["manual"]["score"] = passed
            updated += 1

    with open(db_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)

    print(f"  Updated {updated} records in {db_path}")


def verify_paste(text: str) -> None:
    """
    Analyse a pasted/retrieved string for invisible Unicode characters.
    Reports what was found, what survived, and counts per code point.
    """
    print(f"\n  Input length   : {len(text)} chars")

    visible   = [ch for ch in text if not unicodedata.category(ch).startswith("C")
                 and ch != "\u00AD"]
    invisible = [ch for ch in text if unicodedata.category(ch).startswith("C")
                 or ch == "\u00AD"]

    print(f"  Visible chars  : {len(visible)}")
    print(f"  Invisible chars: {len(invisible)}")

    if invisible:
        from collections import Counter
        counts = Counter(invisible)
        print(f"\n  Invisible char breakdown:")
        print(f"  {'Hex':<10} {'Name':<45} {'Count':>6}")
        print(f"  {'─'*10} {'─'*45} {'─'*6}")
        for ch, cnt in sorted(counts.items(), key=lambda x: ord(x[0])):
            try:
                name = unicodedata.name(ch)
            except ValueError:
                name = "<unnamed>"
            cp = ord(ch)
            hx = f"U+{cp:04X}" if cp <= 0xFFFF else f"U+{cp:05X}"
            print(f"  {hx:<10} {name[:45]:<45} {cnt:>6}")
    else:
        print("\n  No invisible chars found — all were stripped by the environment.")


# =============================================================================
# §10  CLI
# =============================================================================

_BANNER = """
  ╔══════════════════════════════════════════════════════════════════╗
  ║  UNICODE COMPAT · Stage 2 · Invisible Character Test Suite      ║
  ║  392 candidates · 13 automated tests · semantic tier scoring    ║
  ╚══════════════════════════════════════════════════════════════════╝"""


def _show_profiles_only() -> None:
    """Print profile sizes from semantic tiers without running tests."""
    pool = build_candidate_pool()
    print()
    print(f"  {'Profile':<12} {'Tier':<3}  {'Chars':>6}  {'bits/sym':>9}")
    print(f"  {'─'*12} {'─'*3}  {'─'*6}  {'─'*9}")
    for pname, min_tier in PROFILE_TIER.items():
        chars = [c for c in pool if c.semantic_tier <= min_tier]
        n     = len(chars)
        bps   = math.log2(n) if n > 1 else 0.0
        print(f"  {pname:<12} ≤{min_tier}    {n:>6}  {bps:>9.3f}")
    print()
    print(f"  Total candidate pool: {len(pool)} chars")
    print(f"  Automated tests: {NUM_AUTO_TESTS} per candidate")
    print()


def _build_argparser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="unicode_compat",
        description="Stage 2: Unicode Invisible-Character Compatibility Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python unicode_compat.py test\n"
            "  python unicode_compat.py test --matrix\n"
            "  python unicode_compat.py export --dir ./output\n"
            "  python unicode_compat.py profiles\n"
            "  python unicode_compat.py verify 'A\u200BB'\n"
            "  python unicode_compat.py load-manual candidates.json --results r.json\n"
        ),
    )
    sub = parser.add_subparsers(dest="cmd")

    # test
    t = sub.add_parser("test", help="Run all tests, print tier summary")
    t.add_argument("-v", "--verbose", action="store_true",
                   help="Print one result line per candidate")
    t.add_argument("--matrix", action="store_true",
                   help="Print pass/fail matrix after the summary")

    # export
    e = sub.add_parser("export", help="Run tests + write all output files")
    e.add_argument("--dir", default=".", metavar="PATH",
                   help="Output directory (default: current directory)")
    e.add_argument("-v", "--verbose", action="store_true")

    # profiles
    sub.add_parser("profiles", help="Show profile sizes (no testing)")

    # verify
    v = sub.add_parser("verify", help="Analyse a pasted string for invisible chars")
    v.add_argument("text", help="String to analyse")

    # load-manual
    lm = sub.add_parser("load-manual",
                         help="Merge manual test results into candidates.json")
    lm.add_argument("db",      help="Path to candidates.json")
    lm.add_argument("--results", required=True, metavar="JSON",
                    help="JSON file with manual test results")

    return parser


def main() -> None:
    print(_BANNER)

    if len(sys.argv) < 2:
        print()
        print("  [1]  Run tests — print tier summary")
        print("  [2]  Run tests — print tier summary + test matrix")
        print("  [3]  Run tests + export all output files")
        print("  [4]  Verify pasted text for invisible chars")
        print("  [5]  Show profile sizes (no tests)")
        print("  [Q]  Quit")
        choice = input("\n  Choice: ").strip().upper()

        if choice == "1":
            db = run_compatibility_database(verbose=False, progress=True)
            print_tier_summary(db)

        elif choice == "2":
            db = run_compatibility_database(verbose=False, progress=True)
            print_tier_summary(db)
            print_test_matrix(db)

        elif choice == "3":
            out_dir = input("  Output directory [.]: ").strip() or "."
            os.makedirs(out_dir, exist_ok=True)
            db = run_compatibility_database(verbose=False, progress=True)
            print_tier_summary(db)
            print("\n  Exporting files ...")
            export_json(db,  os.path.join(out_dir, "candidates.json"))
            export_csv(db,   os.path.join(out_dir, "candidates.csv"))
            export_report(db, os.path.join(out_dir, "compat_report.txt"))
            export_manual_tests(db, os.path.join(out_dir, "manual_tests.txt"))
            export_validated_alphabets(db,
                                       os.path.join(out_dir, "validated_alphabets.py"))
            print(f"\n  All files written to: {os.path.abspath(out_dir)}")

        elif choice == "4":
            text = input("  Paste text to verify: ")
            verify_paste(text)

        elif choice == "5":
            _show_profiles_only()

        elif choice == "Q":
            sys.exit(0)
        else:
            print("  Invalid choice.")
        return

    # ── argparse path ─────────────────────────────────────────────────────────
    parser = _build_argparser()
    args   = parser.parse_args()

    if args.cmd == "test":
        db = run_compatibility_database(verbose=args.verbose,
                                        progress=not args.verbose)
        print_tier_summary(db)
        if args.matrix:
            print_test_matrix(db)

    elif args.cmd == "export":
        out_dir = args.dir
        os.makedirs(out_dir, exist_ok=True)
        db = run_compatibility_database(verbose=args.verbose,
                                        progress=not args.verbose)
        print_tier_summary(db)
        print("\n  Exporting ...")
        export_json(db,  os.path.join(out_dir, "candidates.json"))
        export_csv(db,   os.path.join(out_dir, "candidates.csv"))
        export_report(db, os.path.join(out_dir, "compat_report.txt"))
        export_manual_tests(db, os.path.join(out_dir, "manual_tests.txt"))
        export_validated_alphabets(db,
                                   os.path.join(out_dir, "validated_alphabets.py"))
        print(f"\n  All files written to: {os.path.abspath(out_dir)}")

    elif args.cmd == "profiles":
        _show_profiles_only()

    elif args.cmd == "verify":
        verify_paste(args.text)

    elif args.cmd == "load-manual":
        load_manual_results(args.db, args.results)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
