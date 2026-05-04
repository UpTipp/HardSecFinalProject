"""
detector.py — Lightweight Hardware Trojan Detector

Usage:
    python detector.py <verilog_file_or_directory>

Example:
    python detector.py ./trojaned_outputs/
    python detector.py ./trojaned_outputs/aes_sbox_HT1_gpt-4.1_A1.v
"""

import os
import re
import sys
import glob
from dataclasses import dataclass, field
from typing import List, Tuple


# ---------------------------------------------------------------------------
# Detection rules
# Each rule is a (pattern, description, suspected_type, severity).
# severity: "HIGH" = strong indicator, "MEDIUM" = worth investigating
# ---------------------------------------------------------------------------

RULES: List[Tuple[str, str, str, str]] = [
    # --- Trojan marker comments (explicit, from GHOST output format) ---
    (r"trojan_insertion_begin", "Explicit trojan_insertion_begin marker", "Any", "HIGH"),
    (r"trojan_insertion_end", "Explicit trojan_insertion_end marker", "Any", "HIGH"),
    (r"TROJANED DESIGN", "TROJANED DESIGN header comment", "Any", "HIGH"),
    (r"trojan", "Signal/variable name contains 'trojan'", "Any", "HIGH"),
    # --- T1: Change Functionality ---
    (r"==\s*10'd1023", "Counter comparison to 1023 (1024-cycle trigger)", "T1", "HIGH"),
    (r"==\s*2'b10", "2-bit counter trigger comparison", "T1", "MEDIUM"),
    (r"<=\s*\w+\s*\+\s*[2-9]\b", "Increment by value >1 (possible payload)", "T1", "MEDIUM"),
    (r"trojan_trigger\s*=", "Signal named trojan_trigger assigned", "T1", "HIGH"),
    (r"trojan_triggered\s*=", "Signal named trojan_triggered assigned", "T1", "HIGH"),
    (r"trojan_counter", "Register named trojan_counter", "T1", "HIGH"),
    # --- T2: Leak Information ---
    (r"trojan_leak", "Signal named trojan_leak (covert channel)", "T2", "HIGH"),
    (r"trojan_key", "Input named trojan_key (secret key trigger)", "T2", "HIGH"),
    (r"trojan_active", "Register named trojan_active", "T2", "HIGH"),
    (r"leak_bit_cnt", "Register named leak_bit_cnt", "T2", "HIGH"),
    (r"output\s+reg\s+\w*leak\w*", "Output register with 'leak' in name", "T2", "HIGH"),
    (r"key_shift", "Register named key_shift (key detection)", "T2", "HIGH"),
    # --- T3: Denial of Service ---
    (r"==\s*8'hAA", "Magic byte 8'hAA (part of DoS trigger seq)", "T3", "HIGH"),
    (r"==\s*8'h55", "Magic byte 8'h55 (part of DoS trigger seq)", "T3", "HIGH"),
    (r"==\s*8'hFF", "Magic byte 8'hFF (forced output or trigger)", "T3", "HIGH"),
    (r"<=\s*8'b0+\s*;", "Output forced to zero (possible DoS payload)", "T3", "MEDIUM"),
    (r"data_out\s*=\s*8'h00", "data_out forced to 0x00", "T3", "HIGH"),
    # --- T4: Performance Degradation ---
    (r"==\s*8'h7B", "Rare value 8'h7B used as trigger", "T4", "HIGH"),
    (r"trojan_en_shift", "Register named trojan_en_shift", "T4", "HIGH"),
    # Generic patterns applicable to multiple types
    (r"[2-9][0-9]+'[bh][0-9a-fA-F_]+\s*;", "Hardcoded multi-bit constant", "T1/T4", "MEDIUM"),
    (r"if\s*\(\s*\w+\s*==\s*\d+'[bh][0-9a-fA-F]+\s*\)", "Conditional trigger on specific bit pattern", "Any", "MEDIUM"),
]


# ---------------------------------------------------------------------------
# Dataclass for a finding
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    line_number: int
    line_text: str
    rule_description: str
    suspected_type: str
    severity: str


@dataclass
class FileResult:
    filepath: str
    findings: List[Finding] = field(default_factory=list)

    @property
    def high_count(self):
        return sum(1 for f in self.findings if f.severity == "HIGH")

    @property
    def medium_count(self):
        return sum(1 for f in self.findings if f.severity == "MEDIUM")

    @property
    def flagged(self):
        return len(self.findings) > 0


# ---------------------------------------------------------------------------
# Core detection logic
# ---------------------------------------------------------------------------

def detect(filepath: str) -> FileResult:
    result = FileResult(filepath=filepath)

    try:
        with open(filepath, "r", errors="replace") as f:
            lines = f.readlines()
    except OSError as e:
        print(f"  [ERROR] Could not read {filepath}: {e}")
        return result

    # Track which pairs we've already reported to avoid duplicates
    seen = set()

    for line_num, line in enumerate(lines, start=1):
        for pattern, description, suspected_type, severity in RULES:
            if re.search(pattern, line, re.IGNORECASE):
                key = (line_num, pattern)
                if key not in seen:
                    seen.add(key)
                    result.findings.append(Finding(
                        line_number=line_num,
                        line_text=line.rstrip(),
                        rule_description=description,
                        suspected_type=suspected_type,
                        severity=severity
                    ))

    return result


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_result(result: FileResult, verbose: bool = True):
    filename = os.path.basename(result.filepath)
    status = "🚨 FLAGGED" if result.flagged else "✅ CLEAN"
    print(f"\n{status}  {filename}")
    print(f"         HIGH: {result.high_count}  |  MEDIUM: {result.medium_count}  |  Total findings: {len(result.findings)}")

    if verbose and result.findings:
        for f in result.findings:
            prefix = "  ⛔" if f.severity == "HIGH" else "  ⚠️ "
            print(f"{prefix} [Line {f.line_num if hasattr(f,'line_num') else f.line_number}] [{f.severity}] [{f.suspected_type}] {f.rule_description}")
            print(f"       → {f.line_text.strip()}")


def print_summary(results: List[FileResult]):
    total = len(results)
    flagged = sum(1 for r in results if r.flagged)
    clean = total - flagged
    high_hits = sum(r.high_count for r in results)
    med_hits = sum(r.medium_count for r in results)

    print("\n" + "=" * 60)
    print("📊 DETECTION SUMMARY")
    print("=" * 60)
    print(f"  Files scanned  : {total}")
    print(f"  Flagged        : {flagged}  ({100*flagged//total if total else 0}%)")
    print(f"  Clean          : {clean}")
    print(f"  HIGH findings  : {high_hits}")
    print(f"  MEDIUM findings: {med_hits}")

    if flagged:
        print("\n🚨 Flagged files:")
        for r in results:
            if r.flagged:
                print(f"   • {os.path.basename(r.filepath)}  "
                      f"(HIGH={r.high_count}, MED={r.medium_count})")

    print("\n📝 False Positive / False Negative Notes:")
    print("  FP risk: Clean designs that legitimately use counters or specific constants may trigger MEDIUM rules.")
    print("  FN risk: Novel Trojans that avoid 'trojan_*' naming and use uncommon magic values will evade HIGH rules.")
    print("  Recommendation: HIGH findings should always be reviewed; MEDIUM findings require context from the designer.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(target: str, verbose: bool = True):
    # Collect files
    if os.path.isfile(target):
        files = [target]
    elif os.path.isdir(target):
        files = glob.glob(os.path.join(target, "**", "*.v"), recursive=True)
        if not files:
            print(f"No .v files found in {target}")
            return
    else:
        print(f"Target not found: {target}")
        return

    print("🔍 Hardware Trojan Heuristic Detector")
    print(f"   Scanning {len(files)} Verilog file(s) in: {target}")
    print("=" * 60)

    results = []
    for filepath in sorted(files):
        result = detect(filepath)
        print_result(result, verbose=verbose)
        results.append(result)

    print_summary(results)
    return results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python detector.py <verilog_file_or_directory>")
        print("Example: python detector.py ./trojaned_outputs/")
        sys.exit(1)

    target = sys.argv[1]
    verbose = "--quiet" not in sys.argv
    run(target, verbose=verbose)
