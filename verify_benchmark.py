#!/usr/bin/env python3
"""
EDHOC-Hybrid Benchmark Consistency Checker
===========================================
Verifies cross-table consistency across the 3 benchmark CSV files:
  - output/benchmark_operations.csv
  - output/benchmark_overhead.csv
  - output/benchmark_handshake.csv

Checks performed:
  1. processing + precomp == sum(ops × calls)       [handshake ↔ operations]
  2. cpu_time_us == processing_us                    [overhead  ↔ handshake]
  3. total == processing + txrx + precomp + overhead [handshake arithmetic]
  4. All values >= 0                                 [handshake sanity]
  5. avg_time_us × calls == total_per_handshake_us   [operations internal]
  6. Detailed breakdown per type/role:               [full cross-table audit]
       A. sum(non-keygen ops) == processing_us
       B. sum(keygen ops)     == precomputation_us
       C. cpu_time_us         == processing_us
       D. processing + precomp == sum(ALL ops)

Usage:
  python3 verify_benchmark.py
"""

import csv
import sys
import os

# ── Tolerance ────────────────────────────────────────────────────────────
TOLERANCE_US = 1.0  # microseconds

# ── Resolve paths relative to this script's directory ────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OPS_CSV = os.path.join(BASE_DIR, "output", "benchmark_operations.csv")
OH_CSV = os.path.join(BASE_DIR, "output", "benchmark_overhead.csv")
HS_CSV = os.path.join(BASE_DIR, "output", "benchmark_handshake.csv")

# KeyGen operation names (used to split processing vs precomputation)
KEYGEN_OPS = {"KeyGen", "PQ_KeyGen"}


def load_csvs():
    for path in [OPS_CSV, OH_CSV, HS_CSV]:
        if not os.path.exists(path):
            print(f"  ERROR: file not found: {path}")
            sys.exit(1)
    ops = list(csv.DictReader(open(OPS_CSV)))
    oh = list(csv.DictReader(open(OH_CSV)))
    hs = list(csv.DictReader(open(HS_CSV)))
    return ops, oh, hs


def section(title):
    print("=" * 70)
    print(title)
    print("=" * 70)


def passfail(ok):
    return "PASS" if ok else "FAIL"


# ── CHECK 1 ──────────────────────────────────────────────────────────────
def check1(ops, hs):
    """processing_us + precomputation_us == sum(ops × calls)"""
    section("CHECK 1: processing_us + precomputation_us == sum(ops × calls)")
    all_ok = True
    for h in hs:
        key = (h["type"], h["role"])
        lhs = float(h["processing_us"]) + float(h["precomputation_us"])
        rhs = sum(
            float(o["avg_time_us"]) * int(o["calls_per_handshake"])
            for o in ops
            if (o["type"], o["role"]) == key
        )
        diff = abs(lhs - rhs)
        ok = diff < TOLERANCE_US
        print(
            f"  {key[0]:16s} {key[1]:12s}"
            f"  proc+precomp={lhs:12.3f}"
            f"  sum(ops)={rhs:12.3f}"
            f"  diff={diff:.3f}  [{passfail(ok)}]"
        )
        if not ok:
            all_ok = False
    print(f'  => CHECK 1: {"ALL PASS" if all_ok else "SOME FAIL"}\n')
    return all_ok


# ── CHECK 2 ──────────────────────────────────────────────────────────────
def check2(oh, hs):
    """cpu_time_us (overhead CSV) == processing_us (handshake CSV)"""
    section("CHECK 2: cpu_time_us == processing_us")
    all_ok = True
    for h in hs:
        key = (h["type"], h["role"])
        proc = float(h["processing_us"])
        for o2 in oh:
            if (o2["type"], o2["role"]) == key:
                cpu = float(o2["cpu_time_us"])
                diff = abs(cpu - proc)
                ok = diff < TOLERANCE_US
                print(
                    f"  {key[0]:16s} {key[1]:12s}"
                    f"  cpu_time={cpu:12.3f}"
                    f"  processing={proc:12.3f}"
                    f"  diff={diff:.3f}  [{passfail(ok)}]"
                )
                if not ok:
                    all_ok = False
    print(f'  => CHECK 2: {"ALL PASS" if all_ok else "SOME FAIL"}\n')
    return all_ok


# ── CHECK 3 ──────────────────────────────────────────────────────────────
def check3(hs):
    """total == processing + txrx + precomp + overhead"""
    section("CHECK 3: total == processing + txrx + precomp + overhead")
    all_ok = True
    for h in hs:
        key = (h["type"], h["role"])
        proc = float(h["processing_us"])
        txrx = float(h["txrx_us"])
        precomp = float(h["precomputation_us"])
        over = float(h["overhead_us"])
        total = float(h["total_us"])
        computed = proc + txrx + precomp + over
        diff = abs(total - computed)
        ok = diff < TOLERANCE_US
        print(
            f"  {key[0]:16s} {key[1]:12s}"
            f"  total={total:12.3f}"
            f"  sum={computed:12.3f}"
            f"  diff={diff:.3f}  [{passfail(ok)}]"
        )
        if not ok:
            all_ok = False
    print(f'  => CHECK 3: {"ALL PASS" if all_ok else "SOME FAIL"}\n')
    return all_ok


# ── CHECK 4 ──────────────────────────────────────────────────────────────
def check4(hs):
    """All handshake values >= 0"""
    section("CHECK 4: all values >= 0")
    all_ok = True
    for h in hs:
        key = (h["type"], h["role"])
        for col in [
            "processing_us",
            "txrx_us",
            "precomputation_us",
            "overhead_us",
            "total_us",
        ]:
            v = float(h[col])
            if v < 0:
                print(f"  FAIL: {key[0]} {key[1]} {col} = {v}")
                all_ok = False
    if all_ok:
        print("  All handshake values >= 0")
    print(f'  => CHECK 4: {"ALL PASS" if all_ok else "SOME FAIL"}\n')
    return all_ok


# ── CHECK 5 ──────────────────────────────────────────────────────────────
def check5(ops):
    """ops internal: avg_time_us * calls == total_per_handshake_us"""
    section("CHECK 5: ops internal: avg_time_us × calls == total_per_handshake_us")
    all_ok = True
    fails = 0
    for o in ops:
        avg = float(o["avg_time_us"])
        calls = int(o["calls_per_handshake"])
        total = float(o["total_per_handshake_us"])
        computed = avg * calls
        diff = abs(total - computed)
        if diff >= 0.5:
            print(
                f'  FAIL: {o["type"]} {o["role"]} {o["operation"]}'
                f"  avg={avg} calls={calls} total={total} computed={computed}"
            )
            all_ok = False
            fails += 1
    print(f"  {len(ops)} rows checked, {fails} failures")
    print(f'  => CHECK 5: {"ALL PASS" if all_ok else "SOME FAIL"}\n')
    return all_ok


# ── CHECK 6 ──────────────────────────────────────────────────────────────
def check6(ops, oh, hs):
    """Detailed per-role breakdown: processing vs non-keygen, precomp vs keygen"""
    section(
        "CHECK 6: Detailed Breakdown  (processing ↔ non-keygen ops,\n"
        "         precomp ↔ keygen ops, cpu_time ↔ processing)"
    )
    all_ok = True

    for h in hs:
        key = (h["type"], h["role"])
        proc = float(h["processing_us"])
        precomp = float(h["precomputation_us"])

        # Find cpu_time from overhead CSV
        cpu = 0.0
        for o2 in oh:
            if (o2["type"], o2["role"]) == key:
                cpu = float(o2["cpu_time_us"])

        # Gather ops and split keygen vs non-keygen
        keygen_total = 0.0
        non_keygen_total = 0.0
        op_lines = []
        for o in ops:
            if (o["type"], o["role"]) != key:
                continue
            avg = float(o["avg_time_us"])
            calls = int(o["calls_per_handshake"])
            total = avg * calls
            is_kg = o["operation"] in KEYGEN_OPS
            if is_kg:
                keygen_total += total
            else:
                non_keygen_total += total
            # Only show ops with calls > 0 or nonzero avg
            if total > 0 or calls > 0:
                tag = "  ◄ PRECOMP (keygen)" if is_kg else ""
                op_lines.append(
                    f"    {o['operation']:20s}"
                    f"  avg={avg:10.3f} × {calls} = {total:10.3f}{tag}"
                )
        all_total = keygen_total + non_keygen_total

        # Print header
        print(f"\n  ┌─ {key[0]} {key[1]} {'─' * (50 - len(key[0]) - len(key[1]))}")

        # Print operation details
        for line in op_lines:
            print(f"  │{line}")
        print(f"  │  {'':20s}  {'─' * 38}")
        print(f"  │  {'sum(non-keygen)':20s}  = {non_keygen_total:10.3f}")
        print(f"  │  {'sum(keygen)':20s}  = {keygen_total:10.3f}")
        print(f"  │  {'sum(ALL ops)':20s}  = {all_total:10.3f}")

        # Print CSV values
        print(f"  │")
        print(f"  │  CSV values:")
        print(f"  │    processing_us     = {proc:10.3f}  (handshake CSV)")
        print(f"  │    precomputation_us  = {precomp:10.3f}  (handshake CSV)")
        print(f"  │    cpu_time_us        = {cpu:10.3f}  (overhead CSV)")

        # Sub-checks
        diff_a = abs(non_keygen_total - proc)
        diff_b = abs(keygen_total - precomp)
        diff_c = abs(cpu - proc)
        diff_d = abs((proc + precomp) - all_total)

        ok_a = diff_a < TOLERANCE_US
        ok_b = diff_b < TOLERANCE_US
        ok_c = diff_c < TOLERANCE_US
        ok_d = diff_d < TOLERANCE_US

        print(f"  │")
        print(
            f"  │  A. sum(non-keygen) == processing?  "
            f" diff={diff_a:.3f}  [{passfail(ok_a)}]"
        )
        print(
            f"  │  B. sum(keygen)     == precomp?     "
            f" diff={diff_b:.3f}  [{passfail(ok_b)}]"
        )
        print(
            f"  │  C. cpu_time        == processing?  "
            f" diff={diff_c:.3f}  [{passfail(ok_c)}]"
        )
        print(
            f"  │  D. proc+precomp    == sum(ALL)?    "
            f" diff={diff_d:.3f}  [{passfail(ok_d)}]"
        )

        row_ok = ok_a and ok_b and ok_c and ok_d
        print(
            f"  └─ {'✅ ALL PASS' if row_ok else '❌ SOME FAIL'}"
            f" {'─' * 55}"
        )
        if not row_ok:
            all_ok = False

    print(f'\n  => CHECK 6: {"ALL PASS" if all_ok else "SOME FAIL"}\n')
    return all_ok


# ── MAIN ─────────────────────────────────────────────────────────────────
def main():
    print()
    print("  ╔══════════════════════════════════════════════════╗")
    print("  ║   EDHOC-Hybrid Benchmark Consistency Checker    ║")
    print("  ╚══════════════════════════════════════════════════╝")
    print()
    print(f"  Files:")
    print(f"    ops : {OPS_CSV}")
    print(f"    overhead : {OH_CSV}")
    print(f"    handshake: {HS_CSV}")
    print(f"  Tolerance: {TOLERANCE_US} µs")
    print()

    ops, oh, hs = load_csvs()

    results = [
        check1(ops, hs),
        check2(oh, hs),
        check3(hs),
        check4(hs),
        check5(ops),
        check6(ops, oh, hs),
    ]

    print("=" * 70)
    if all(results):
        print("OVERALL: ✅ ALL 6 CHECKS PASS — Data is fully consistent!")
    else:
        failed = [i + 1 for i, ok in enumerate(results) if not ok]
        print(f"OVERALL: ❌ FAILED CHECK(S): {failed}")
    print("=" * 70)

    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
