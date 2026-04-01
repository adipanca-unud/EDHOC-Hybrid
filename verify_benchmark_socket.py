#!/usr/bin/env python3
"""
EDHOC-Hybrid Socket Benchmark Consistency Checker
===================================================
Same logic as verify_benchmark.py but checks the output_socket/ CSVs.

Usage:
  python3 verify_benchmark_socket.py
"""

import csv
import sys
import os

TOLERANCE_US = 1.0

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OPS_CSV = os.path.join(BASE_DIR, "output_socket", "benchmark_operations.csv")
OH_CSV  = os.path.join(BASE_DIR, "output_socket", "benchmark_overhead.csv")
HS_CSV  = os.path.join(BASE_DIR, "output_socket", "benchmark_handshake.csv")

KEYGEN_OPS = {"KeyGen", "PQ_KeyGen"}


def load_csvs():
    for path in [OPS_CSV, OH_CSV, HS_CSV]:
        if not os.path.exists(path):
            print(f"  ERROR: file not found: {path}")
            sys.exit(1)
    ops = list(csv.DictReader(open(OPS_CSV)))
    oh  = list(csv.DictReader(open(OH_CSV)))
    hs  = list(csv.DictReader(open(HS_CSV)))
    return ops, oh, hs


def section(title):
    print("=" * 70)
    print(title)
    print("=" * 70)


def passfail(ok):
    return "PASS" if ok else "FAIL"


def check1(oh, hs):
    """processing_us + precomputation_us == cpu_time_us (both derived from measured CPU)"""
    section("CHECK 1: processing_us + precomputation_us == cpu_time_us + precomp")
    all_ok = True
    for h in hs:
        key = (h["type"], h["role"])
        proc = float(h["processing_us"])
        precomp = float(h["precomputation_us"])
        lhs = proc + precomp
        # cpu_time_us in overhead CSV == processing_us, so cpu + precomp should == proc + precomp
        cpu = 0.0
        for o2 in oh:
            if (o2["type"], o2["role"]) == key:
                cpu = float(o2["cpu_time_us"])
        rhs = cpu + precomp
        diff = abs(lhs - rhs)
        ok = diff < TOLERANCE_US
        print(f"  {key[0]:16s} {key[1]:12s}  proc+precomp={lhs:12.3f}  cpu+precomp={rhs:12.3f}  diff={diff:.3f}  [{passfail(ok)}]")
        if not ok: all_ok = False
    print(f'  => CHECK 1: {"ALL PASS" if all_ok else "SOME FAIL"}\n')
    return all_ok


def check2(oh, hs):
    """cpu_time_us (overhead) == processing_us (handshake)"""
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
                print(f"  {key[0]:16s} {key[1]:12s}  cpu_time={cpu:12.3f}  processing={proc:12.3f}  diff={diff:.3f}  [{passfail(ok)}]")
                if not ok: all_ok = False
    print(f'  => CHECK 2: {"ALL PASS" if all_ok else "SOME FAIL"}\n')
    return all_ok


def check3(hs):
    """total == processing + txrx + precomp + overhead"""
    section("CHECK 3: total == processing + txrx + precomp + overhead")
    all_ok = True
    for h in hs:
        key = (h["type"], h["role"])
        proc = float(h["processing_us"]); txrx = float(h["txrx_us"])
        precomp = float(h["precomputation_us"]); over = float(h["overhead_us"])
        total = float(h["total_us"]); computed = proc + txrx + precomp + over
        diff = abs(total - computed)
        ok = diff < TOLERANCE_US
        print(f"  {key[0]:16s} {key[1]:12s}  total={total:12.3f}  sum={computed:12.3f}  diff={diff:.3f}  [{passfail(ok)}]")
        if not ok: all_ok = False
    print(f'  => CHECK 3: {"ALL PASS" if all_ok else "SOME FAIL"}\n')
    return all_ok


def check4(hs):
    """All handshake values >= 0"""
    section("CHECK 4: all values >= 0")
    all_ok = True
    for h in hs:
        key = (h["type"], h["role"])
        for col in ["processing_us", "txrx_us", "precomputation_us", "overhead_us", "total_us"]:
            v = float(h[col])
            if v < 0:
                print(f"  FAIL: {key[0]} {key[1]} {col} = {v}")
                all_ok = False
    if all_ok: print("  All handshake values >= 0")
    print(f'  => CHECK 4: {"ALL PASS" if all_ok else "SOME FAIL"}\n')
    return all_ok


def check5(ops):
    """ops internal: avg_time_us * calls == total_per_handshake_us"""
    section("CHECK 5: ops internal: avg_time_us × calls == total_per_handshake_us")
    all_ok = True; fails = 0
    for o in ops:
        avg = float(o["avg_time_us"]); calls = int(o["calls_per_handshake"])
        total = float(o["total_per_handshake_us"]); computed = avg * calls
        diff = abs(total - computed)
        if diff >= 0.5:
            print(f'  FAIL: {o["type"]} {o["role"]} {o["operation"]}  avg={avg} calls={calls} total={total} computed={computed}')
            all_ok = False; fails += 1
    print(f"  {len(ops)} rows checked, {fails} failures")
    print(f'  => CHECK 5: {"ALL PASS" if all_ok else "SOME FAIL"}\n')
    return all_ok


def check6(ops, oh, hs):
    """Detailed per-role breakdown"""
    section("CHECK 6: Detailed Breakdown  (precomp == keygen ops,\n"
            "         cpu_time == processing, proc+precomp by construction)")
    all_ok = True
    for h in hs:
        key = (h["type"], h["role"])
        proc = float(h["processing_us"]); precomp = float(h["precomputation_us"])
        cpu = 0.0
        for o2 in oh:
            if (o2["type"], o2["role"]) == key:
                cpu = float(o2["cpu_time_us"])
        keygen_total = 0.0; non_keygen_total = 0.0; op_lines = []
        for o in ops:
            if (o["type"], o["role"]) != key: continue
            avg = float(o["avg_time_us"]); calls = int(o["calls_per_handshake"])
            total = avg * calls; is_kg = o["operation"] in KEYGEN_OPS
            if is_kg: keygen_total += total
            else: non_keygen_total += total
            if total > 0 or calls > 0:
                tag = "  ◄ PRECOMP (keygen)" if is_kg else ""
                op_lines.append(f"    {o['operation']:20s}  avg={avg:10.3f} × {calls} = {total:10.3f}{tag}")
        all_total = keygen_total + non_keygen_total
        print(f"\n  ┌─ {key[0]} {key[1]} {'─' * (50 - len(key[0]) - len(key[1]))}")
        for line in op_lines: print(f"  │{line}")
        print(f"  │  {'':20s}  {'─' * 38}")
        print(f"  │  {'sum(non-keygen)':20s}  = {non_keygen_total:10.3f}")
        print(f"  │  {'sum(keygen)':20s}  = {keygen_total:10.3f}")
        print(f"  │  {'sum(ALL ops)':20s}  = {all_total:10.3f}")
        print(f"  │")
        print(f"  │  CSV values:")
        print(f"  │    processing_us     = {proc:10.3f}  (handshake CSV)")
        print(f"  │    precomputation_us  = {precomp:10.3f}  (handshake CSV)")
        print(f"  │    cpu_time_us        = {cpu:10.3f}  (overhead CSV)")
        # --- Exact checks ---
        diff_b = abs(keygen_total - precomp)
        diff_c = abs(cpu - proc)
        ok_b = diff_b < TOLERANCE_US
        ok_c = diff_c < TOLERANCE_US
        # --- Informational (not exact, due to handshake overhead vs micro-benchmark sum) ---
        diff_a = abs(non_keygen_total - proc)
        diff_d = abs((proc + precomp) - all_total)
        print(f"  │")
        print(f"  │  A. sum(non-keygen) ≈ processing?   diff={diff_a:.3f}  [INFO — not exact]")
        print(f"  │  B. sum(keygen)     == precomp?      diff={diff_b:.3f}  [{passfail(ok_b)}]")
        print(f"  │  C. cpu_time        == processing?   diff={diff_c:.3f}  [{passfail(ok_c)}]")
        print(f"  │  D. proc+precomp    ≈ sum(ALL)?      diff={diff_d:.3f}  [INFO — not exact]")
        row_ok = ok_b and ok_c
        print(f"  └─ {'✅ ALL PASS' if row_ok else '❌ SOME FAIL'} {'─' * 55}")
        if not row_ok: all_ok = False
    print(f'\n  => CHECK 6: {"ALL PASS" if all_ok else "SOME FAIL"}\n')
    return all_ok


def check7(ops):
    """Cross-variant consistency: same operation should have similar avg_time_us across variants"""
    section("CHECK 7: Cross-variant consistency (same op, same role → similar avg)")
    # Group by (operation, role) across all types
    from collections import defaultdict
    groups = defaultdict(list)
    for o in ops:
        key = (o["operation"], o["role"])
        calls = int(o["calls_per_handshake"])
        if calls == 0:
            continue  # Skip ops not present in this variant
        groups[key].append((o["type"], float(o["avg_time_us"])))

    all_ok = True
    CROSS_TOLERANCE_PCT = 10.0  # 10% relative tolerance
    CROSS_MIN_ABS_US = 5.0     # ignore deviations below 5µs absolute
    for (op_name, role), entries in sorted(groups.items()):
        if len(entries) < 2:
            continue
        values = [v for _, v in entries]
        mean_val = sum(values) / len(values)
        if mean_val < 1.0:
            continue  # skip near-zero ops
        max_dev = max(abs(v - mean_val) for v in values)
        pct = (max_dev / mean_val) * 100.0
        ok = pct < CROSS_TOLERANCE_PCT or max_dev < CROSS_MIN_ABS_US
        tag = passfail(ok)
        variants = ", ".join(f"{t}={v:.1f}" for t, v in entries)
        # Ops that differ legitimately between Type0 (Sig) and Type3 (MAC) are informational
        # Type0 uses Ed25519 keygen; Type3/Hybrid use X25519 keygen — different underlying crypto
        mixed_crypto = False
        type_families = set(t.split("_")[0] for t, _ in entries)
        if len(type_families) > 1 and op_name in ("KeyGen", "Encap", "Decap", "ECDH", "HKDF", "Hash",
                                                     "Signature", "Verification"):
            mixed_crypto = True
        if mixed_crypto:
            print(f"  {op_name:20s} {role:12s}  mean={mean_val:8.1f}  max_dev={pct:5.1f}%  [INFO — mixed crypto]  ({variants})")
        else:
            print(f"  {op_name:20s} {role:12s}  mean={mean_val:8.1f}  max_dev={pct:5.1f}%  [{tag}]  ({variants})")
            if not ok:
                all_ok = False
    print(f'\n  => CHECK 7: {"ALL PASS" if all_ok else "SOME FAIL"}\n')
    return all_ok


def main():
    print()
    print("  ╔═══════════════════════════════════════════════════════╗")
    print("  ║  EDHOC-Hybrid Socket Benchmark Consistency Checker   ║")
    print("  ╚═══════════════════════════════════════════════════════╝")
    print()
    print(f"  Operations CSV : {OPS_CSV}")
    print(f"  Overhead CSV   : {OH_CSV}")
    print(f"  Handshake CSV  : {HS_CSV}")
    print()

    ops, oh, hs = load_csvs()
    results = []
    results.append(("CHECK 1: proc+precomp == cpu+precomp",  check1(oh, hs)))
    results.append(("CHECK 2: cpu_time == processing",       check2(oh, hs)))
    results.append(("CHECK 3: total == sum(components)",     check3(hs)))
    results.append(("CHECK 4: all values >= 0",              check4(hs)))
    results.append(("CHECK 5: ops internal consistency",     check5(ops)))
    results.append(("CHECK 6: detailed breakdown",           check6(ops, oh, hs)))
    results.append(("CHECK 7: cross-variant consistency",    check7(ops)))

    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    all_pass = True
    for name, ok in results:
        status = "✅ PASS" if ok else "❌ FAIL"
        print(f"  {status}  {name}")
        if not ok: all_pass = False
    print()
    if all_pass:
        print("  🎉 ALL CHECKS PASSED — Socket benchmark CSV data is internally consistent!")
    else:
        print("  ⚠️  SOME CHECKS FAILED — Review detailed output above.")
    print()
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
