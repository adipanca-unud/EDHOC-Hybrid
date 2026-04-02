#!/usr/bin/env python3
"""
Verify consistency between standalone crypto benchmark (benchmark_crypto_simple.csv)
and EDHOC socket benchmark (benchmark_operations.csv).

Optimization: Application code compiled with -O2, PQClean sources with -O3.
Library (uoscore-uedhoc) compiled with -O2.

Both benchmarks now use the SAME crypto libraries:
  - Classic (X25519, Ed25519): libsodium (assembly-optimized)
    The EDHOC app overrides the library's compact25519 WEAK functions
    with libsodium via src/crypto_libsodium.c.
  - PQ (ML-KEM-768, ML-DSA-65): PQClean (compiled at -O3)

Classic operations have additional overhead in the socket benchmark due to
the EDHOC framework wrapper (buffer copies, CBOR encoding, HKDF context, etc.),
so a wider tolerance is used for classic ops compared to PQ ops.

KeyGen has the highest overhead because the socket benchmark's ephemeral_dh_key_gen()
performs SHA-256 seed expansion + RFC 7748 clamping + crypto_scalarmult_base(),
whereas the standalone benchmark only calls crypto_scalarmult_base().
"""

import csv
import sys
import os

# ─── Configuration ───
STANDALONE_CSV = "output/benchmark_crypto_simple.csv"
SOCKET_CSV     = "output/benchmark_operations.csv"

# PQ operations tolerance: both use PQClean, but socket has wrapper overhead
TOLERANCE_PQ = 0.40   # 40% for PQClean (wrapper overhead + measurement variance)
# Classic operations tolerance: both use libsodium, but socket has EDHOC wrapper overhead
TOLERANCE_CLASSIC = 0.50  # 50% — socket wraps libsodium in EDHOC's crypto_wrapper layer
# KeyGen has extra overhead: SHA-256 seed expansion + clamping on top of scalarmult_base
TOLERANCE_KEYGEN = 0.55   # 55% — accounts for seed expansion overhead

# Mapping: (standalone_algorithm, standalone_operation) →
#          (socket_operation_name, category)
# Categories:
#   "pq"      = same PQClean library, can compare
#   "classic"  = same libsodium library (via override), can compare
#   "keygen"   = classic keygen with extra seed expansion overhead
COMPARE_MAP = [
    # Classic — both use libsodium now (socket via crypto_libsodium.c override)
    (("X25519",    "Keygen"),        "KeyGen",        "keygen"),
    (("Ed25519",   "Signature"),     "Signature",     "classic"),
    (("Ed25519",   "Verification"),  "Verification",  "classic"),
    (("X25519",    "Shared Secret"), "ECDH",          "classic"),
    # PQ (both call PQClean directly — should be comparable)
    (("ML-KEM-768", "Keygen"),       "PQ_KeyGen",     "pq"),
    (("ML-KEM-768", "Encap"),        "PQ_Encaps",     "pq"),
    (("ML-KEM-768", "Decap"),        "PQ_Decaps",     "pq"),
    (("ML-DSA-65",  "Signature"),    "PQ_Signature",  "pq"),
    (("ML-DSA-65",  "Verification"), "PQ_Verification","pq"),
]


def load_standalone(path):
    """Load standalone benchmark CSV → dict keyed by (algorithm, operation)."""
    data = {}
    with open(path, "r") as f:
        reader = csv.reader(f)
        header = next(reader)
        current_algo = ""
        for row in reader:
            if not row or len(row) < 3:
                continue
            algo = row[0].strip() if row[0].strip() else current_algo
            if row[0].strip():
                current_algo = algo
            op   = row[1].strip()
            avg  = float(row[2])
            data[(algo, op)] = avg
    return data


def load_socket(path):
    """Load socket benchmark CSV → dict keyed by operation name (avg_time_us).
       Returns first non-zero value for each operation."""
    data = {}
    with open(path, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            key = row["operation"]
            avg = float(row["avg_time_us"])
            if avg > 0 and key not in data:
                data[key] = avg
    return data


def main():
    os.chdir(os.path.dirname(os.path.abspath(__file__)) or ".")

    if not os.path.exists(STANDALONE_CSV):
        print(f"ERROR: {STANDALONE_CSV} not found. Run: make -f Makefile.crypto_bench run")
        sys.exit(1)
    if not os.path.exists(SOCKET_CSV):
        print(f"ERROR: {SOCKET_CSV} not found. Run: ./build/edhoc_hybrid 6")
        sys.exit(1)

    standalone = load_standalone(STANDALONE_CSV)
    socket_ops = load_socket(SOCKET_CSV)

    print("=" * 95)
    print("  Benchmark Consistency Verification")
    print("  Standalone (benchmark_crypto_simple.csv) vs Socket (benchmark_operations.csv)")
    print("=" * 95)

    # ── Section 1: Classic Operations — Same libsodium library ──
    print(f"\n  ┌─ Classic Ops (libsodium — compared, {TOLERANCE_CLASSIC*100:.0f}% tolerance, KeyGen {TOLERANCE_KEYGEN*100:.0f}%) ────────┐")
    print(f"  │  Both benchmarks use libsodium (socket via crypto_libsodium.c override).    │")
    print(f"  │  Socket has additional EDHOC wrapper overhead (buffer copies, CBOR, etc.).   │")
    print(f"  │  KeyGen: socket also does SHA-256 seed expansion + RFC 7748 clamping.        │")
    print(f"  └────────────────────────────────────────────────────────────────────────────────┘")
    print(f"  {'Operation':<28} {'Standalone':>12} {'Socket':>12} {'Diff%':>8} {'Tol%':>6} {'Status':>8}")
    print(f"  {'─'*26} {'─'*12} {'─'*12} {'─'*8} {'─'*6} {'─'*8}")

    passed = 0
    failed = 0
    skipped = 0

    for (algo, op), sock_key, category in COMPARE_MAP:
        if category not in ("classic", "keygen"):
            continue
        label = f"{algo}/{op}"
        sa_val = standalone.get((algo, op))
        so_val = socket_ops.get(sock_key)
        tolerance = TOLERANCE_KEYGEN if category == "keygen" else TOLERANCE_CLASSIC
        tol_pct = tolerance * 100

        if sa_val is None or so_val is None or so_val == 0:
            print(f"  {label:<28} {'N/A':>12} {'N/A':>12} {'':>8} {'':>6} {'SKIP':>8}")
            skipped += 1
            continue

        diff_pct = abs(sa_val - so_val) / max(sa_val, so_val) * 100
        ok = diff_pct <= tol_pct
        status = "✅ PASS" if ok else "❌ FAIL"

        if ok:
            passed += 1
        else:
            failed += 1

        print(f"  {label:<28} {sa_val:>11.3f}µ {so_val:>11.3f}µ {diff_pct:>7.1f}% {tol_pct:>5.0f}% {status}")

    # ── Section 2: PQ Operations — Same PQClean library ──
    print(f"\n  ┌─ PQ Ops (Same PQClean Library — compared, {TOLERANCE_PQ*100:.0f}% tolerance) ──────────────────┐")
    print(f"  │  Both benchmarks call PQClean ML-KEM-768 / ML-DSA-65 directly.             │")
    print(f"  │  Standalone compiled at -O3, EDHOC PQClean sources also at -O3.            │")
    print(f"  └────────────────────────────────────────────────────────────────────────────────┘")
    print(f"  {'Operation':<28} {'Standalone':>12} {'Socket':>12} {'Diff%':>8} {'Tol%':>6} {'Status':>8}")
    print(f"  {'─'*26} {'─'*12} {'─'*12} {'─'*8} {'─'*6} {'─'*8}")

    for (algo, op), sock_key, category in COMPARE_MAP:
        if category != "pq":
            continue
        label = f"{algo}/{op}"
        sa_val = standalone.get((algo, op))
        so_val = socket_ops.get(sock_key)
        tol_pct = TOLERANCE_PQ * 100

        if sa_val is None or so_val is None or so_val == 0:
            print(f"  {label:<28} {'N/A':>12} {'N/A':>12} {'':>8} {'':>6} {'SKIP':>8}")
            skipped += 1
            continue

        diff_pct = abs(sa_val - so_val) / max(sa_val, so_val) * 100
        ok = diff_pct <= tol_pct
        status = "✅ PASS" if ok else "❌ FAIL"

        if ok:
            passed += 1
        else:
            failed += 1

        print(f"  {label:<28} {sa_val:>11.3f}µ {so_val:>11.3f}µ {diff_pct:>7.1f}% {tol_pct:>5.0f}% {status}")

    total = passed + failed
    print(f"\n{'='*95}")
    print(f"  Overall Results: {passed}/{total} passed, {failed}/{total} failed, {skipped} skipped")

    if failed == 0:
        print("  ✅ All operation timings are consistent between benchmarks!")
    else:
        print("  ⚠️  Some timings exceed tolerance. Check:")
        print("    1. Both PQClean sources compiled at -O3")
        print("    2. No background load during benchmarks")
        print("    3. Same machine for both runs")

    print()
    print("  NOTE: Both benchmarks now use the same crypto libraries:")
    print("        Classic: libsodium (socket uses crypto_libsodium.c override)")
    print("        PQ:      PQClean ML-KEM-768 / ML-DSA-65 (compiled at -O3)")
    print("        Socket overhead from EDHOC wrapper (CBOR, buffers, etc.) is expected.")
    print(f"{'='*95}")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
