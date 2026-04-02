#!/usr/bin/env python3
"""
Verify consistency between standalone crypto benchmark (benchmark_crypto_simple.csv)
and EDHOC socket benchmark (benchmark_operations.csv).

Both must use the same -O2 optimization flag.

NOTE: Socket benchmark measures crypto through the uoscore-uedhoc EDHOC library
wrappers, which add overhead (CBOR, key format conversion, etc.).
Standalone benchmark calls libsodium/PQClean APIs directly.
Therefore, some deviation is expected — especially for Ed25519 Sign which goes
through sign(EdDSA,...) wrapper in EDHOC vs crypto_sign_ed25519_detached() standalone.
"""

import csv
import sys
import os

# ─── Configuration ───
STANDALONE_CSV = "output/benchmark_crypto_simple.csv"
SOCKET_CSV     = "output/benchmark_operations.csv"
TOLERANCE_DIRECT = 0.30   # 30% for direct API calls (PQClean → PQClean)
TOLERANCE_WRAPPED = 0.60  # 60% for wrapper-mediated calls (libsodium → uoscore-uedhoc)

# Mapping: (standalone_algorithm, standalone_operation) →
#          (socket_operation_name, is_wrapped)
# is_wrapped = True means socket uses EDHOC wrapper, higher tolerance expected
COMPARE_MAP = [
    # Classic (socket uses uoscore-uedhoc wrappers)
    (("X25519",    "Keygen"),        "KeyGen",        True),
    (("Ed25519",   "Signature"),     "Signature",     True),   # sign(EdDSA,...) wrapper
    (("Ed25519",   "Verification"),  "Verification",  True),   # verify(EdDSA,...) wrapper
    (("X25519",    "Shared Secret"), "ECDH",          True),   # shared_secret_derive() wrapper
    # PQ (both call PQClean directly — should be very close)
    (("ML-KEM-768", "Keygen"),       "PQ_KeyGen",     False),
    (("ML-KEM-768", "Encap"),        "PQ_Encaps",     False),
    (("ML-KEM-768", "Decap"),        "PQ_Decaps",     False),
    (("ML-DSA-65",  "Signature"),    "PQ_Signature",  False),
    (("ML-DSA-65",  "Verification"), "PQ_Verification",False),
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

    print("=" * 90)
    print("  Benchmark Consistency Verification")
    print("  Standalone (benchmark_crypto_simple.csv) vs Socket (benchmark_operations.csv)")
    print("=" * 90)

    print(f"\n  {'Operation':<28} {'Standalone':>12} {'Socket':>12} {'Diff%':>8} {'Tol%':>6} {'Status':>8}")
    print(f"  {'─'*26} {'─'*12} {'─'*12} {'─'*8} {'─'*6} {'─'*8}")

    passed = 0
    failed = 0
    skipped = 0

    for (algo, op), sock_key, is_wrapped in COMPARE_MAP:
        label = f"{algo}/{op}"
        sa_val = standalone.get((algo, op))
        so_val = socket_ops.get(sock_key)
        tol = TOLERANCE_WRAPPED if is_wrapped else TOLERANCE_DIRECT

        if sa_val is None or so_val is None or so_val == 0:
            print(f"  {label:<28} {'N/A':>12} {'N/A':>12} {'':>8} {'':>6} {'SKIP':>8}")
            skipped += 1
            continue

        diff_pct = abs(sa_val - so_val) / max(sa_val, so_val) * 100
        tol_pct = tol * 100
        ok = diff_pct <= tol_pct
        status = "✅ PASS" if ok else "❌ FAIL"

        if ok:
            passed += 1
        else:
            failed += 1

        print(f"  {label:<28} {sa_val:>11.3f}µ {so_val:>11.3f}µ {diff_pct:>7.1f}% {tol_pct:>5.0f}% {status}")

    total = passed + failed
    print(f"\n{'='*90}")
    print(f"  Results: {passed}/{total} passed, {failed}/{total} failed, {skipped} skipped")

    if failed == 0:
        print("  ✅ All comparable timings are consistent!")
        print()
        print("  NOTE: Wrapped operations (Ed25519 Sign/Verify, X25519 ECDH, KeyGen)")
        print("        are slower in socket benchmark because they go through uoscore-uedhoc")
        print("        EDHOC library wrappers. This is expected and not a bug.")
    else:
        print("  ⚠️  Some timings exceed tolerance. Check:")
        print("    1. Both builds use -O2 (Makefile line 71, makefile_config.mk OPT)")
        print("    2. No background load during benchmarks")
        print("    3. Same machine for both runs")
    print(f"{'='*90}")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
