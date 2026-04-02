#!/usr/bin/env python3
"""
verify_crypto_benchmark.py
==========================
Verify and visualize the pure cryptographic operations benchmark results.

Reads output/benchmark_crypto_ops.csv and benchmark_crypto_matrix.csv,
prints a summary table, and optionally generates bar charts (if matplotlib
is available).

Usage:
    python3 verify_crypto_benchmark.py
"""

import csv
import os
import sys

OUTPUT_DIR = "output"
OPS_CSV = os.path.join(OUTPUT_DIR, "benchmark_crypto_ops.csv")
MATRIX_CSV = os.path.join(OUTPUT_DIR, "benchmark_crypto_matrix.csv")


def load_ops_csv(path):
    """Load the detailed ops CSV into a list of dicts."""
    rows = []
    with open(path, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    return rows


def load_matrix_csv(path):
    """Load the matrix CSV (operations × algorithms)."""
    with open(path, "r") as f:
        reader = csv.reader(f)
        header = next(reader)
        data = {}
        for row in reader:
            op = row[0]
            vals = {}
            for i, col in enumerate(header[1:], 1):
                vals[col] = row[i] if i < len(row) else "N/A"
            data[op] = vals
    return header[1:], data


def print_summary(columns, matrix):
    """Print a nicely formatted summary table."""
    # Column widths
    op_width = max(len(op) for op in matrix.keys()) + 2
    col_width = 20

    # Header
    print("\n" + "=" * (op_width + col_width * len(columns) + len(columns) + 1))
    print("  PURE CRYPTOGRAPHIC OPERATIONS BENCHMARK — RESULTS SUMMARY")
    print("=" * (op_width + col_width * len(columns) + len(columns) + 1))

    # Column headers
    hdr = f"{'Operation':<{op_width}}│"
    for col in columns:
        col_short = col.replace(" (µs)", "")
        hdr += f" {col_short:>{col_width-2}} │"
    print(hdr)
    print("─" * (op_width) + "┼" + ("─" * col_width + "┼") * len(columns))

    # Data rows
    for op, vals in matrix.items():
        row = f"{op:<{op_width}}│"
        for col in columns:
            v = vals.get(col, "N/A")
            if v == "N/A":
                row += f" {'N/A':>{col_width-2}} │"
            else:
                row += f" {float(v):>{col_width-5}.3f} µs │"
        print(row)

    print("─" * (op_width) + "┴" + ("─" * col_width + "┴") * len(columns))


def verify_results(ops_data):
    """Run sanity checks on the benchmark results."""
    checks_passed = 0
    checks_total = 0

    print("\n  SANITY CHECKS")
    print("  " + "=" * 60)

    # Check 1: PQ keygen should be slower than classical keygen
    checks_total += 1
    x25519_keygen = None
    mlkem_keygen = None
    for r in ops_data:
        if r["operation"] == "Keygen" and r["algorithm"] == "X25519" and r["avg_us"] != "N/A":
            x25519_keygen = float(r["avg_us"])
        if r["operation"] == "Keygen" and r["algorithm"] == "ML-KEM-768" and r["avg_us"] != "N/A":
            mlkem_keygen = float(r["avg_us"])
    if x25519_keygen and mlkem_keygen:
        if mlkem_keygen > x25519_keygen:
            print(f"  ✓ ML-KEM-768 keygen ({mlkem_keygen:.1f}µs) > X25519 keygen ({x25519_keygen:.1f}µs)")
            checks_passed += 1
        else:
            print(f"  ✗ ML-KEM-768 keygen ({mlkem_keygen:.1f}µs) should be > X25519 keygen ({x25519_keygen:.1f}µs)")

    # Check 2: ML-DSA signature should be much slower than Ed25519
    checks_total += 1
    ed_sig = None
    mldsa_sig = None
    for r in ops_data:
        if r["operation"] == "Signature" and r["algorithm"] == "Ed25519" and r["avg_us"] != "N/A":
            ed_sig = float(r["avg_us"])
        if r["operation"] == "Signature" and r["algorithm"] == "ML-DSA-65" and r["avg_us"] != "N/A":
            mldsa_sig = float(r["avg_us"])
    if ed_sig and mldsa_sig:
        if mldsa_sig > ed_sig:
            ratio = mldsa_sig / ed_sig
            print(f"  ✓ ML-DSA-65 sign ({mldsa_sig:.1f}µs) > Ed25519 sign ({ed_sig:.1f}µs) [{ratio:.1f}x slower]")
            checks_passed += 1
        else:
            print(f"  ✗ ML-DSA-65 sign should be slower than Ed25519")

    # Check 3: Hybrid keygen ≈ X25519 keygen + ML-KEM keygen
    checks_total += 1
    hybrid_keygen = None
    for r in ops_data:
        if r["operation"] == "Keygen" and r["algorithm"] == "X25519+ML-KEM-768" and r["avg_us"] != "N/A":
            hybrid_keygen = float(r["avg_us"])
    if x25519_keygen and mlkem_keygen and hybrid_keygen:
        expected = x25519_keygen + mlkem_keygen
        tolerance = 0.30  # 30% tolerance
        if abs(hybrid_keygen - expected) / expected < tolerance:
            print(f"  ✓ Hybrid keygen ({hybrid_keygen:.1f}µs) ≈ X25519+ML-KEM ({expected:.1f}µs) [within {tolerance*100:.0f}%]")
            checks_passed += 1
        else:
            print(f"  ~ Hybrid keygen ({hybrid_keygen:.1f}µs) vs expected ({expected:.1f}µs) [outside tolerance]")

    # Check 4: Symmetric ops should be fast (< 5 µs)
    checks_total += 1
    sym_ops = ["HKDF-Extract", "HKDF-Expand", "Hash (SHA-256)", "AEAD Encrypt", "AEAD Decrypt"]
    all_fast = True
    for r in ops_data:
        if r["operation"] in sym_ops and r["avg_us"] != "N/A":
            if float(r["avg_us"]) > 5.0:
                all_fast = False
                print(f"  ✗ {r['operation']} for {r['algorithm']} is too slow: {r['avg_us']}µs")
    if all_fast:
        print(f"  ✓ All symmetric operations < 5µs")
        checks_passed += 1

    # Check 5: All N/A values are in correct places
    checks_total += 1
    expected_na = {
        ("Encap", "Ed25519"), ("Decap", "Ed25519"),
        ("Encap", "ML-DSA-65"), ("Decap", "ML-DSA-65"),
        ("Signature", "X25519"), ("Verification", "X25519"),
        ("Signature", "ML-KEM-768"), ("Verification", "ML-KEM-768"),
        ("Signature", "X25519+ML-KEM-768"), ("Verification", "X25519+ML-KEM-768"),
        ("Key Exchange (full)", "Ed25519"), ("Key Exchange (full)", "ML-DSA-65"),
        ("Shared Secret Derivation", "Ed25519"), ("Shared Secret Derivation", "ML-DSA-65"),
    }
    na_correct = True
    for r in ops_data:
        key = (r["operation"], r["algorithm"])
        if r["avg_us"] == "N/A" and key not in expected_na:
            na_correct = False
            print(f"  ✗ Unexpected N/A: {r['operation']} / {r['algorithm']}")
        if r["avg_us"] != "N/A" and key in expected_na:
            na_correct = False
            print(f"  ✗ Should be N/A: {r['operation']} / {r['algorithm']}")
    if na_correct:
        print(f"  ✓ All N/A values are correctly placed")
        checks_passed += 1

    print(f"\n  Result: {checks_passed}/{checks_total} checks passed\n")
    return checks_passed == checks_total


def try_plot(columns, matrix):
    """Generate bar charts if matplotlib is available."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        print("  (matplotlib not available, skipping chart generation)")
        return

    col_labels = [c.replace(" (µs)", "") for c in columns]

    # ── Chart 1: Asymmetric operations (Keygen, Encap/Decap, Sign, Verify) ──
    asym_ops = ["Keygen", "Encap", "Decap", "Signature", "Verification"]
    fig, axes = plt.subplots(1, len(asym_ops), figsize=(20, 6), sharey=False)
    fig.suptitle("Asymmetric Cryptographic Operations Benchmark (µs)", fontsize=14, fontweight="bold")

    colors = ["#2196F3", "#4CAF50", "#FF9800", "#F44336", "#9C27B0"]

    for idx, op in enumerate(asym_ops):
        ax = axes[idx]
        vals = []
        labels = []
        bar_colors = []
        if op in matrix:
            for i, col in enumerate(columns):
                v = matrix[op].get(col, "N/A")
                if v != "N/A":
                    vals.append(float(v))
                    labels.append(col_labels[i])
                    bar_colors.append(colors[i])

        if vals:
            bars = ax.bar(range(len(vals)), vals, color=bar_colors, width=0.6)
            ax.set_xticks(range(len(vals)))
            ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=8)
            for bar, val in zip(bars, vals):
                ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                       f"{val:.1f}", ha="center", va="bottom", fontsize=7)
        ax.set_title(op, fontsize=10, fontweight="bold")
        ax.set_ylabel("Time (µs)")

    plt.tight_layout()
    chart_path = os.path.join(OUTPUT_DIR, "benchmark_crypto_asymmetric.png")
    plt.savefig(chart_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  Chart saved: {chart_path}")

    # ── Chart 2: Symmetric operations ──
    sym_ops = ["HKDF-Extract", "HKDF-Expand", "Hash (SHA-256)", "AEAD Encrypt", "AEAD Decrypt"]
    fig, ax = plt.subplots(figsize=(14, 6))
    fig.suptitle("Symmetric Cryptographic Operations Benchmark (µs)", fontsize=14, fontweight="bold")

    x = np.arange(len(sym_ops))
    width = 0.15
    for i, col in enumerate(columns):
        vals = []
        for op in sym_ops:
            v = matrix.get(op, {}).get(col, "N/A")
            vals.append(float(v) if v != "N/A" else 0)
        bars = ax.bar(x + i * width, vals, width, label=col_labels[i], color=colors[i])

    ax.set_ylabel("Time (µs)")
    ax.set_xticks(x + width * 2)
    ax.set_xticklabels(sym_ops, rotation=30, ha="right")
    ax.legend(fontsize=9)
    ax.grid(axis="y", alpha=0.3)

    plt.tight_layout()
    chart_path = os.path.join(OUTPUT_DIR, "benchmark_crypto_symmetric.png")
    plt.savefig(chart_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  Chart saved: {chart_path}")

    # ── Chart 3: Key Exchange comparison ──
    ke_ops = ["Key Exchange (full)", "Shared Secret Derivation"]
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    fig.suptitle("Key Exchange & Secret Derivation Benchmark (µs)", fontsize=14, fontweight="bold")

    for idx, op in enumerate(ke_ops):
        ax = axes[idx]
        vals = []
        labels = []
        bar_colors = []
        if op in matrix:
            for i, col in enumerate(columns):
                v = matrix[op].get(col, "N/A")
                if v != "N/A":
                    vals.append(float(v))
                    labels.append(col_labels[i])
                    bar_colors.append(colors[i])
        if vals:
            bars = ax.bar(range(len(vals)), vals, color=bar_colors, width=0.5)
            ax.set_xticks(range(len(vals)))
            ax.set_xticklabels(labels, rotation=30, ha="right", fontsize=9)
            for bar, val in zip(bars, vals):
                ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.3,
                       f"{val:.2f}", ha="center", va="bottom", fontsize=8)
        ax.set_title(op, fontsize=10, fontweight="bold")
        ax.set_ylabel("Time (µs)")

    plt.tight_layout()
    chart_path = os.path.join(OUTPUT_DIR, "benchmark_crypto_keyexchange.png")
    plt.savefig(chart_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  Chart saved: {chart_path}")


def main():
    if not os.path.exists(OPS_CSV):
        print(f"ERROR: {OPS_CSV} not found. Run the benchmark first:")
        print(f"  make -f Makefile.crypto_bench run")
        sys.exit(1)

    if not os.path.exists(MATRIX_CSV):
        print(f"ERROR: {MATRIX_CSV} not found.")
        sys.exit(1)

    print("\n  Loading benchmark results...")
    ops_data = load_ops_csv(OPS_CSV)
    columns, matrix = load_matrix_csv(MATRIX_CSV)

    print(f"  Loaded {len(ops_data)} data points from {OPS_CSV}")
    print(f"  Loaded {len(matrix)} operations × {len(columns)} algorithms from {MATRIX_CSV}")

    print_summary(columns, matrix)
    all_ok = verify_results(ops_data)
    try_plot(columns, matrix)

    if all_ok:
        print("  ✓ All verifications passed!\n")
    else:
        print("  ⚠ Some checks failed — review results above.\n")


if __name__ == "__main__":
    main()
