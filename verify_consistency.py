#!/usr/bin/env python3
"""Verify consistency across all benchmark CSV files."""
import csv, os, sys

OUTPUT = "output"

def load_csv(name):
    path = os.path.join(OUTPUT, name)
    if not os.path.exists(path):
        print(f"  WARNING MISSING: {path}")
        return []
    with open(path) as f:
        return list(csv.DictReader(f))

# Expected call counts per (type, role) -> {operation: count}
EXPECTED = {
    ("Type0_SigSig","Initiator"): {"KeyGen":1,"AEAD_Enc":1,"AEAD_Dec":0,"Signature":1,"Verification":1,"ECDH":2,"HKDF":8,"Hash":4},
    ("Type0_SigSig","Responder"): {"KeyGen":1,"AEAD_Enc":0,"AEAD_Dec":1,"Signature":1,"Verification":1,"ECDH":2,"HKDF":8,"Hash":4},
    ("Type3_MACMAC","Initiator"): {"KeyGen":1,"AEAD_Enc":1,"AEAD_Dec":0,"Signature":0,"Verification":0,"ECDH":4,"HKDF":10,"Hash":4},
    ("Type3_MACMAC","Responder"): {"KeyGen":1,"AEAD_Enc":0,"AEAD_Dec":1,"Signature":0,"Verification":0,"ECDH":4,"HKDF":10,"Hash":4},
    ("Type0_PQ","Initiator"): {"PQ_KeyGen":1,"PQ_Encaps":1,"PQ_Decaps":1,"PQ_Signature":1,"PQ_Verification":1,"PQ_AEAD_Enc":2,"PQ_AEAD_Dec":1,"PQ_HKDF":8,"PQ_Hash":3},
    ("Type0_PQ","Responder"): {"PQ_KeyGen":1,"PQ_Encaps":1,"PQ_Decaps":1,"PQ_Signature":1,"PQ_Verification":1,"PQ_AEAD_Enc":1,"PQ_AEAD_Dec":2,"PQ_HKDF":8,"PQ_Hash":3},
    ("Type3_PQ","Initiator"): {"PQ_KeyGen":1,"PQ_Encaps":1,"PQ_Decaps":2,"PQ_Signature":0,"PQ_Verification":0,"PQ_AEAD_Enc":2,"PQ_AEAD_Dec":1,"PQ_HKDF":8,"PQ_Hash":3},
    ("Type3_PQ","Responder"): {"PQ_KeyGen":1,"PQ_Encaps":2,"PQ_Decaps":1,"PQ_Signature":0,"PQ_Verification":0,"PQ_AEAD_Enc":1,"PQ_AEAD_Dec":2,"PQ_HKDF":8,"PQ_Hash":3},
    ("Type3_Hybrid","Initiator"): {"KeyGen":1,"AEAD_Enc":1,"AEAD_Dec":1,"ECDH":4,"HKDF":10,"Hash":3,"PQ_KeyGen":1,"PQ_Encaps":0,"PQ_Decaps":1},
    ("Type3_Hybrid","Responder"): {"KeyGen":1,"AEAD_Enc":1,"AEAD_Dec":1,"ECDH":4,"HKDF":10,"Hash":3,"PQ_KeyGen":0,"PQ_Encaps":1,"PQ_Decaps":0},
}

def check_call_counts(rows, label):
    errors = 0
    for row in rows:
        key = (row["type"], row["role"])
        op = row["operation"]
        calls = int(row["calls_per_handshake"])
        if key in EXPECTED and op in EXPECTED[key]:
            exp = EXPECTED[key][op]
            if calls != exp:
                print(f"  FAIL {label}: {key[0]} {key[1]} {op}: expected {exp}, got {calls}")
                errors += 1
    return errors

def check_socket_vs_p2p_counts(sck_rows, p2p_rows):
    errors = 0
    sck_map = {}
    for r in sck_rows:
        sck_map[(r["type"], r["role"], r["operation"])] = int(r["calls_per_handshake"])
    for r in p2p_rows:
        key = (r["type"], r["role"], r["operation"])
        p2p_calls = int(r["calls_per_handshake"])
        if key in sck_map and sck_map[key] != p2p_calls:
            print(f"  FAIL Socket vs P2P mismatch: {key}: socket={sck_map[key]}, p2p={p2p_calls}")
            errors += 1
    return errors

def check_handshake_totals(rows, label):
    errors = 0
    for row in rows:
        proc = float(row["processing_us"])
        txrx = float(row["txrx_us"])
        pre = float(row["precomputation_us"])
        ovh = float(row["overhead_us"])
        total = float(row["total_us"])
        computed = proc + txrx + pre + ovh
        diff = abs(total - computed)
        if diff > 1.0:
            print(f"  FAIL {label}: {row['type']} {row.get('role','')} total={total:.1f} != sum={computed:.1f} (diff={diff:.1f})")
            errors += 1
    return errors

def check_timing_reasonableness(crypto, ops, label):
    """Check ops timings are within 20x of crypto_simple reference."""
    crypto_map = {}
    for r in crypto:
        crypto_map[(r["algorithm"], r["operation"])] = float(r["avg_us"])
    OP_MAP = {
        "KeyGen": ("X25519","Keygen"), "ECDH": ("X25519","Shared Secret"),
        "Signature": ("Ed25519","Signature"), "Verification": ("Ed25519","Verification"),
        "PQ_KeyGen": ("ML-KEM-768","Keygen"), "PQ_Encaps": ("ML-KEM-768","Encap"),
        "PQ_Decaps": ("ML-KEM-768","Decap"), "PQ_Signature": ("ML-DSA-65","Signature"),
        "PQ_Verification": ("ML-DSA-65","Verification"),
    }
    warnings = 0
    for r in ops:
        op = r["operation"]
        avg = float(r["avg_time_us"])
        if int(r["calls_per_handshake"]) == 0 or avg == 0:
            continue
        if op in OP_MAP and OP_MAP[op] in crypto_map:
            ref = crypto_map[OP_MAP[op]]
            ratio = avg / ref if ref > 0 else 999
            if ratio < 0.05 or ratio > 50:
                print(f"  WARN {label}: {r['type']} {op} avg={avg:.1f} vs ref={ref:.1f} (ratio={ratio:.1f}x)")
                warnings += 1
    return warnings

print("=" * 60)
print("  Benchmark CSV Consistency Verification")
print("=" * 60)

total_errors = 0
total_warnings = 0

for role in ["initiator", "responder"]:
    print(f"\n-- {role.upper()} --")
    crypto = load_csv(f"benchmark_crypto_simple_{role}.csv")
    sck_ops = load_csv(f"benchmark_operations_{role}.csv")
    sck_hs = load_csv(f"benchmark_handshake_{role}.csv")
    p2p_ops = load_csv(f"p2p_operations_{role}.csv")
    p2p_hs = load_csv(f"p2p_handshake_{role}.csv")

    print(f"  [1] Socket call counts:")
    e = check_call_counts(sck_ops, f"sck_{role}")
    print(f"  OK" if e == 0 else "")
    total_errors += e

    print(f"  [2] P2P call counts:")
    e = check_call_counts(p2p_ops, f"p2p_{role}")
    print(f"  OK" if e == 0 else "")
    total_errors += e

    print(f"  [3] Socket vs P2P consistency:")
    e = check_socket_vs_p2p_counts(sck_ops, p2p_ops)
    print(f"  OK" if e == 0 else "")
    total_errors += e

    print(f"  [4] Timing reasonableness:")
    w = check_timing_reasonableness(crypto, sck_ops, f"sck_{role}")
    w += check_timing_reasonableness(crypto, p2p_ops, f"p2p_{role}")
    print(f"  OK" if w == 0 else "")
    total_warnings += w

    print(f"  [5] Socket handshake totals:")
    e = check_handshake_totals(sck_hs, f"sck_{role}")
    print(f"  OK" if e == 0 else "")
    total_errors += e

    print(f"  [6] P2P handshake totals:")
    e = check_handshake_totals(p2p_hs, f"p2p_{role}")
    print(f"  OK" if e == 0 else "")
    total_errors += e

print(f"\n{'=' * 60}")
print(f"  RESULT: {total_errors} errors, {total_warnings} warnings")
if total_errors == 0:
    print(f"  ALL CHECKS PASSED")
else:
    print(f"  SOME CHECKS FAILED")
print(f"{'=' * 60}")
sys.exit(0 if total_errors == 0 else 1)
