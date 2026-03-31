# EDHOC-Hybrid (RFC 9528)

Hybrid EDHOC implementation (classic + post-quantum + hybrid) built on top of
[uoscore-uedhoc](https://github.com/eriptic/uoscore-uedhoc). Classic paths use
libsodium for X25519/Ed25519/HKDF-SHA256; PQ paths use PQClean (ML-KEM-768 &
ML-DSA-65) with mbedTLS AES-CCM for symmetric encryption; the hybrid path chains
X25519 ECDHE with ML-KEM-768 KEM for EDHOC Type 3 MAC-MAC.

## Variants & Crypto Stacks

| Menu | Variant | Key Agreement / Auth | Sign / MAC | HKDF & Hash | AEAD |
|------|---------|----------------------|------------|-------------|------|
| 1 | Type 0 Classic (Sig-Sig) | X25519 (ephemeral) | Ed25519 | HKDF-HMAC-SHA256 (libsodium) | AES-CCM-16-64-128 (mbedTLS) |
| 2 | Type 3 Classic (MAC-MAC) | X25519 (static DH for MAC) | HMAC/X25519 | HKDF-HMAC-SHA256 (libsodium) | AES-CCM-16-64-128 (mbedTLS) |
| 4 | Type 0 PQ (KEM Sig-like) | ML-KEM-768 (PQClean) + long-term KEM auth | ML-DSA-65 (PQClean) | HKDF-HMAC-SHA256 (libsodium) / SHA-256 | AES-CCM-16-64-128 (mbedTLS) |
| 5 | Type 3 PQ (KEM MAC-MAC) | ML-KEM-768 (PQClean) | MAC with KEM-derived keys | HKDF-HMAC-SHA256 (libsodium) / SHA-256 | AES-CCM-16-64-128 (mbedTLS) |
| 7 | Type 3 Hybrid (MAC-MAC) | X25519 ECDHE + ML-KEM-768 KEM (chained HKDF-Extract) | MAC from hybrid secrets | HKDF-HMAC-SHA256 (libsodium) | AES-CCM-16-64-128 (mbedTLS) |

Menu **3** runs classic benchmarks (Types 0 & 3). Menu **6** runs full benchmarks
(classic + PQ). Menu **7** runs a standalone hybrid handshake. Menu **8** runs
full benchmarks across classic, PQ, and hybrid, writing CSVs under `output/`.

## Prerequisites

- GCC (C11), GNU Make
- Git (for submodules)
- `libsodium-dev` (X25519, Ed25519, HKDF-SHA256)
- pthreads (POSIX threads)
- Python 3 (for `verify_benchmark.py`)

## Clone with Submodules (liboqs removed)

This repo vendors only the pieces we use: `uoscore-uedhoc` and `PQClean`
(plus nested deps inside `uoscore-uedhoc`). The `liboqs` submodule has been
removed; PQ flows rely on PQClean by default.

```bash
git clone --recursive https://github.com/<your-user>/EDHOC-Hybrid.git
cd EDHOC-Hybrid
# If you pulled without --recursive
git submodule update --init --recursive
```

## Build

```bash
make                    # Build (default: USE_PQCLEAN=1, libsodium HKDF)
make USE_PQCLEAN=1 -j$(nproc)   # Explicit PQClean path
make clean              # Clean application objects
make lib-clean          # Clean everything (app + uoscore-uedhoc build)
```

Notes:
- liboqs is **not** vendored anymore. The supported/tested path is `USE_PQCLEAN=1`
        (default). If you experiment with `USE_PQCLEAN=0`, install liboqs separately
        and adjust include/library paths as needed.
- Enable verbose protocol debug by uncommenting `DEBUG_PRINT` in
        `lib/uoscore-uedhoc/makefile_config.mk` or adding `-DDEBUG_PRINT` to `CFLAGS`.

## Run

Interactive menu:

```bash
./build/edhoc_hybrid
```

Direct (skip menu):

```bash
./build/edhoc_hybrid 1   # Type 0 Classic (Sig-Sig)
./build/edhoc_hybrid 2   # Type 3 Classic (MAC-MAC)
./build/edhoc_hybrid 3   # Benchmark Classic (Types 0 & 3)
./build/edhoc_hybrid 4   # Type 0 PQ (ML-KEM-768 + ML-DSA-65)
./build/edhoc_hybrid 5   # Type 3 PQ (ML-KEM-768 MAC-MAC)
./build/edhoc_hybrid 6   # Full Benchmark (Classic + PQ)
./build/edhoc_hybrid 7   # Type 3 Hybrid (X25519 + ML-KEM-768)
./build/edhoc_hybrid 8   # Full Benchmark (Classic + PQ + Hybrid)
```

Benchmark output CSVs:

- `output/benchmark_operations.csv`
- `output/benchmark_overhead.csv`
- `output/benchmark_handshake.csv`

## Performance notes (classic vs PQ vs hybrid)

- **KEM counts drive latency.** Hybrid Type 3 uses 1 KEM.Enc (Responder) + 1 KEM.Dec (Initiator). PQ Type 3 uses 3 KEMs per side. With ML-KEM-768 ≈ 150–200 µs/op, Hybrid saves ~400–500 µs over PQ Type 3.
- **ECDH backbone.** All X25519 comes from libsodium (`crypto_scalarmult_curve25519`) with the same compiler flags. Hybrid keeps two ECDH calls per side and one KEM anchor for PQ security.
- **Why Hybrid ECDH looks very small (≈18–23 µs).** The ops micro-benchmark hits the bare crypto call with pre-made keys (no CBOR/PSA setup), so libsodium’s optimized scalar-mult lands in the ~20 µs range. Classic Type 3 includes a slightly heavier wrapper path, so its per-op number is higher.
- **HKDF load.** Hybrid runs 10 HKDFs (~95–127 µs total): heavier than PQ (8 HKDFs, ~30–40 µs) but lighter than classic (10 HKDFs with larger buffers, ~500–700 µs).
- **What the 1 µs Encap/Decap rows are.** Those are the lightweight AEAD wrap/unwrap inside EDHOC; PQ costs live under `PQ_Encaps`/`PQ_Decaps` (100–170 µs each).
- **Scope of timings.** Benchmarks measure crypto only (no CBOR encode/decode, no network I/O). This favors direct crypto costs and makes the KEM-count difference visible.

## Verify Benchmark Consistency

```bash
python3 verify_benchmark.py
```

Runs six cross-table checks (operations ↔ overhead ↔ handshake) with 1 µs tolerance.

## Project Structure (trimmed)

```
EDHOC-Hybrid/
├── Makefile                  # Top-level build (defaults to PQClean)
├── README.md
├── include/
│   ├── edhoc_common.h        # Shared helpers
│   ├── edhoc_type0_classic.h # Classic Sig-Sig
│   ├── edhoc_type3_classic.h # Classic MAC-MAC
│   ├── edhoc_type0_pq.h      # PQ KEM Sig-like
│   ├── edhoc_type3_pq.h      # PQ KEM MAC-MAC
│   └── edhoc_type3_hybrid.h  # Hybrid MAC-MAC (ECDHE + KEM)
├── src/
│   ├── main.c                # Menu + dispatcher (1–8)
│   ├── edhoc_common.c
│   ├── edhoc_type0_classic.c
│   ├── edhoc_type3_classic.c
│   ├── edhoc_type0_pq.c
│   ├── edhoc_type3_pq.c
│   ├── edhoc_type3_hybrid.c  # Hybrid Type 3 implementation
│   └── edhoc_benchmark.c     # Benchmark harness (classic + PQ + hybrid)
├── lib/
│   ├── PQClean/              # PQ KEM/Signature (ML-KEM-768, ML-DSA-65)
│   └── uoscore-uedhoc/       # Core EDHOC/OSCORE library + nested externals
└── output/                   # Benchmark CSVs
```

### External Dependencies (via submodules or system)

| Component | Source | Purpose |
|-----------|--------|---------|
| uoscore-uedhoc | submodule | Core EDHOC/OSCORE logic
| PQClean | submodule | ML-KEM-768, ML-DSA-65 implementations
| mbedTLS | `lib/uoscore-uedhoc/externals/mbedtls` | AES-CCM, PSA crypto
| zcbor | `lib/uoscore-uedhoc/externals/zcbor` | CBOR codec
| tinycrypt | `lib/uoscore-uedhoc/externals/tinycrypt` | Lightweight crypto (optional paths)
| libsodium | system (`libsodium-dev`) | X25519, Ed25519, HKDF-HMAC-SHA256

## License

uoscore-uedhoc is dual-licensed under Apache-2.0 and MIT; follow upstream terms.
