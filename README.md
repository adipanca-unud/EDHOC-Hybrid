# EDHOC-Hybrid (RFC 9528)

Hybrid EDHOC implementation (classic + post-quantum) built on top of
[uoscore-uedhoc](https://github.com/eriptic/uoscore-uedhoc). Classic paths use
libsodium for X25519/Ed25519/HKDF-SHA256; PQ paths use PQClean (ML-KEM-768 &
ML-DSA-65) with mbedTLS AES-CCM for symmetric encryption.

## Variants & Crypto Stacks

| Menu | Variant | Key Agreement / Auth | Sign / MAC | HKDF & Hash | AEAD |
|------|---------|----------------------|------------|-------------|------|
| 1 | Type 0 Classic (Sig-Sig) | X25519 (ephemeral) | Ed25519 | HKDF-HMAC-SHA256 (libsodium) | AES-CCM-16-64-128 (mbedTLS) |
| 2 | Type 3 Classic (MAC-MAC) | X25519 (static DH for MAC) | HMAC/X25519 | HKDF-HMAC-SHA256 (libsodium) | AES-CCM-16-64-128 (mbedTLS) |
| 4 | Type 0 PQ (KEM Sig-like) | ML-KEM-768 (PQClean) + long-term KEM auth | ML-DSA-65 (PQClean) | HKDF-HMAC-SHA256 (libsodium) / SHA-256 | AES-CCM-16-64-128 (mbedTLS) |
| 5 | Type 3 PQ (KEM MAC-MAC) | ML-KEM-768 (PQClean) | MAC with KEM-derived keys | HKDF-HMAC-SHA256 (libsodium) / SHA-256 | AES-CCM-16-64-128 (mbedTLS) |

Menu **3** runs classic benchmarks (Types 0 & 3). Menu **6** runs full benchmarks
(classic + PQ) and writes CSVs under `output/`.

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
```

Benchmark output CSVs:

- `output/benchmark_operations.csv`
- `output/benchmark_overhead.csv`
- `output/benchmark_handshake.csv`

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
│   └── edhoc_type3_pq.h      # PQ KEM MAC-MAC
├── src/
│   ├── main.c                # Menu + dispatcher (1–6)
│   ├── edhoc_common.c
│   ├── edhoc_type0_classic.c
│   ├── edhoc_type3_classic.c
│   ├── edhoc_type0_pq.c
│   ├── edhoc_type3_pq.c
│   └── edhoc_benchmark.c     # Benchmark harness
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
