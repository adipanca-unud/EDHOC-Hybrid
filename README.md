# EDHOC-Hybrid (RFC 9528)

Hybrid EDHOC implementation (classic + post-quantum + hybrid) built on top of [uoscore-uedhoc](https://github.com/eriptic/uoscore-uedhoc).
Classic paths use libsodium for X25519/Ed25519/HKDF-SHA256; PQ paths use PQClean (ML-KEM-768 & ML-DSA-65) with mbedTLS AES-CCM for symmetric encryption; the hybrid path chains X25519 ECDHE with ML-KEM-768 KEM for EDHOC Type 3 MAC-MAC.




## Variants & Crypto Stacks

| Menu | Variant                  | Key Agreement / Auth                        | Sign / MAC                | HKDF & Hash                        | AEAD                        |
|------|--------------------------|---------------------------------------------|---------------------------|-------------------------------------|-----------------------------|
| 1    | Type 0 Classic (Sig-Sig) | X25519 (ephemeral)                          | Ed25519                   | HKDF-HMAC-SHA256 (libsodium)        | AES-CCM-16-64-128 (mbedTLS) |
| 2    | Type 3 Classic (MAC-MAC) | X25519 (static DH for MAC)                  | HMAC/X25519               | HKDF-HMAC-SHA256 (libsodium)        | AES-CCM-16-64-128 (mbedTLS) |
| 3    | Type 0 PQ (KEM Sig-like) | ML-KEM-768 (PQClean) + long-term KEM auth   | ML-DSA-65 (PQClean)       | HKDF-HMAC-SHA256 (libsodium)/SHA256 | AES-CCM-16-64-128 (mbedTLS) |
| 4    | Type 3 PQ (KEM MAC-MAC)  | ML-KEM-768 (PQClean)                        | MAC with KEM-derived keys | HKDF-HMAC-SHA256 (libsodium)/SHA256 | AES-CCM-16-64-128 (mbedTLS) |
| 5    | Type 3 Hybrid (MAC-MAC)  | X25519 ECDHE + ML-KEM-768 KEM (chained HKDF)| MAC from hybrid secrets   | HKDF-HMAC-SHA256 (libsodium)        | AES-CCM-16-64-128 (mbedTLS) |


Menu **6** runs the benchmark (TCP client-server) across all 5 variants. Menu **3** runs classic benchmarks (Types 0 & 3). Menu **6** runs full benchmarks

variants, writing CSVs under `output/`. (classic + PQ). Menu **7** runs a standalone hybrid handshake. Menu **8** runs

full benchmarks across classic, PQ, and hybrid, writing CSVs under `output/`.

## Prerequisites

## Prerequisites

- GCC (C11), GNU Make

- Git (for submodules)- GCC (C11), GNU Make

- `libsodium-dev` (X25519, Ed25519, HKDF-SHA256)- Git (for submodules)

- pthreads (POSIX threads)- `libsodium-dev` (X25519, Ed25519, HKDF-SHA256)

- Python 3 (for `verify_benchmark.py`)- pthreads (POSIX threads)

## Clone with Submodules (liboqs removed)

## Clone with Submodules (liboqs removed)

This repo vendors only the pieces we use: `uoscore-uedhoc` and `PQClean`

(plus nested deps inside `uoscore-uedhoc`). The `liboqs` submodule has beenThis repo vendors only the pieces we use: `uoscore-uedhoc` and `PQClean`

removed; PQ flows rely on PQClean by default.(plus nested deps inside `uoscore-uedhoc`). The `liboqs` submodule has been

removed; PQ flows rely on PQClean by default.

```bash

git clone --recursive https://github.com/<your-user>/EDHOC-Hybrid.git```bash

cd EDHOC-Hybridgit clone --recursive https://github.com/<your-user>/EDHOC-Hybrid.git

# If you pulled without --recursivecd EDHOC-Hybrid

git submodule update --init --recursive# If you pulled without --recursive

```git submodule update --init --recursive

```

## Build

## Build

```bash

make                    # Build (default: USE_PQCLEAN=1, libsodium HKDF)```bash

make USE_PQCLEAN=1 -j$(nproc)   # Explicit PQClean pathmake                    # Build (default: USE_PQCLEAN=1, libsodium HKDF)

make clean              # Clean application objectsmake USE_PQCLEAN=1 -j$(nproc)   # Explicit PQClean path

make lib-clean          # Clean everything (app + uoscore-uedhoc build)make clean              # Clean application objects

```make lib-clean          # Clean everything (app + uoscore-uedhoc build)

```

Notes:

- liboqs is **not** vendored anymore. The supported/tested path is `USE_PQCLEAN=1`Notes:

        (default). If you experiment with `USE_PQCLEAN=0`, install liboqs separately- liboqs is **not** vendored anymore. The supported/tested path is `USE_PQCLEAN=1`

        and adjust include/library paths as needed.        (default). If you experiment with `USE_PQCLEAN=0`, install liboqs separately

- Enable verbose protocol debug by uncommenting `DEBUG_PRINT` in        and adjust include/library paths as needed.

        `lib/uoscore-uedhoc/makefile_config.mk` or adding `-DDEBUG_PRINT` to `CFLAGS`.- Enable verbose protocol debug by uncommenting `DEBUG_PRINT` in

        `lib/uoscore-uedhoc/makefile_config.mk` or adding `-DDEBUG_PRINT` to `CFLAGS`.

## Run

## Run

Interactive menu:

Interactive menu:

```bash

./build/edhoc_hybrid```bash

```./build/edhoc_hybrid

```

Direct (skip menu):

Direct (skip menu):

```bash

./build/edhoc_hybrid 1   # Type 0 Classic (Sig-Sig)```bash

./build/edhoc_hybrid 2   # Type 3 Classic (MAC-MAC)./build/edhoc_hybrid 1   # Type 0 Classic (Sig-Sig)

./build/edhoc_hybrid 3   # Type 0 PQ (ML-KEM-768 + ML-DSA-65)./build/edhoc_hybrid 2   # Type 3 Classic (MAC-MAC)

./build/edhoc_hybrid 4   # Type 3 PQ (ML-KEM-768 MAC-MAC)./build/edhoc_hybrid 3   # Benchmark Classic (Types 0 & 3)

./build/edhoc_hybrid 5   # Type 3 Hybrid (X25519 + ML-KEM-768)./build/edhoc_hybrid 4   # Type 0 PQ (ML-KEM-768 + ML-DSA-65)

./build/edhoc_hybrid 6   # Benchmark (TCP, all 5 variants)

```./build/edhoc_hybrid 6   # Full Benchmark (Classic + PQ)

./build/edhoc_hybrid 7   # Type 3 Hybrid (X25519 + ML-KEM-768)

Benchmark output CSVs (TCP client-server):

```

 - `output/benchmark_operations.csv`

 - `output/benchmark_overhead.csv`

 - `output/benchmark_handshake.csv`

- `output/benchmark_operations.csv`

## Performance notes (classic vs PQ vs hybrid)- `output/benchmark_overhead.csv`

- `output/benchmark_handshake.csv`


### Crypto library alignment (fairness)

All five variants share the same underlying libraries to ensure a fair comparison:

| Operation         | Classic (Type 0/3)                        | PQ (Type 0/3)                | Hybrid (Type 3)                        |
|-------------------|--------------------------------------------|------------------------------|-----------------------------------------|
| **ECDH / KeyGen** | libsodium `crypto_scalarmult`              | —                            | libsodium `crypto_scalarmult`           |
| **HKDF**          | libsodium HMAC-SHA256                      | mbedTLS PSA HMAC             | libsodium HMAC-SHA256                   |
| **Hash (SHA-256)**| mbedTLS PSA `psa_hash_compute`             | mbedTLS PSA `psa_hash_compute`| mbedTLS PSA `psa_hash_compute`          |
| **AEAD (AES-CCM)**| mbedTLS PSA `psa_aead_*`                   | mbedTLS PSA `psa_aead_*`     | mbedTLS PSA `psa_aead_*`                |
| **KEM (ML-KEM-768)**| —                                       | PQClean                      | PQClean                                 |
| **Signature**     | libsodium Ed25519                          | PQClean ML-DSA-65            | — (MAC-only)                            |

The hybrid handshake (`edhoc_type3_hybrid.c`) calls the same `crypto_wrapper.h` functions (libsodium HKDF, mbedTLS AEAD/Hash) as classic Type 3, dan PQClean KEM seperti PQ Type 3.

as PQ Type 3. The benchmark micro-benchmarks (`bench_ecdh`, `bench_hkdf`, `bench_hash`,

`bench_encap`, `bench_decap`, `bench_pq_*`) use the identical call path, so measuredThe hybrid handshake (`edhoc_type3_hybrid.c`) calls the same `crypto_wrapper.h` functions

times reflect the same overhead.(libsodium HKDF, mbedTLS AEAD/Hash) as classic Type 3, and the same PQClean KEM functions

as PQ Type 3. The benchmark micro-benchmarks (`bench_ecdh`, `bench_hkdf`, `bench_hash`,

### Why Hybrid is faster than PQ`bench_encap`, `bench_decap`, `bench_pq_*`) use the identical call path, so measured

times reflect the same overhead.

- **KEM counts drive latency.** Hybrid uses 1 KEM.Enc (Responder) + 1 KEM.Dec (Initiator). PQ Type 3 uses 3 KEMs per side. With ML-KEM-768 ~150-200 us/op, Hybrid saves ~400 us.

- **ECDH backbone.** Hybrid keeps 2 ECDH calls per side (~25-35 us each) and one KEM as a PQ security anchor — much cheaper than replacing all ECDHs with KEMs.### Why Hybrid is faster than PQ

- **HKDF load.** Hybrid runs 10 HKDFs (~45-65 us total via libsodium), comparable to classic.

- **Structural insight:** ECDH = performance backbone, KEM = PQ security reinforcement.- **KEM counts drive latency.** Hybrid uses 1 KEM.Enc (Responder) + 1 KEM.Dec (Initiator). PQ Type 3 uses 3 KEMs per side. With ML-KEM-768 ~150-200 us/op, Hybrid saves ~400 us.

- **ECDH backbone.** Hybrid keeps 2 ECDH calls per side (~25-35 us each) and one KEM as a PQ security anchor — much cheaper than replacing all ECDHs with KEMs.

### Benchmark scope- **HKDF load.** Hybrid runs 10 HKDFs (~45-65 us total via libsodium), comparable to classic.

- **Structural insight:** ECDH = performance backbone, KEM = PQ security reinforcement.

- **What the 1-2 us Encap/Decap rows are.** Those are the lightweight AES-CCM AEAD wrap/unwrap; PQ costs appear under `PQ_Encaps`/`PQ_Decaps` (120-180 us each).

- **Micro-bench variance.** Ops run sequentially (classic -> PQ -> hybrid); later batches benefit from warm CPU caches. Per-call times differ between classic and hybrid even for the same function, but both use identical code paths.### Benchmark scope

- **Scope of timings.** The benchmark measures crypto processing + real TCP I/O latency (txrx), providing realistic client-server performance numbers.

- **What the 1-2 us Encap/Decap rows are.** Those are the lightweight AES-CCM AEAD wrap/unwrap; PQ costs appear under `PQ_Encaps`/`PQ_Decaps` (120-180 us each).

## Verify Benchmark Consistency- **Micro-bench variance.** Ops run sequentially (classic -> PQ -> hybrid); later batches benefit from warm CPU caches. Per-call times differ between classic and hybrid even for the same function, but both use identical code paths.

- **Scope of timings.** Benchmarks measure crypto only (no CBOR encode/decode, no network I/O, no PSA setup in the handshake itself).

```bash

python3 verify_benchmark.py

```

```bash

Runs cross-table checks (operations ↔ overhead ↔ handshake) on `output/` CSVs with 1 µs tolerance.

```

## Project Structure (trimmed)

Runs six cross-table checks (operations ↔ overhead ↔ handshake) with 1 µs tolerance.

```
EDHOC-Hybrid/
├── Makefile                  # Top-level build (defaults to PQClean)
├── [README.md](http://_vscodecontentref_/2)
├── [verify_benchmark.py](http://_vscodecontentref_/3)       # Benchmark CSV consistency checker
├── include/
│   ├── edhoc_common.h        # Shared helpers
│   ├── edhoc_type0_classic.h # Classic Sig-Sig
│   ├── edhoc_type3_classic.h # Classic MAC-MAC
│   ├── edhoc_type0_pq.h      # PQ KEM Sig-like
│   ├── edhoc_type3_pq.h      # PQ KEM MAC-MAC
│   ├── edhoc_type3_hybrid.h  # Hybrid MAC-MAC (ECDHE + KEM)
│   └── edhoc_benchmark.h     # Benchmark header
├── src/
│   ├── main.c                # Menu + dispatcher (1–8)
│   ├── edhoc_common.c
│   ├── edhoc_type0_classic.c
│   ├── edhoc_type3_classic.c
│   ├── edhoc_type0_pq.c
│   ├── edhoc_type3_pq.c
│   ├── edhoc_type3_hybrid.c  # Hybrid Type 3 implementation
│   └── edhoc_benchmark.c     # Benchmark (TCP client-server)
├── lib/
│   ├── PQClean/              # PQ KEM/Signature (ML-KEM-768, ML-DSA-65)
│   └── uoscore-uedhoc/       # Core EDHOC/OSCORE library + nested externals
└── output/                   # Benchmark CSVs

```


### External Dependencies (via submodules or system)

| Component    | Source                                         | Purpose                                    |
|--------------|------------------------------------------------|--------------------------------------------|
| uoscore-uedhoc | submodule                                    | Core EDHOC/OSCORE logic                    |
| PQClean      | submodule                                      | ML-KEM-768, ML-DSA-65 implementations      |
| mbedTLS      | `lib/uoscore-uedhoc/externals/mbedtls`         | AES-CCM, PSA crypto                        |
| zcbor        | `lib/uoscore-uedhoc/externals/zcbor`           | CBOR codec                                 |
| tinycrypt    | `lib/uoscore-uedhoc/externals/tinycrypt`       | Lightweight crypto (optional paths)         |
| libsodium    | system (`libsodium-dev`)                       | X25519, Ed25519, HKDF-HMAC-SHA256          |

## License

## License

uoscore-uedhoc is dual-licensed under Apache-2.0 and MIT; follow upstream terms.

uoscore-uedhoc is dual-licensed under Apache-2.0 and MIT; follow upstream terms.
