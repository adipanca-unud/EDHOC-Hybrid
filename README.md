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

Menu **6** runs the benchmark (TCP client-server) across all 5 variants. Menu **7** runs a standalone hybrid handshake. Menu **8** runs full benchmarks across classic, PQ, and hybrid, writing CSVs under `output/`. Menu **9** runs the **P2P Network Benchmark** between two separate machines (e.g. Raspberry Pi as Initiator + Ubuntu server as Responder).

## Prerequisites

- GCC (C11), GNU Make
- Git (for submodules)
- `libsodium-dev` (X25519, Ed25519, HKDF-SHA256)
- pthreads (POSIX threads)
- Python 3 (for `verify_benchmark.py`)

## Clone with Submodules (liboqs removed)

This repo vendors only the pieces we use: `uoscore-uedhoc` and `PQClean` (plus nested deps inside `uoscore-uedhoc`). The `liboqs` submodule has been removed; PQ flows rely on PQClean by default.

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
- liboqs is **not** vendored anymore. The supported/tested path is `USE_PQCLEAN=1` (default). If you experiment with `USE_PQCLEAN=0`, install liboqs separately and adjust include/library paths as needed.
- Enable verbose protocol debug by uncommenting `DEBUG_PRINT` in `lib/uoscore-uedhoc/makefile_config.mk` or adding `-DDEBUG_PRINT` to `CFLAGS`.

## Run

Interactive menu:
```bash
./build/edhoc_hybrid
```


Direct (skip menu):
```bash
./build/edhoc_hybrid 1   # Type 0 Classic (Sig-Sig)
./build/edhoc_hybrid 2   # Type 3 Classic (MAC-MAC)
./build/edhoc_hybrid 3   # Type 0 PQ (ML-KEM-768 + ML-DSA-65)
./build/edhoc_hybrid 4   # Type 3 PQ (ML-KEM-768 MAC-MAC)
./build/edhoc_hybrid 5   # Type 3 Hybrid (X25519 + ML-KEM-768)
./build/edhoc_hybrid 6   # Benchmark (TCP, all 5 variants)
./build/edhoc_hybrid 7   # Type 3 Hybrid (X25519 + ML-KEM-768)
```

### P2P Network Benchmark (Menu 9)

Run **real network** benchmarks between two separate machines (e.g. Raspberry Pi → Ubuntu server).

#### Architecture

```
 ┌──────────────────────┐          TCP         ┌──────────────────────┐
 │   Raspberry Pi       │ ◄───────────────────► │   Ubuntu Server      │
 │   (Initiator)        │      Port 19000       │   (Responder)        │
 │                      │   Control channel     │                      │
 │   ./edhoc_hybrid 9   │   + handshake ports   │   ./edhoc_hybrid 9   │
 │     --initiator      │                       │     --responder      │
 │     --host <IP>      │                       │                      │
 └──────────────────────┘                       └──────────────────────┘
```

Both machines run the same binary. The **Responder** starts first and waits; the **Initiator** connects and drives the benchmark.

#### Setup on Responder (Ubuntu Server)

```bash
# 1. Clone and build on the server
git clone --recursive https://github.com/<your-user>/EDHOC-Hybrid.git
cd EDHOC-Hybrid
sudo apt-get install -y gcc make libsodium-dev
make clean && make -j$(nproc)

# 2. Open firewall for benchmark ports
sudo ufw allow 19000:19999/tcp   # or: sudo iptables -A INPUT -p tcp --dport 19000:19999 -j ACCEPT

# 3. Start Responder (waits for Initiator)
./build/edhoc_hybrid 9 --responder
# Optional: custom port
./build/edhoc_hybrid 9 --responder --port 20000
```

#### Setup on Initiator (Raspberry Pi)

```bash
# 1. Clone and build on the Raspberry Pi
git clone --recursive https://github.com/<your-user>/EDHOC-Hybrid.git
cd EDHOC-Hybrid
sudo apt-get install -y gcc make libsodium-dev
make clean && make -j$(nproc)

# 2. Run Initiator (connects to Responder)
./build/edhoc_hybrid 9 --initiator --host <SERVER_IP>
# Example:
./build/edhoc_hybrid 9 --initiator --host 192.168.1.100
# Optional: custom port (must match Responder)
./build/edhoc_hybrid 9 --initiator --host 192.168.1.100 --port 20000
```

#### P2P Benchmark Output

Each machine writes its own CSV:
- **Responder:** `output/p2p_handshake_responder.csv`
- **Initiator:** `output/p2p_handshake_initiator.csv`

Columns: `type, role, processing_us, txrx_us, total_us, success_count`

The benchmark runs all 5 handshake variants (Classic Type 0/3, PQ Type 0/3, Hybrid Type 3) with 50 iterations each. Key material is exchanged over a control channel at startup.

#### Cross-Compilation for Raspberry Pi (optional)

If you prefer to cross-compile on the server instead of building natively on the Pi:

```bash
# On Ubuntu server
sudo apt-get install -y gcc-aarch64-linux-gnu
make CC=aarch64-linux-gnu-gcc clean all
# Copy binary to Raspberry Pi
scp build/edhoc_hybrid pi@<PI_IP>:~/
```

Benchmark output CSVs (TCP client-server):
- `output/benchmark_operations.csv`
- `output/benchmark_overhead.csv`
- `output/benchmark_handshake.csv`

## Performance notes (classic vs PQ vs hybrid)

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

The hybrid handshake (`edhoc_type3_hybrid.c`) calls the same `crypto_wrapper.h` functions (libsodium HKDF, mbedTLS AEAD/Hash) as classic Type 3, and PQClean KEM as PQ Type 3. The benchmark micro-benchmarks (`bench_ecdh`, `bench_hkdf`, `bench_hash`, `bench_encap`, `bench_decap`, `bench_pq_*`) use the identical call path, so measured times reflect the same overhead.

- **Scope of timings.** Benchmarks measure crypto only (no CBOR encode/decode, no network I/O, no PSA setup in the handshake itself).

```bash
python3 verify_benchmark.py
```
Runs cross-table checks (operations ↔ overhead ↔ handshake) on `output/` CSVs with 1 µs tolerance.

## Project Structure (trimmed)

```
EDHOC-Hybrid/
├── Makefile                  # Top-level build (defaults to PQClean)
├── README.md                 # This file
├── verify_benchmark.py       # Benchmark CSV consistency checker
├── include/
│   ├── edhoc_common.h        # Shared helpers
│   ├── edhoc_type0_classic.h # Classic Sig-Sig
│   ├── edhoc_type3_classic.h # Classic MAC-MAC
│   ├── edhoc_type0_pq.h      # PQ KEM Sig-like
│   ├── edhoc_type3_pq.h      # PQ KEM MAC-MAC
│   ├── edhoc_type3_hybrid.h  # Hybrid MAC-MAC (ECDHE + KEM)
│   ├── edhoc_benchmark.h     # Benchmark header
│   └── edhoc_benchmark_p2p.h # P2P Network Benchmark header
├── src/
│   ├── main.c                # Menu + dispatcher (1–8)
│   ├── edhoc_common.c
│   ├── edhoc_type0_classic.c
│   ├── edhoc_type3_classic.c
│   ├── edhoc_type0_pq.c
│   ├── edhoc_type3_pq.c
│   ├── edhoc_type3_hybrid.c  # Hybrid Type 3 implementation
│   ├── edhoc_benchmark.c     # Benchmark (TCP client-server)
│   └── edhoc_benchmark_p2p.c # P2P Network Benchmark (two machines)
├── lib/
│   ├── PQClean/              # PQ KEM/Signature (ML-KEM-768, ML-DSA-65)
│   └── uoscore-uedhoc/       # Core EDHOC/OSCORE library + nested externals
└── output/                   # Benchmark CSVs
```

### External Dependencies (via submodules or system)

| Component      | Source                                         | Purpose                                    |
|---------------|------------------------------------------------|--------------------------------------------|
| uoscore-uedhoc | submodule                                      | Core EDHOC/OSCORE logic                    |
| PQClean        | submodule                                      | ML-KEM-768, ML-DSA-65 implementations      |
| mbedTLS        | `lib/uoscore-uedhoc/externals/mbedtls`         | AES-CCM, PSA crypto                        |
| zcbor          | `lib/uoscore-uedhoc/externals/zcbor`           | CBOR codec                                 |
| tinycrypt      | `lib/uoscore-uedhoc/externals/tinycrypt`       | Lightweight crypto (optional paths)         |
| libsodium      | system (`libsodium-dev`)                       | X25519, Ed25519, HKDF-HMAC-SHA256          |

## License

uoscore-uedhoc is dual-licensed under Apache-2.0 and MIT; follow upstream terms.
