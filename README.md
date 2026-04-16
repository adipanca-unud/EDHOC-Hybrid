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

## Algorithm → Library Mapping (Benchmark Fairness)

Untuk memastikan benchmark fair dan konsisten antar varian, implementasi saat ini menggunakan mapping berikut:

| Algorithm | Library yang digunakan | Keterangan |
|---|---|---|
| X25519 | libsodium | `crypto_scalarmult*` untuk keygen/ECDH classic + hybrid |
| ML-KEM-768 | PQClean | KEM keygen/encaps/decaps untuk varian PQ + hybrid |
| Ed25519 (sign/verify) | libsodium | `crypto_sign_*` untuk Type 0/3 classic |
| ML-DSA-65 | PQClean | Signature/verification untuk Type 0 PQ |
| AEAD | mbedTLS PSA (AES-CCM-16-64-128) | `psa_aead_encrypt/decrypt` di semua varian |
| SHA-256 | libsodium | `crypto_hash_sha256` di semua varian benchmark |
| HKDF (Extract/Expand) | libsodium (HMAC-SHA256) | Implementasi HKDF berbasis `crypto_auth_hmacsha256_*` |

> Catatan: Mapping ini diselaraskan agar jalur benchmark Classic, PQ, dan Hybrid memakai backend simetris yang sama untuk Hash/HKDF, sehingga tidak terjadi bias perbandingan antar varian.

Menu **6** runs the benchmark (TCP client-server) across all 5 variants. Menu **7** runs a standalone hybrid handshake. Menu **8** runs full benchmarks across classic, PQ, and hybrid, writing CSVs under `output/`. Menu **9** runs the **All-in-One Benchmark** (crypto + socket + P2P network) producing 9 role-suffixed CSV files (`_initiator` / `_responder`) in a single run on each machine.

## Prerequisites

- GCC (C11), GNU Make
- Git (for submodules)
- `libsodium-dev` (X25519, Ed25519, HKDF-SHA256, SHA-256)
- pthreads (POSIX threads)
- Python 3 (for `verify_benchmark.py`)

## Clone with Submodules (liboqs removed)

This repo vendors only the pieces we use: `uoscore-uedhoc` and `PQClean` (plus nested deps inside `uoscore-uedhoc`). The `liboqs` submodule has been removed; PQ flows rely on PQClean by default.

```bash
git clone --recursive https://github.com/<your-user>/EDHOC-Hybrid.git
cd EDHOC-Hybrid
git checkout raspberrypi        # Switch to the benchmarking branch
git submodule update --init --recursive   # If you pulled without --recursive
```

## Build (Quick Start)

The easiest way to build — especially on Raspberry Pi — is to use the **setup script** which automatically patches the library and builds everything:

```bash
./setup.sh              # Applies patches + full build (recommended)
```

### Manual Build

```bash
make                    # Build (default: USE_PQCLEAN=1, libsodium HKDF+SHA-256)
make USE_PQCLEAN=1 -j$(nproc)   # Explicit PQClean path
make clean              # Clean application objects
make lib-clean          # Clean everything (app + uoscore-uedhoc build)
```

> **Important**: After a fresh clone, the `lib/uoscore-uedhoc` library needs a patch
> for production benchmarking (disables verbose hex-dump output, enables -O2 optimization,
> fixes compact25519 build on ARM). The patch is at `patches/uoscore-uedhoc.patch` and is
> applied automatically by `./setup.sh`. To apply manually:
> ```bash
> git -C lib/uoscore-uedhoc apply "$(pwd)/patches/uoscore-uedhoc.patch"
> make lib-clean && make -j$(nproc)
> ```

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
 │   (Initiator)        │      Port 15000       │   (Responder)        │
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
git checkout raspberrypi
sudo apt-get install -y gcc make libsodium-dev
./setup.sh              # Apply patches + build

# 2. Open firewall for benchmark ports
# Mode 9 uses control port PORT and per-variant handshake ports at PORT+1000..PORT+1004.
# For default PORT=15000, open 15000 and 16000-16004 (or open the contiguous range below).
sudo ufw allow 15000:16004/tcp   # or: sudo iptables -A INPUT -p tcp --dport 15000:16004 -j ACCEPT

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
git checkout raspberrypi
sudo apt-get install -y gcc make libsodium-dev
./setup.sh              # Apply patches + build

# 2. Run Initiator (connects to Responder)
./build/edhoc_hybrid 9 --initiator --host <SERVER_IP>
# Example:
./build/edhoc_hybrid 9 --initiator --host 192.168.1.100
# Optional: custom port (must match Responder)
./build/edhoc_hybrid 9 --initiator --host 192.168.1.100 --port 20000
```

#### P2P Benchmark Output (Menu 9 — All-in-One)

Menu 9 runs **three benchmark phases** sequentially on each machine, producing **9 CSV files per machine** in a single invocation. CSV filenames include a **role suffix** (`_initiator` or `_responder`) so that both sides can write to the same `output/` directory without overwriting each other.

**Phase A — Pure Crypto Operations (local, no network):**
| Responder | Initiator |
|-----------|-----------|
| `output/benchmark_crypto_ops_responder.csv` | `output/benchmark_crypto_ops_initiator.csv` |
| `output/benchmark_crypto_matrix_responder.csv` | `output/benchmark_crypto_matrix_initiator.csv` |
| `output/benchmark_crypto_simple_responder.csv` | `output/benchmark_crypto_simple_initiator.csv` |

**Phase B — Socket Benchmark (TCP localhost, all 5 variants):**
| Responder | Initiator |
|-----------|-----------|
| `output/benchmark_operations_responder.csv` | `output/benchmark_operations_initiator.csv` |
| `output/benchmark_overhead_responder.csv` | `output/benchmark_overhead_initiator.csv` |
| `output/benchmark_handshake_responder.csv` | `output/benchmark_handshake_initiator.csv` |

**Phase C — P2P Network Handshake (Initiator ↔ Responder over TCP):**
| Responder | Initiator |
|-----------|-----------|
| `output/p2p_handshake_responder.csv` | `output/p2p_handshake_initiator.csv` |
| `output/p2p_overhead_responder.csv` | `output/p2p_overhead_initiator.csv` |
| `output/p2p_operations_responder.csv` | `output/p2p_operations_initiator.csv` |

Columns:
- `p2p_handshake_*`: `type, role, processing_us, txrx_us, precomputation_us, overhead_us, total_us, success_count`
- `p2p_overhead_*`: `type, role, memory_estimate_bytes, cpu_time_us, txrx_time_us, precomputation_us, overhead_pct`
- `p2p_operations_*`: `type, role, operation, calls_per_handshake, avg_time_us, total_time_us, contribution_pct`

> **Latest fix (April 2026):** default P2P port changed to **15000** to avoid overlap with socket benchmark port range (`SOCK_BENCH_BASE_PORT=19000`). This removes port-collision crashes when running mode 9 concurrently on Initiator/Responder.

The benchmark runs all 5 handshake variants (Classic Type 0/3, PQ Type 0/3, Hybrid Type 3) with 1000 iterations each. Key material is exchanged over a control channel at startup.

> **Note:** When running standalone modes (Menu 6 for socket benchmark, or `make crypto_bench` for crypto benchmark), CSV filenames have **no role suffix** (e.g. `benchmark_operations.csv`).

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
| **HKDF**          | libsodium HMAC-SHA256                      | libsodium HMAC-SHA256        | libsodium HMAC-SHA256                   |
| **Hash (SHA-256)**| libsodium `crypto_hash_sha256`             | libsodium `crypto_hash_sha256`| libsodium `crypto_hash_sha256`          |
| **AEAD (AES-CCM)**| mbedTLS PSA `psa_aead_*`                   | mbedTLS PSA `psa_aead_*`     | mbedTLS PSA `psa_aead_*`                |
| **KEM (ML-KEM-768)**| —                                       | PQClean                      | PQClean                                 |
| **Signature**     | libsodium Ed25519                          | PQClean ML-DSA-65            | — (MAC-only)                            |

The hybrid handshake (`edhoc_type3_hybrid.c`) calls the same `crypto_wrapper.h` functions (libsodium HKDF/Hash, mbedTLS AEAD) as classic Type 3, and PQClean KEM as PQ Type 3. The benchmark micro-benchmarks (`bench_ecdh`, `bench_hkdf`, `bench_hash`, `bench_encap`, `bench_decap`, `bench_pq_*`) use the identical call path, so measured times reflect the same overhead.

- **Scope of timings.** Benchmarks measure crypto only (no CBOR encode/decode, no network I/O, no PSA setup in the handshake itself).

```bash
python3 verify_benchmark.py
```
Runs cross-table checks (operations ↔ overhead ↔ handshake) on `output/` CSVs with 1 µs tolerance.

```bash
python3 verify_consistency.py
```
Runs full cross-file consistency checks for mode-9 role-suffixed CSV outputs:
- call counts vs expected table,
- socket vs P2P operation parity,
- handshake decomposition (`total = processing + txrx + precomputation + overhead`),
- primitive timing reasonableness against `benchmark_crypto_simple_*`.

## Cryptographic Operation Calls per Handshake

The table below is aligned with implementation and benchmark CSVs (key generation counted as part of the ECDH family for classic/hybrid reporting).

| Variant | KeyGen | ECDH | Encap/Decap | Sign/Verify | AEAD (Enc/Dec) | HKDF | Hash |
|---|---:|---:|---:|---:|---:|---:|---:|
| Type0 SigSig (I) | 1 | 2 | 0 | 1/1 | 1/0 | 8 | 4 |
| Type0 SigSig (R) | 1 | 2 | 0 | 1/1 | 0/1 | 8 | 4 |
| Type3 MACMAC (I) | 1 | 4 | 0 | 0/0 | 1/0 | 10 | 4 |
| Type3 MACMAC (R) | 1 | 4 | 0 | 0/0 | 0/1 | 10 | 4 |
| Type0 PQ (I) | 1 | -- | 1/1 | 1/1 | 2/1 | 8 | 3 |
| Type0 PQ (R) | 1 | -- | 1/1 | 1/1 | 1/2 | 8 | 3 |
| Type3 PQ (I) | 1 | -- | 1/2 | 0/0 | 2/1 | 8 | 3 |
| Type3 PQ (R) | 1 | -- | 2/1 | 0/0 | 1/2 | 8 | 3 |
| Type3 Hybrid (I) | 1 | 4 | 0/1 | 0/0 | 1/1 | 10 | 3 |
| Type3 Hybrid (R) | 1 | 4 | 1/0 | 0/0 | 1/1 | 10 | 3 |

### LaTeX version (paper-ready)

```tex
\begin{table*}[t]
\centering
\caption{Comparison of Cryptographic Operation Calls per Handshake}
\label{tab:operation_calls_comparison}
\renewcommand{\arraystretch}{1.2}
\setlength{\tabcolsep}{4pt}

\begin{tabularx}{\textwidth}{l c c c c c c c}
\hline
{\bfseries Variant} 
& \textbf{KeyGen} 
& \textbf{ECDH} 
& \textbf{Encap/Decap} 
& \textbf{Sign/Verify} 
& \textbf{AEAD} 
& \textbf{HKDF} 
& \textbf{Hash} \\
\hline

Type0 SigSig (I) & 1 & 2 & 0 & 1/1 & 1/0 & 8 & 4 \\
Type0 SigSig (R) & 1 & 2 & 0 & 1/1 & 0/1 & 8 & 4 \\

Type3 MACMAC (I) & 1 & 4 & 0 & 0/0 & 1/0 & 10 & 4 \\
Type3 MACMAC (R) & 1 & 4 & 0 & 0/0 & 0/1 & 10 & 4 \\

Type0 PQ (I) & 1 & -- & 1/1 & 1/1 & 2/1 & 8 & 3 \\
Type0 PQ (R) & 1 & -- & 1/1 & 1/1 & 1/2 & 8 & 3 \\

Type3 PQ (I) & 1 & -- & 1/2 & 0/0 & 2/1 & 8 & 3 \\
Type3 PQ (R) & 1 & -- & 2/1 & 0/0 & 1/2 & 8 & 3 \\

Type3 Hybrid (I) & 1 & 4 & 0/1 & 0/0 & 1/1 & 10 & 3 \\
Type3 Hybrid (R) & 1 & 4 & 1/0 & 0/0 & 1/1 & 10 & 3 \\

\hline
\end{tabularx}

\vspace{2pt}
\footnotesize{Counts reflect total operations per handshake and are aligned with Tables~\ref{table:comparison2} and~\ref{table:comparison3}. Pre-computable operations are included.}
\end{table*}
```

## Project Structure (trimmed)

```
EDHOC-Hybrid/
├── Makefile                  # Top-level build (defaults to PQClean)
├── README.md                 # This file
├── verify_benchmark.py       # Benchmark CSV consistency checker (single-run CSVs)
├── verify_consistency.py     # Cross-CSV checker for mode-9 role-suffixed outputs
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
│   ├── main.c                # Menu + dispatcher (1–9)
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
