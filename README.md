# EDHOC-Hybrid: EDHOC Protocol Implementation (RFC 9528)

Implementation of the EDHOC (Ephemeral Diffie-Hellman Over COSE) protocol
according to [RFC 9528](https://www.rfc-editor.org/rfc/rfc9528) using the
[uoscore-uedhoc](https://github.com/eriptic/uoscore-uedhoc) library.

## Supported EDHOC Types

| Type | Name | Method | Initiator Auth | Responder Auth | Suite | Curve |
|------|------|--------|---------------|---------------|-------|-------|
| 0 | Signature-Signature (Classic) | INITIATOR_SK_RESPONDER_SK | Signature Key | Signature Key | Suite 0 | X25519 + EdDSA |
| 3 | MAC-MAC (Classic) | INITIATOR_SDHK_RESPONDER_SDHK | Static DH Key | Static DH Key | Suite 0 | X25519 (Static DH + MAC) |

## Prerequisites

- GCC (C11 compatible)
- GNU Make
- Git (for submodule management)
- pthreads (POSIX threads)

## Getting Started

### Clone with submodules

```bash
git clone --recursive https://github.com/<your-user>/EDHOC-Hybrid.git
cd EDHOC-Hybrid
```

Or if you already cloned without `--recursive`:

```bash
git submodule update --init --recursive
```

### Build

```bash
make          # Build everything (library + externals + application)
make clean    # Clean application objects only
make lib-clean # Clean everything including library
```

To enable verbose protocol debug output, uncomment `DEBUG_PRINT` in
`lib/uoscore-uedhoc/makefile_config.mk` or add `-DDEBUG_PRINT` to CFLAGS
in the Makefile.

## Run

### Interactive mode (with menu):
```bash
./build/edhoc_hybrid
```

### Direct mode (skip menu):
```bash
./build/edhoc_hybrid 1    # Run Type 0 (Sig-Sig)
./build/edhoc_hybrid 2    # Run Type 3 (MAC-MAC)
```

## Project Structure

```
EDHOC-Hybrid/
├── .gitmodules                        # Git submodule configuration
├── README.md
├── Makefile
├── include/
│   ├── edhoc_common.h                 # Common utilities, transport, print helpers
│   ├── edhoc_type0_classic.h          # Type 0 Sig-Sig header
│   ├── edhoc_type3_classic.h          # Type 3 MAC-MAC header
│   └── edhoc_type3_x25519_testvec.h   # X25519 test vectors for Type 3
├── src/
│   ├── main.c                         # Entry point with interactive menu
│   ├── edhoc_common.c                 # Shared tx/rx (pthread), print utilities, OSCORE key derivation
│   ├── edhoc_type0_classic.c          # Type 0 Sig-Sig (RFC 9529 test vectors, Suite 0)
│   └── edhoc_type3_classic.c          # Type 3 MAC-MAC (X25519 static DH keys, Suite 0)
├── lib/
│   └── uoscore-uedhoc/  [Git submodule] # Core EDHOC/OSCORE library
│       ├── src/                       # Library source (EDHOC initiator/responder, OSCORE)
│       ├── inc/                       # Library headers
│       ├── test_vectors/              # RFC 9529 + P-256 test vectors
│       └── externals/   [Git submodules]
│           ├── zcbor/                 # CBOR encoder/decoder
│           ├── compact25519/          # (legacy) X25519/EdDSA; replaced by libsodium backend
│           └── mbedtls/               # P-256/ES256/AES crypto (Suite 2)
└── build/                             # Build output (edhoc_hybrid binary)
```

### External Dependencies (Git Submodules)

| Submodule | Path | Repository | Purpose |
|-----------|------|------------|---------|
| uoscore-uedhoc | `lib/uoscore-uedhoc` | [eriptic/uoscore-uedhoc](https://github.com/eriptic/uoscore-uedhoc) | Core EDHOC/OSCORE protocol library |
| mbedtls | `lib/uoscore-uedhoc/externals/mbedtls` | [ARMmbed/mbedtls](https://github.com/ARMmbed/mbedtls) | AES-CCM, SHA-256, P-256/ES256 crypto |
| zcbor | `lib/uoscore-uedhoc/externals/zcbor` | [NordicSemiconductor/zcbor](https://github.com/NordicSemiconductor/zcbor) | CBOR encoding/decoding |
| cantcoap | `lib/uoscore-uedhoc/externals/cantcoap` | [staropram/cantcoap](https://github.com/staropram/cantcoap) | CoAP message parsing (optional) |
| tinycrypt | `lib/uoscore-uedhoc/externals/tinycrypt` | [intel/tinycrypt](https://github.com/intel/tinycrypt) | Lightweight crypto (alternative engine) |
| libsodium | system (`libsodium-dev`) | [jedisct1/libsodium](https://github.com/jedisct1/libsodium) | X25519 + Ed25519 backend for Suite 0 |

## Architecture

Each EDHOC type runs Initiator and Responder as **separate pthreads** communicating
through a shared message buffer with mutex/condition variable synchronization,
simulating real network message exchange.

### Message Flow (3-message handshake per RFC 9528):

```
Initiator (Thread 1)                    Responder (Thread 2)
        |                                        |
        |  ---- message_1 (METHOD, SUITES_I, G_X, C_I) --->  |
        |                                        |
        |  <--- message_2 (G_Y, C_R, Enc_2) --- |
        |                                        |
        |  ---- message_3 (Enc_3) ------------->  |
        |                                        |
        | Both derive PRK_out → prk_exporter     |
        | → OSCORE Master Secret + Salt          |
```

### Method Types:
- **Method 0** (Sig-Sig): Both parties use signature keys (EdDSA with X25519 DH)
- **Method 3** (MAC-MAC): Both parties use static DH keys for MAC-based authentication (X25519 DH)

### Key Derivation:
After successful EDHOC exchange, both sides derive:
1. **PRK_out** — Protocol output key
2. **prk_exporter** — Exporter secret (via `prk_out2exporter`)
3. **OSCORE Master Secret** (16 bytes) — For OSCORE protected communication
4. **OSCORE Master Salt** (8 bytes) — For OSCORE security context

## Test Vectors

- **Type 0**: Uses RFC 9529 test vectors (Test 1, Method 0, Suite 0)
- **Type 3**: Uses X25519 generated keys (Method 3, Suite 0) with RFC 9529 credentials

## License

This project uses the uoscore-uedhoc library which is dual-licensed under Apache-2.0 and MIT.
