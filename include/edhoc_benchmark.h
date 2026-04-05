/*
 * =============================================================================
 * EDHOC-Hybrid: Socket-based (TCP) Benchmark
 * =============================================================================
 *
 * Same benchmark methodology as edhoc_benchmark.c but uses TCP localhost
 * sockets for message exchange instead of pthread shared-memory.
 *
 * This measures real network I/O latency in the txrx component, providing
 * a realistic client-server benchmark.
 *
 * Outputs the same 3 CSV files (to output/ directory) with identical
 * format so that verify_benchmark.py can validate.
 *
 * All 15 variants:
 *   EDHOC (2-party, TCP):
 *   - Type 0 Classic (Sig-Sig)
 *   - Type 3 Classic (MAC-MAC)
 *   - Type 0 PQ (KEM-based Sig-Sig, ML-KEM-768)
 *   - Type 3 PQ (KEM-based MAC-MAC, ML-KEM-768)
 *   - Type 3 Hybrid (X25519 ECDHE + ML-KEM-768)
 *
 *   EAP-EDHOC (2-party, EAP over TCP):
 *   - EAP Type 0 Classic, EAP Type 3 Classic
 *   - EAP Type 0 PQ, EAP Type 3 PQ
 *   - EAP Type 3 Hybrid
 *
 *   AAA EAP-EDHOC (3-party, Peer ↔ Authenticator ↔ AAA Server via RADIUS):
 *   - AAA Type 0 Classic, AAA Type 3 Classic
 *   - AAA Type 0 PQ, AAA Type 3 PQ
 *   - AAA Type 3 Hybrid
 */

#ifndef EDHOC_BENCHMARK_H
#define EDHOC_BENCHMARK_H

/* Same iteration counts as the in-memory benchmark */
#define SOCK_BENCH_ITERATIONS             100
#define SOCK_BENCH_HANDSHAKE_ITERATIONS   50

/* Output directory for socket benchmark CSVs */
#define SOCK_BENCH_OUTPUT_DIR   "output"
#define SOCK_CSV_OPERATIONS     SOCK_BENCH_OUTPUT_DIR "/benchmark_operations.csv"
#define SOCK_CSV_OVERHEAD       SOCK_BENCH_OUTPUT_DIR "/benchmark_overhead.csv"
#define SOCK_CSV_HANDSHAKE      SOCK_BENCH_OUTPUT_DIR "/benchmark_handshake.csv"

/* Base TCP port — each iteration uses base_port + variant_offset */
#define SOCK_BENCH_BASE_PORT    19000

/* Base UDP port for AAA RADIUS server (3-party architecture) */
#define AAA_RADIUS_BASE_PORT    21000

/**
 * @brief Run full socket-based benchmark (all 15 variants).
 *
 * Measures:
 *   - Crypto operations (same as in-memory benchmark)
 *   - Handshake timing over TCP localhost sockets
 *   - AAA handshake timing over RADIUS/UDP (3-party architecture)
 *   - Overhead derived from calibrated ops
 *
 * @return 0 on success, -1 on failure
 */
int run_edhoc_benchmark_socket(void);

#endif /* EDHOC_BENCHMARK_H */
