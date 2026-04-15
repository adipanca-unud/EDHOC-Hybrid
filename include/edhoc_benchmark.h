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
 * All 5 variants:
 *   - Type 0 Classic (Sig-Sig)
 *   - Type 3 Classic (MAC-MAC)
 *   - Type 0 PQ (KEM-based Sig-Sig, ML-KEM-768)
 *   - Type 3 PQ (KEM-based MAC-MAC, ML-KEM-768)
 *   - Type 3 Hybrid (X25519 ECDHE + ML-KEM-768)
 */

#ifndef EDHOC_BENCHMARK_H
#define EDHOC_BENCHMARK_H

/* Same iteration counts as the in-memory benchmark */
#define SOCK_BENCH_ITERATIONS             5
#define SOCK_BENCH_HANDSHAKE_ITERATIONS   5

/* Output directory for socket benchmark CSVs */
#define SOCK_BENCH_OUTPUT_DIR   "output"
#define SOCK_CSV_OPERATIONS     SOCK_BENCH_OUTPUT_DIR "/benchmark_operations.csv"
#define SOCK_CSV_OVERHEAD       SOCK_BENCH_OUTPUT_DIR "/benchmark_overhead.csv"
#define SOCK_CSV_HANDSHAKE      SOCK_BENCH_OUTPUT_DIR "/benchmark_handshake.csv"

/* Base TCP port — each iteration uses base_port + variant_offset */
#define SOCK_BENCH_BASE_PORT    19000

/**
 * @brief Run full socket-based benchmark (all 5 variants).
 *
 * Measures:
 *   - Crypto operations (same as in-memory benchmark)
 *   - Handshake timing over TCP localhost sockets
 *   - Overhead derived from calibrated ops
 *
 * @param role_suffix  If non-NULL and non-empty (e.g. "initiator"),
 *                     CSV filenames are suffixed: benchmark_operations_initiator.csv
 *                     Pass NULL or "" for default (no suffix).
 * @return 0 on success, -1 on failure
 */
int run_edhoc_benchmark_socket(const char *role_suffix);

#endif /* EDHOC_BENCHMARK_H */
