/*
 * =============================================================================
 * Pure Cryptographic Operations Benchmark — Public API
 * =============================================================================
 *
 * Provides run_crypto_benchmark() so the main binary can call the standalone
 * crypto benchmark as part of a larger benchmark run (e.g. mode 9).
 *
 * Output CSV files (in output/):
 *   - benchmark_crypto_ops.csv      (full ops × algo matrix)
 *   - benchmark_crypto_matrix.csv   (avg µs matrix)
 *   - benchmark_crypto_simple.csv   (one-row-per-operation, simple format)
 */

#ifndef BENCHMARK_CRYPTO_H
#define BENCHMARK_CRYPTO_H

/**
 * @brief Run the pure cryptographic operations benchmark.
 *
 * Benchmarks X25519, Ed25519, P-256, ECDSA-P-256, ML-KEM-768, ML-DSA-65,
 * X25519+ML-KEM-768 (Hybrid), and AES-256-GCM.  Results are written to
 * three CSV files under output/.
 *
 * @param role_suffix  If non-NULL and non-empty (e.g. "initiator"),
 *                     CSV filenames are suffixed: benchmark_crypto_ops_initiator.csv
 *                     Pass NULL or "" for default (no suffix).
 * @return 0 on success, non-zero on failure.
 */
int run_crypto_benchmark(const char *role_suffix);

#endif /* BENCHMARK_CRYPTO_H */
