/*
 * =============================================================================
 * EDHOC-Hybrid: Peer-to-Peer (P2P) Network Benchmark
 * =============================================================================
 *
 * Benchmark EDHOC handshakes between two separate machines over a real
 * TCP network:
 *   - Responder (server) runs on a Linux server (e.g., Ubuntu x86_64)
 *   - Initiator (client) runs on a Raspberry Pi (aarch64)
 *
 * Unlike the localhost benchmark (edhoc_benchmark.c) which runs both
 * roles as threads on the same machine, this P2P benchmark runs each
 * role as a separate process on a separate machine, measuring real
 * network latency and per-device crypto performance.
 *
 * Usage:
 *   Server (Responder):
 *     ./build/edhoc_hybrid 9 --responder --port 19000
 *
 *   Client (Initiator):
 *     ./build/edhoc_hybrid 9 --initiator --host <SERVER_IP> --port 19000
 *
 * Output:
 *   Each side writes its own CSV files in output/ (suffixed with role).
 *
 * All 5 variants:
 *   - Type 0 Classic (Sig-Sig)
 *   - Type 3 Classic (MAC-MAC)
 *   - Type 0 PQ (KEM-based Sig-Sig, ML-KEM-768)
 *   - Type 3 PQ (KEM-based MAC-MAC, ML-KEM-768)
 *   - Type 3 Hybrid (X25519 ECDHE + ML-KEM-768)
 */

#ifndef EDHOC_BENCHMARK_P2P_H
#define EDHOC_BENCHMARK_P2P_H

/* Iteration counts for P2P benchmark */
#define P2P_BENCH_ITERATIONS             100
#define P2P_BENCH_HANDSHAKE_ITERATIONS   50

/* Output directory */
#define P2P_BENCH_OUTPUT_DIR   "output"

/* Default TCP port */
#define P2P_BENCH_DEFAULT_PORT  19000

/* Maximum host string length */
#define P2P_MAX_HOST_LEN        256

/**
 * @brief Run P2P benchmark as Responder (server).
 *
 * Listens on all interfaces (0.0.0.0) at the given port.
 * Runs crypto primitive benchmark locally, then waits for Initiator
 * to connect for each handshake variant.
 *
 * @param port TCP port to listen on
 * @return 0 on success, -1 on failure
 */
int run_p2p_responder(int port);

/**
 * @brief Run P2P benchmark as Initiator (client).
 *
 * Connects to the remote Responder at host:port.
 * Runs crypto primitive benchmark locally, then connects for each
 * handshake variant.
 *
 * @param host IP address or hostname of the Responder
 * @param port TCP port of the Responder
 * @return 0 on success, -1 on failure
 */
int run_p2p_initiator(const char *host, int port);

/**
 * @brief Parse command-line arguments for P2P benchmark mode.
 *
 * Expected formats:
 *   ./edhoc_hybrid 9 --responder [--port PORT]
 *   ./edhoc_hybrid 9 --initiator --host HOST [--port PORT]
 *
 * @param argc argument count
 * @param argv argument values
 * @return 0 on success, -1 on error (prints usage)
 */
int run_p2p_benchmark(int argc, char *argv[]);

#endif /* EDHOC_BENCHMARK_P2P_H */
