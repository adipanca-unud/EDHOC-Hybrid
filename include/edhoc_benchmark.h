/*
 * =============================================================================
 * EDHOC-Hybrid: Benchmark System Header
 * =============================================================================
 *
 * Sistem benchmark komprehensif untuk mengukur performa dua varian EDHOC:
 *   - Type 0 (Sig-Sig): Method 0, EdDSA Signature + Verify
 *   - Type 3 (MAC-MAC): Method 3, X25519 Static DH + MAC
 *
 * Benchmark mengukur 3 kategori dari sisi Initiator DAN Responder:
 *
 *   1. Operations Benchmark (benchmark_operations.csv)
 *      Waktu eksekusi setiap operasi kriptografi primitif:
 *      - KeyGen    : Pembangkitan kunci X25519/EdDSA
 *      - Encap     : AEAD Encrypt (AES-CCM-16-64-128)
 *      - Decap     : AEAD Decrypt (AES-CCM-16-64-128)
 *      - Signature : EdDSA Sign (hanya Type 0)
 *      - Verify    : EdDSA Verify (hanya Type 0)
 *      - ECDH      : X25519 Shared Secret Derivation
 *      - HKDF      : HKDF-Extract + HKDF-Expand (SHA-256)
 *
 *   2. Overhead Benchmark (benchmark_overhead.csv)
 *      Resource usage selama full handshake:
 *      - CPU Time     : Waktu CPU yang digunakan (user + system) dalam µs
 *      - Memory Peak  : Peak RSS memory usage dalam bytes
 *
 *   3. Handshake Benchmark (benchmark_handshake.csv)
 *      Waktu per fase dalam handshake EDHOC:
 *      - Processing     : Total waktu komputasi kriptografi
 *      - TxRx           : Total waktu transmisi + penerimaan pesan
 *      - Precomputation : Waktu setup kunci sebelum handshake
 *      - Total          : Total waktu handshake end-to-end
 *
 * Output: 3 file CSV di direktori output/
 * =============================================================================
 */

#ifndef EDHOC_BENCHMARK_H
#define EDHOC_BENCHMARK_H

#include <stdint.h>

/* Jumlah iterasi untuk rata-rata benchmark operasi */
#define BENCH_ITERATIONS 100

/* Jumlah iterasi untuk benchmark handshake */
#define BENCH_HANDSHAKE_ITERATIONS 50

/* Direktori output CSV */
#define BENCH_OUTPUT_DIR "output"

/* Nama file CSV output */
#define BENCH_CSV_OPERATIONS  BENCH_OUTPUT_DIR "/benchmark_operations.csv"
#define BENCH_CSV_OVERHEAD    BENCH_OUTPUT_DIR "/benchmark_overhead.csv"
#define BENCH_CSV_HANDSHAKE   BENCH_OUTPUT_DIR "/benchmark_handshake.csv"

/**
 * @brief Menjalankan seluruh benchmark suite untuk kedua tipe EDHOC.
 *
 * Mengukur operasi kriptografi, overhead resource, dan waktu handshake
 * untuk Type 0 (Sig-Sig) dan Type 3 (MAC-MAC) dari sisi Initiator
 * dan Responder, kemudian menyimpan hasilnya ke 3 file CSV.
 *
 * @return 0 jika sukses, -1 jika gagal
 */
int run_edhoc_benchmark(void);

/**
 * @brief Menjalankan benchmark lengkap: Classic + PQ (4 varian).
 *
 * Mengukur semua 4 varian EDHOC:
 *   - Type 0 Classic (Sig-Sig)
 *   - Type 3 Classic (MAC-MAC)
 *   - Type 0 PQ (KEM-based Sig-Sig, ML-KEM-768)
 *   - Type 3 PQ (KEM-based MAC-MAC, ML-KEM-768)
 *
 * @return 0 jika sukses, -1 jika gagal
 */
int run_edhoc_benchmark_full(void);

#endif /* EDHOC_BENCHMARK_H */
