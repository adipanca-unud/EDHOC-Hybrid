/*
 * EDHOC-Hybrid: Main entry point with interactive menu
 * Implements EDHOC Protocol per RFC 9528 using uoscore-uedhoc library.
 *
 * Program ini mensimulasikan handshake EDHOC antara Initiator dan Responder
 * melalui 3 pesan (message_1, message_2, message_3) untuk menghasilkan
 * shared secret key (PRK_out) yang kemudian diturunkan menjadi OSCORE keys.
 *
 * Supports:
 *   1. EDHOC Type 0 - Signature-Signature (Classic)
 *      - Method 0: Initiator Sign + Responder Sign
 *      - Suite 0: X25519 (ephemeral DH) + EdDSA (Signature & Verify)
 *      - Autentikasi: Initiator menandatangani dengan EdDSA private key,
 *        Responder memverifikasi signature dengan EdDSA public key
 *
 *   2. EDHOC Type 3 - MAC-MAC (Classic)
 *      - Method 3: Initiator Static DH + Responder Static DH
 *      - Suite 0: X25519 (ephemeral + static DH) + HMAC (MAC)
 *      - Autentikasi: Kedua pihak menggunakan X25519 Static DH untuk
 *        menghitung MAC (bukan signature). Classic algorithm = X25519 DH.
 *
 * Usage:
 *   ./build/edhoc_hybrid       # Interactive menu
 *   ./build/edhoc_hybrid 1     # Run Type 0 (Sig-Sig) directly
 *   ./build/edhoc_hybrid 2     # Run Type 3 (MAC-MAC) directly
 *   ./build/edhoc_hybrid 3     # Run Benchmark (Type 0 + Type 3)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "edhoc_common.h"
#include "edhoc_type0_classic.h"
#include "edhoc_type3_classic.h"
#include "edhoc_type0_pq.h"
#include "edhoc_type3_pq.h"
#include "edhoc_type3_hybrid.h"
#include "edhoc_benchmark.h"
#include "edhoc_benchmark_socket.h"

static void print_banner(void)
{
	printf("\n");
	printf("%s%s", CLR_BOLD, CLR_CYAN);
	printf("╔══════════════════════════════════════════════════════════════╗\n");
	printf("║                                                              ║\n");
	printf("║              EDHOC-Hybrid Protocol Implementation            ║\n");
	printf("║                    RFC 9528 (EDHOC)                          ║\n");
	printf("║           Using uoscore-uedhoc Core Library                  ║\n");
	printf("║                                                              ║\n");
	printf("╚══════════════════════════════════════════════════════════════╝\n");
	printf("%s\n", CLR_RESET);
}

static void print_menu(void)
{
	printf("%s%s  Select EDHOC Type:%s\n\n", CLR_BOLD, CLR_YELLOW, CLR_RESET);
	printf("  %s[1]%s EDHOC Type 0 - Signature-Signature (Classic)\n",
	       CLR_GREEN, CLR_RESET);
	printf("      %sMethod 0 | Suite 0 | X25519 + EdDSA%s\n",
	       CLR_CYAN, CLR_RESET);
	printf("\n");
	printf("  %s[2]%s EDHOC Type 3 - MAC-MAC (Classic)\n",
	       CLR_GREEN, CLR_RESET);
	printf("      %sMethod 3 | Suite 0 | X25519 (Static DH + MAC)%s\n",
	       CLR_CYAN, CLR_RESET);
	printf("\n");
	printf("  %s[3]%s Benchmark Classic (Type 0 + Type 3)\n",
	       CLR_GREEN, CLR_RESET);
	printf("      %sMeasure operations, overhead, handshake → 3 CSV files%s\n",
	       CLR_CYAN, CLR_RESET);
	printf("\n");
	printf("  %s[4]%s EDHOC Type 0 PQ - KEM-based Sig-Sig (ML-KEM-768)\n",
	       CLR_GREEN, CLR_RESET);
	printf("      %sPost-Quantum | ML-KEM-768 | KEM Encaps/Decaps + MAC%s\n",
	       CLR_CYAN, CLR_RESET);
	printf("\n");
	printf("  %s[5]%s EDHOC Type 3 PQ - KEM-based MAC-MAC (ML-KEM-768)\n",
	       CLR_GREEN, CLR_RESET);
	printf("      %sPost-Quantum | ML-KEM-768 | KEM Encaps/Decaps + MAC%s\n",
	       CLR_CYAN, CLR_RESET);
	printf("\n");
	printf("  %s[6]%s Full Benchmark (Classic + PQ)\n",
	       CLR_GREEN, CLR_RESET);
	printf("      %sAll 4 variants → 3 CSV files (operations, overhead, handshake)%s\n",
	       CLR_CYAN, CLR_RESET);
	printf("\n");
	printf("  %s[7]%s EDHOC Type 3 Hybrid (X25519 + ML-KEM-768)\n",
	       CLR_GREEN, CLR_RESET);
	printf("      %sHybrid | ECDHE + KEM | MAC-MAC (static DH auth)%s\n",
	       CLR_CYAN, CLR_RESET);
	printf("\n");
	printf("  %s[8]%s Full Benchmark (Classic + PQ + Hybrid)\n",
	       CLR_GREEN, CLR_RESET);
	printf("      %sAll 5 variants → 3 CSV files%s\n",
	       CLR_CYAN, CLR_RESET);
	printf("\n");
	printf("  %s[9]%s Socket Benchmark (TCP Client-Server, All 5 Variants)\n",
	       CLR_GREEN, CLR_RESET);
	printf("      %sTCP localhost | All 5 variants → 3 CSV files (output_socket/)%s\n",
	       CLR_CYAN, CLR_RESET);
	printf("\n");
	printf("  %s[0]%s Exit\n", CLR_RED, CLR_RESET);
	printf("\n");
	printf("  %s> Choice: %s", CLR_BOLD, CLR_RESET);
}

int main(int argc, char *argv[])
{
	int choice = -1;
	int result = 0;

	/* Allow command-line argument to skip interactive menu */
	if (argc > 1) {
		choice = atoi(argv[1]);
	}

	while (1) {
		if (choice < 0) {
			print_banner();
			print_menu();

			if (scanf("%d", &choice) != 1) {
				/* Clear invalid input */
				int c;
				while ((c = getchar()) != '\n' && c != EOF)
					;
				printf("\n");
				print_error("Invalid input. Please enter 0-9.");
				choice = -1;
				continue;
			}
		}

		switch (choice) {
		case 0:
			printf("\n");
			print_info("Exiting EDHOC-Hybrid. Goodbye!");
			printf("\n");
			return 0;

		case 1:
			result = run_edhoc_type0_classic();
			if (result != 0) {
				print_error("Type 0 (Signature-Signature) failed!");
			}
			break;

		case 2:
			result = run_edhoc_type3_classic();
			if (result != 0) {
				print_error("Type 3 (MAC-MAC) failed!");
			}
			break;

		case 3:
			result = run_edhoc_benchmark();
			if (result != 0) {
				print_error("Benchmark failed!");
			}
			break;

		case 4:
			result = run_edhoc_type0_pq();
			if (result != 0) {
				print_error("Type 0 PQ (KEM Sig-Sig) failed!");
			}
			break;

		case 5:
			result = run_edhoc_type3_pq();
			if (result != 0) {
				print_error("Type 3 PQ (KEM MAC-MAC) failed!");
			}
			break;

		case 6:
			result = run_edhoc_benchmark_full();
			if (result != 0) {
				print_error("Full Benchmark (Classic + PQ) failed!");
			}
			break;

		case 7:
			result = run_edhoc_type3_hybrid();
			if (result != 0) {
				print_error("Type 3 Hybrid (ECDHE + KEM) failed!");
			}
			break;

		case 8:
			result = run_edhoc_benchmark_full_hybrid();
			if (result != 0) {
				print_error("Full Benchmark (Classic + PQ + Hybrid) failed!");
			}
			break;

		case 9:
			result = run_edhoc_benchmark_socket();
			if (result != 0) {
				print_error("Socket Benchmark (TCP) failed!");
			}
			break;

		default:
			printf("\n");
			print_error("Invalid choice. Please enter 0-9.");
			break;
		}

		/* If launched with command-line arg, exit after one run */
		if (argc > 1) {
			return result;
		}

		/* Reset for next iteration */
		choice = -1;
		printf("\n%sPress Enter to continue...%s", CLR_YELLOW, CLR_RESET);
		/* Consume leftover newline */
		int c;
		while ((c = getchar()) != '\n' && c != EOF)
			;
		getchar();
	}

	return 0;
}
