/*
 * =============================================================================
 * EDHOC-Hybrid: Peer-to-Peer (P2P) Network Benchmark
 * =============================================================================
 *
 * Runs EDHOC benchmark between two SEPARATE machines over a real TCP network.
 *   - Responder (server): listens on 0.0.0.0:PORT  (e.g. Ubuntu server)
 *   - Initiator (client): connects to HOST:PORT      (e.g. Raspberry Pi)
 *
 * Design:
 *   1. Control channel on PORT: Initiator connects, they sync via text msgs.
 *   2. For each of 5 variants, Responder creates a listen socket on PORT+offset,
 *      tells Initiator, they run N handshake iterations each on PORT+offset+iter.
 *   3. After all variants, each side writes its own role-suffixed CSV files.
 *
 * All 5 variants use the SAME full crypto protocol as edhoc_benchmark.c.
 *   - Classic Type 0 / Type 3: uses uoscore-uedhoc edhoc_initiator/responder_run
 *   - PQ Type 0 / Type 3: full ML-KEM-768 (+ML-DSA-65) handshake
 *   - Hybrid Type 3: X25519 ECDHE + ML-KEM-768 handshake
 *
 * The only difference: server binds INADDR_ANY, client connects to remote IP.
 * =============================================================================
 */


#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

#include "edhoc_benchmark_p2p.h"
#include "edhoc_benchmark.h"
#include "benchmark_crypto.h"
#include "edhoc_common.h"
#include "edhoc_type0_classic.h"
#include "edhoc_type3_classic.h"
#include "edhoc_type0_pq.h"
#include "edhoc_type3_pq.h"
#include "edhoc_type3_hybrid.h"
#include "edhoc_pq_kem.h"
#include "edhoc_test_vectors_rfc9529.h"
#include "edhoc_type3_x25519_testvec.h"

/* Low-level crypto APIs (same as edhoc_benchmark.c) */
#include "common/crypto_wrapper.h"
#include "edhoc/suites.h"

/* =============================================================================
 * Timing
 * ========================================================================== */
static inline uint64_t p2p_time_ns(void) {
	struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}
static inline uint64_t p2p_cpu_ns(void) {
	struct timespec ts; clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}
static inline double p2p_us(uint64_t a, uint64_t b) { return (double)(b-a)/1000.0; }

/* =============================================================================
 * Quiet guard (suppress library debug/dump prints during benchmark hot paths)
 * ========================================================================== */
struct p2p_quiet_guard {
	int stdout_saved;
	int stderr_saved;
	int null_fd;
};

static void p2p_quiet_begin(struct p2p_quiet_guard *g)
{
	g->stdout_saved = -1;
	g->stderr_saved = -1;
	g->null_fd = -1;

	fflush(stdout);
	fflush(stderr);

	g->stdout_saved = dup(STDOUT_FILENO);
	g->stderr_saved = dup(STDERR_FILENO);
	g->null_fd = open("/dev/null", O_WRONLY);

	if (g->null_fd >= 0) {
		if (g->stdout_saved >= 0)
			dup2(g->null_fd, STDOUT_FILENO);
		if (g->stderr_saved >= 0)
			dup2(g->null_fd, STDERR_FILENO);
	}
}

static void p2p_quiet_end(struct p2p_quiet_guard *g)
{
	fflush(stdout);
	fflush(stderr);

	if (g->stdout_saved >= 0) {
		dup2(g->stdout_saved, STDOUT_FILENO);
		close(g->stdout_saved);
		g->stdout_saved = -1;
	}
	if (g->stderr_saved >= 0) {
		dup2(g->stderr_saved, STDERR_FILENO);
		close(g->stderr_saved);
		g->stderr_saved = -1;
	}
	if (g->null_fd >= 0) {
		close(g->null_fd);
		g->null_fd = -1;
	}
}

/* =============================================================================
 * TCP helpers (P2P: server uses INADDR_ANY, client uses remote IP)
 * ========================================================================== */
static int p2p_send(int fd, const uint8_t *d, uint32_t len) {
	uint32_t nl = htonl(len);
	if (send(fd, &nl, 4, MSG_NOSIGNAL) != 4) return -1;
	uint32_t s = 0;
	while (s < len) { ssize_t n = send(fd, d+s, len-s, MSG_NOSIGNAL); if (n<=0) return -1; s+=(uint32_t)n; }
	return 0;
}
static int p2p_recv(int fd, uint8_t *buf, uint32_t bsz, uint32_t *olen) {
	/* Set 30-second receive timeout so we never block forever */
	struct timeval tv = {30, 0};
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	uint32_t nl, g=0;
	while (g<4) { ssize_t n=recv(fd,((uint8_t*)&nl)+g,4-g,0); if(n<=0) return -1; g+=(uint32_t)n; }
	uint32_t ml=ntohl(nl); if(ml>bsz) return -1; g=0;
	while (g<ml) { ssize_t n=recv(fd,buf+g,ml-g,0); if(n<=0) return -1; g+=(uint32_t)n; }
	*olen=ml; return 0;
}
static int p2p_server(int port) {
	int fd=socket(AF_INET,SOCK_STREAM,0); if(fd<0) return -1;
	int o=1; setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&o,sizeof(o));
	struct sockaddr_in a={0}; a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_ANY); a.sin_port=htons((uint16_t)port);
	if(bind(fd,(struct sockaddr*)&a,sizeof(a))<0){perror("bind");close(fd);return -1;}
	if(listen(fd,1)<0){close(fd);return -1;} return fd;
}
static int p2p_connect(const char *host, int port) {
	int fd=socket(AF_INET,SOCK_STREAM,0); if(fd<0) return -1;
	struct sockaddr_in a={0}; a.sin_family=AF_INET; a.sin_port=htons((uint16_t)port);
	if(inet_pton(AF_INET,host,&a.sin_addr)!=1){
		struct hostent *h=gethostbyname(host); if(!h){close(fd);return -1;}
		memcpy(&a.sin_addr,h->h_addr_list[0],h->h_length);
	}
	for(int r=0;r<100;r++){if(connect(fd,(struct sockaddr*)&a,sizeof(a))==0) return fd; struct timespec ts={0,50000*1000}; nanosleep(&ts,NULL);}
	close(fd); return -1;
}
static int p2p_accept(int listen_fd) {
	/* Set 30-second accept timeout so we never block forever */
	struct timeval tv = {30, 0};
	setsockopt(listen_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	return accept(listen_fd, NULL, NULL);
}
static void p2p_nodelay(int fd){int o=1;setsockopt(fd,IPPROTO_TCP,TCP_NODELAY,&o,sizeof(o));}

/* Control messages */
static int ctrl_s(int fd, const char *m){return p2p_send(fd,(const uint8_t*)m,(uint32_t)strlen(m));}
static int ctrl_r(int fd, char *b, int sz){uint32_t l=0;if(p2p_recv(fd,(uint8_t*)b,(uint32_t)(sz-1),&l)!=0)return -1;b[l]='\0';return 0;}

#define P2P_TAG_READY     "READY"
#define P2P_TAG_ITER_OK   "ITER_OK"
#define P2P_TAG_DONE      "DONE"

/* =============================================================================
 * Thread-local socket fd + tx/rx callbacks for uoscore-uedhoc Classic
 * (needed by edhoc_initiator_run / edhoc_responder_run)
 * ========================================================================== */
static __thread int _p2p_fd = -1;
static __thread uint64_t _p2p_txrx = 0;

static enum err p2p_tx(void *sock, struct byte_array *data) {
	uint64_t s=p2p_time_ns(); int r=p2p_send(_p2p_fd,data->ptr,data->len);
	_p2p_txrx+=(p2p_time_ns()-s); return (r==0)?ok:buffer_to_small;
}
static enum err p2p_rx(void *sock, struct byte_array *data) {
	uint64_t s=p2p_time_ns(); uint32_t l=0;
	int r=p2p_recv(_p2p_fd,data->ptr,data->len,&l);
	_p2p_txrx+=(p2p_time_ns()-s); if(r!=0) return buffer_to_small;
	data->len=l; return ok;
}

/* =============================================================================
 * Result structures
 * ========================================================================== */
struct p2p_hs_result {
	double wall_us, cpu_us, txrx_us;
	int success;
};

struct p2p_hs_accum {
	double total_wall, total_cpu, total_txrx;
	int success_count;
};

/* Keep same type labels as socket benchmark CSVs */
static const char *P2P_TYPE_LABELS[5] = {
	"Type0_SigSig", "Type3_MACMAC", "Type0_PQ", "Type3_PQ", "Type3_Hybrid"
};

/* =============================================================================
 * Classic handshake — one iteration
 * ========================================================================== */
static struct p2p_hs_result p2p_classic_initiator(int type, const char *host, int port)
{
	struct p2p_hs_result res = {0};
	_p2p_fd = p2p_connect(host, port);
	if (_p2p_fd < 0) return res;
	p2p_nodelay(_p2p_fd);
	_p2p_txrx = 0;

	uint8_t err_buf[64]; struct byte_array err_msg={.ptr=err_buf,.len=64};
	uint8_t prk_buf[32]; struct byte_array prk_out={.ptr=prk_buf,.len=32};
	enum err result;

	uint64_t cs = p2p_cpu_ns(), ws = p2p_time_ns();

	if (type == 0) {
		struct edhoc_initiator_context ci; memset(&ci,0,sizeof(ci));
		ci.sock=NULL; ci.method=(enum method_type)T1_RFC9529__METHOD;
		ci.c_i.len=T1_RFC9529__C_I_LEN; ci.c_i.ptr=(uint8_t*)T1_RFC9529__C_I;
		ci.suites_i.len=T1_RFC9529__SUITES_I_LEN; ci.suites_i.ptr=(uint8_t*)T1_RFC9529__SUITES_I;
		ci.ead_1.len=0; ci.ead_1.ptr=NULL; ci.ead_3.len=0; ci.ead_3.ptr=NULL;
		ci.id_cred_i.len=T1_RFC9529__ID_CRED_I_LEN; ci.id_cred_i.ptr=(uint8_t*)T1_RFC9529__ID_CRED_I;
		ci.cred_i.len=T1_RFC9529__CRED_I_LEN; ci.cred_i.ptr=(uint8_t*)T1_RFC9529__CRED_I;
		ci.g_x.len=T1_RFC9529__G_X_LEN; ci.g_x.ptr=(uint8_t*)T1_RFC9529__G_X;
		ci.x.len=T1_RFC9529__X_LEN; ci.x.ptr=(uint8_t*)T1_RFC9529__X;
		ci.sk_i.len=T1_RFC9529__SK_I_LEN; ci.sk_i.ptr=(uint8_t*)T1_RFC9529__SK_I;
		ci.pk_i.len=T1_RFC9529__PK_I_LEN; ci.pk_i.ptr=(uint8_t*)T1_RFC9529__PK_I;
		ci.g_i.len=0; ci.g_i.ptr=NULL; ci.i.len=0; ci.i.ptr=NULL;
		struct other_party_cred cr; memset(&cr,0,sizeof(cr));
		cr.id_cred.len=T1_RFC9529__ID_CRED_R_LEN; cr.id_cred.ptr=(uint8_t*)T1_RFC9529__ID_CRED_R;
		cr.cred.len=T1_RFC9529__CRED_R_LEN; cr.cred.ptr=(uint8_t*)T1_RFC9529__CRED_R;
		cr.pk.len=T1_RFC9529__PK_R_LEN; cr.pk.ptr=(uint8_t*)T1_RFC9529__PK_R;
		cr.g.len=0; cr.g.ptr=NULL; cr.ca.len=0; cr.ca.ptr=NULL; cr.ca_pk.len=0; cr.ca_pk.ptr=NULL;
		struct cred_array ca={.len=1,.ptr=&cr};
		{
			struct p2p_quiet_guard qg;
			p2p_quiet_begin(&qg);
			result = edhoc_initiator_run(&ci, &ca, &err_msg, &prk_out,
						     p2p_tx, p2p_rx, ead_process);
			p2p_quiet_end(&qg);
		}
	} else {
		struct edhoc_initiator_context ci; memset(&ci,0,sizeof(ci));
		ci.sock=NULL; ci.method=(enum method_type)T3_X25519_METHOD;
		ci.c_i.len=T3_X25519_C_I_LEN; ci.c_i.ptr=(uint8_t*)T3_X25519_C_I;
		ci.suites_i.len=T3_X25519_SUITES_I_LEN; ci.suites_i.ptr=(uint8_t*)T3_X25519_SUITES_I;
		ci.ead_1.len=0; ci.ead_1.ptr=NULL; ci.ead_3.len=0; ci.ead_3.ptr=NULL;
		ci.id_cred_i.len=T1_RFC9529__ID_CRED_I_LEN; ci.id_cred_i.ptr=(uint8_t*)T1_RFC9529__ID_CRED_I;
		ci.cred_i.len=T1_RFC9529__CRED_I_LEN; ci.cred_i.ptr=(uint8_t*)T1_RFC9529__CRED_I;
		ci.g_x.len=T3_X25519_G_X_LEN; ci.g_x.ptr=(uint8_t*)T3_X25519_G_X;
		ci.x.len=T3_X25519_X_LEN; ci.x.ptr=(uint8_t*)T3_X25519_X;
		ci.g_i.len=T3_X25519_G_I_LEN; ci.g_i.ptr=(uint8_t*)T3_X25519_G_I;
		ci.i.len=T3_X25519_I_LEN; ci.i.ptr=(uint8_t*)T3_X25519_I;
		ci.sk_i.len=0; ci.sk_i.ptr=NULL; ci.pk_i.len=0; ci.pk_i.ptr=NULL;
		struct other_party_cred cr; memset(&cr,0,sizeof(cr));
		cr.id_cred.len=T1_RFC9529__ID_CRED_R_LEN; cr.id_cred.ptr=(uint8_t*)T1_RFC9529__ID_CRED_R;
		cr.cred.len=T1_RFC9529__CRED_R_LEN; cr.cred.ptr=(uint8_t*)T1_RFC9529__CRED_R;
		cr.g.len=T3_X25519_G_R_LEN; cr.g.ptr=(uint8_t*)T3_X25519_G_R;
		cr.pk.len=0; cr.pk.ptr=NULL; cr.ca.len=0; cr.ca.ptr=NULL; cr.ca_pk.len=0; cr.ca_pk.ptr=NULL;
		struct cred_array ca={.len=1,.ptr=&cr};
		{
			struct p2p_quiet_guard qg;
			p2p_quiet_begin(&qg);
			result = edhoc_initiator_run(&ci, &ca, &err_msg, &prk_out,
						     p2p_tx, p2p_rx, ead_process);
			p2p_quiet_end(&qg);
		}
	}
	uint64_t we=p2p_time_ns(), ce=p2p_cpu_ns();
	close(_p2p_fd); _p2p_fd=-1;
	res.wall_us=p2p_us(ws,we); res.cpu_us=p2p_us(cs,ce); res.txrx_us=(double)_p2p_txrx/1000.0;
	res.success=(result==ok)?1:0; return res;
}

static struct p2p_hs_result p2p_classic_responder(int type, int listen_fd)
{
	struct p2p_hs_result res = {0};
	_p2p_fd = p2p_accept(listen_fd);
	if (_p2p_fd < 0) return res;
	p2p_nodelay(_p2p_fd);
	_p2p_txrx = 0;

	uint8_t err_buf[64]; struct byte_array err_msg={.ptr=err_buf,.len=64};
	uint8_t prk_buf[32]; struct byte_array prk_out={.ptr=prk_buf,.len=32};
	enum err result;

	uint64_t cs=p2p_cpu_ns(), ws=p2p_time_ns();

	if (type == 0) {
		struct edhoc_responder_context cr; memset(&cr,0,sizeof(cr));
		cr.sock=NULL;
		cr.c_r.len=T1_RFC9529__C_R_LEN; cr.c_r.ptr=(uint8_t*)T1_RFC9529__C_R;
		cr.suites_r.len=T1_RFC9529__SUITES_R_LEN; cr.suites_r.ptr=(uint8_t*)T1_RFC9529__SUITES_R;
		cr.ead_2.len=0; cr.ead_2.ptr=NULL; cr.ead_4.len=0; cr.ead_4.ptr=NULL;
		cr.id_cred_r.len=T1_RFC9529__ID_CRED_R_LEN; cr.id_cred_r.ptr=(uint8_t*)T1_RFC9529__ID_CRED_R;
		cr.cred_r.len=T1_RFC9529__CRED_R_LEN; cr.cred_r.ptr=(uint8_t*)T1_RFC9529__CRED_R;
		cr.g_y.len=T1_RFC9529__G_Y_LEN; cr.g_y.ptr=(uint8_t*)T1_RFC9529__G_Y;
		cr.y.len=T1_RFC9529__Y_LEN; cr.y.ptr=(uint8_t*)T1_RFC9529__Y;
		cr.sk_r.len=T1_RFC9529__SK_R_LEN; cr.sk_r.ptr=(uint8_t*)T1_RFC9529__SK_R;
		cr.pk_r.len=T1_RFC9529__PK_R_LEN; cr.pk_r.ptr=(uint8_t*)T1_RFC9529__PK_R;
		cr.g_r.len=0; cr.g_r.ptr=NULL; cr.r.len=0; cr.r.ptr=NULL;
		struct other_party_cred ci; memset(&ci,0,sizeof(ci));
		ci.id_cred.len=T1_RFC9529__ID_CRED_I_LEN; ci.id_cred.ptr=(uint8_t*)T1_RFC9529__ID_CRED_I;
		ci.cred.len=T1_RFC9529__CRED_I_LEN; ci.cred.ptr=(uint8_t*)T1_RFC9529__CRED_I;
		ci.pk.len=T1_RFC9529__PK_I_LEN; ci.pk.ptr=(uint8_t*)T1_RFC9529__PK_I;
		ci.g.len=0; ci.g.ptr=NULL; ci.ca.len=0; ci.ca.ptr=NULL; ci.ca_pk.len=0; ci.ca_pk.ptr=NULL;
		struct cred_array ca={.len=1,.ptr=&ci};
		{
			struct p2p_quiet_guard qg;
			p2p_quiet_begin(&qg);
			result = edhoc_responder_run(&cr, &ca, &err_msg, &prk_out,
						     p2p_tx, p2p_rx, ead_process);
			p2p_quiet_end(&qg);
		}
	} else {
		struct edhoc_responder_context cr; memset(&cr,0,sizeof(cr));
		cr.sock=NULL;
		cr.c_r.len=T3_X25519_C_R_LEN; cr.c_r.ptr=(uint8_t*)T3_X25519_C_R;
		cr.suites_r.len=T3_X25519_SUITES_R_LEN; cr.suites_r.ptr=(uint8_t*)T3_X25519_SUITES_R;
		cr.ead_2.len=0; cr.ead_2.ptr=NULL; cr.ead_4.len=0; cr.ead_4.ptr=NULL;
		cr.id_cred_r.len=T1_RFC9529__ID_CRED_R_LEN; cr.id_cred_r.ptr=(uint8_t*)T1_RFC9529__ID_CRED_R;
		cr.cred_r.len=T1_RFC9529__CRED_R_LEN; cr.cred_r.ptr=(uint8_t*)T1_RFC9529__CRED_R;
		cr.g_y.len=T3_X25519_G_Y_LEN; cr.g_y.ptr=(uint8_t*)T3_X25519_G_Y;
		cr.y.len=T3_X25519_Y_LEN; cr.y.ptr=(uint8_t*)T3_X25519_Y;
		cr.g_r.len=T3_X25519_G_R_LEN; cr.g_r.ptr=(uint8_t*)T3_X25519_G_R;
		cr.r.len=T3_X25519_R_LEN; cr.r.ptr=(uint8_t*)T3_X25519_R;
		cr.sk_r.len=0; cr.sk_r.ptr=NULL; cr.pk_r.len=0; cr.pk_r.ptr=NULL;
		struct other_party_cred ci; memset(&ci,0,sizeof(ci));
		ci.id_cred.len=T1_RFC9529__ID_CRED_I_LEN; ci.id_cred.ptr=(uint8_t*)T1_RFC9529__ID_CRED_I;
		ci.cred.len=T1_RFC9529__CRED_I_LEN; ci.cred.ptr=(uint8_t*)T1_RFC9529__CRED_I;
		ci.g.len=T3_X25519_G_I_LEN; ci.g.ptr=(uint8_t*)T3_X25519_G_I;
		ci.pk.len=0; ci.pk.ptr=NULL; ci.ca.len=0; ci.ca.ptr=NULL; ci.ca_pk.len=0; ci.ca_pk.ptr=NULL;
		struct cred_array ca={.len=1,.ptr=&ci};
		{
			struct p2p_quiet_guard qg;
			p2p_quiet_begin(&qg);
			result = edhoc_responder_run(&cr, &ca, &err_msg, &prk_out,
						     p2p_tx, p2p_rx, ead_process);
			p2p_quiet_end(&qg);
		}
	}
	uint64_t we=p2p_time_ns(), ce=p2p_cpu_ns();
	close(_p2p_fd); _p2p_fd=-1;
	res.wall_us=p2p_us(ws,we); res.cpu_us=p2p_us(cs,ce); res.txrx_us=(double)_p2p_txrx/1000.0;
	res.success=(result==ok)?1:0; return res;
}

/* =============================================================================
 * PQ Type 0 helpers (same labels/derivation as edhoc_benchmark.c)
 * ========================================================================== */
#define P2P_PQ_BUF 8192
static const uint8_t P0_K1[]="EDHOC-PQ-K1", P0_K2[]="EDHOC-PQ-K2", P0_K3[]="EDHOC-PQ-K3";
static const uint8_t P0_IDI[]="EDHOC-PQ-Initiator", P0_IDR[]="EDHOC-PQ-Responder";

static int p2p_pq_dkiv(const uint8_t *prk, const uint8_t *label, size_t ll, uint8_t *key, uint8_t *iv) {
	uint8_t info[64]; memcpy(info,label,ll);
	if(pq_hkdf_expand(prk,info,ll,key,PQ_AEAD_KEY_LEN)!=0) return -1;
	uint8_t iv_i[64]; memcpy(iv_i,label,ll); iv_i[0]^=0xFF;
	if(pq_hkdf_expand(prk,iv_i,ll,iv,PQ_AEAD_NONCE_LEN)!=0) return -1;
	return 0;
}

/* PQ Type 0 — Initiator one iteration (connects to fd) */
static struct p2p_hs_result p2p_pq0_initiator(const char *host, int port,
	const uint8_t *init_lt_pk, const uint8_t *init_lt_sk,
	const uint8_t *resp_lt_pk,
	const uint8_t *init_sig_pk, const uint8_t *init_sig_sk,
	const uint8_t *resp_sig_pk)
{
	struct p2p_hs_result res = {0};
	int fd = p2p_connect(host, port);
	if (fd < 0) return res;
	p2p_nodelay(fd);

	struct pq_party_ctx ctx; memset(&ctx,0,sizeof(ctx));
	memcpy(ctx.lt_pk,init_lt_pk,PQ_KEM_PK_LEN); memcpy(ctx.lt_sk,init_lt_sk,PQ_KEM_SK_LEN);
	memcpy(ctx.other_lt_pk,resp_lt_pk,PQ_KEM_PK_LEN);
	memcpy(ctx.sig_pk,init_sig_pk,PQ_SIG_PK_LEN); memcpy(ctx.sig_sk,init_sig_sk,PQ_SIG_SK_LEN);
	memcpy(ctx.other_sig_pk,resp_sig_pk,PQ_SIG_PK_LEN);

	uint8_t msg1[P2P_PQ_BUF], msg2[P2P_PQ_BUF], msg3[P2P_PQ_BUF];
	uint32_t msg1_len=0, msg2_len=0;
	uint64_t txrx=0;
	int ret;

	uint64_t cs=p2p_cpu_ns(), ws=p2p_time_ns();

	/* Keygen ephemeral */
	ret = pq_kem_keygen(ctx.eph_pk, ctx.eph_sk); if(ret) goto done;
	/* Encaps to resp lt pk */
	uint8_t ct_R[PQ_KEM_CT_LEN], ss_R[PQ_KEM_SS_LEN];
	ret = pq_kem_encaps(ct_R, ss_R, ctx.other_lt_pk); if(ret) goto done;
	ret = pq_hkdf_extract(NULL,0,ss_R,PQ_KEM_SS_LEN,ctx.prk1); if(ret) goto done;
	uint8_t k1[PQ_AEAD_KEY_LEN], iv1[PQ_AEAD_NONCE_LEN];
	ret = p2p_pq_dkiv(ctx.prk1,P0_K1,sizeof(P0_K1)-1,k1,iv1); if(ret) goto done;
	uint8_t pt1[256]; uint32_t pt1l=0;
	pt1[pt1l++]=0x00; pt1[pt1l++]=0x00; pt1[pt1l++]=0x37;
	uint8_t ct1a[256+PQ_AEAD_TAG_LEN]; size_t ct1al=0;
	ret = pq_aead_encrypt(k1,iv1,NULL,0,pt1,pt1l,ct1a,&ct1al); if(ret) goto done;
	/* Build msg1 */
	{uint8_t*p=msg1;uint32_t o=0;
	 memcpy(p+o,ctx.eph_pk,PQ_KEM_PK_LEN);o+=PQ_KEM_PK_LEN;
	 memcpy(p+o,ct_R,PQ_KEM_CT_LEN);o+=PQ_KEM_CT_LEN;
	 p[o++]=(uint8_t)(ct1al>>8);p[o++]=(uint8_t)(ct1al&0xFF);
	 memcpy(p+o,ct1a,ct1al);o+=(uint32_t)ct1al;msg1_len=o;}
	/* Send msg1 */
	{uint64_t t=p2p_time_ns();ret=p2p_send(fd,msg1,msg1_len);txrx+=(p2p_time_ns()-t);if(ret)goto done;}
	/* Recv msg2 */
	{uint64_t t=p2p_time_ns();ret=p2p_recv(fd,msg2,P2P_PQ_BUF,&msg2_len);txrx+=(p2p_time_ns()-t);if(ret)goto done;}
	/* Parse msg2 */
	uint8_t *m2=msg2; uint32_t m2o=0;
	uint8_t ct_e2[PQ_KEM_CT_LEN]; memcpy(ct_e2,m2+m2o,PQ_KEM_CT_LEN);m2o+=PQ_KEM_CT_LEN;
	uint16_t s2l=(m2[m2o]<<8)|m2[m2o+1];m2o+=2;
	uint8_t sig2[PQ_SIG_MAX_LEN]; memcpy(sig2,m2+m2o,s2l);m2o+=s2l;
	uint16_t c2al=(m2[m2o]<<8)|m2[m2o+1];m2o+=2;
	uint8_t ct2a[512+PQ_AEAD_TAG_LEN]; memcpy(ct2a,m2+m2o,c2al);
	/* Decaps ephemeral */
	uint8_t ss_e[PQ_KEM_SS_LEN];
	ret=pq_kem_decaps(ss_e,ct_e2,ctx.eph_sk);if(ret)goto done;
	ret=pq_hkdf_extract(ctx.prk1,PQ_PRK_LEN,ss_e,PQ_KEM_SS_LEN,ctx.prk2);if(ret)goto done;
	uint8_t k2[PQ_AEAD_KEY_LEN],iv2[PQ_AEAD_NONCE_LEN];
	ret=p2p_pq_dkiv(ctx.prk2,P0_K2,sizeof(P0_K2)-1,k2,iv2);if(ret)goto done;
	uint8_t pt2[512];size_t pt2l=0;
	ret=pq_aead_decrypt(k2,iv2,NULL,0,ct2a,c2al,pt2,&pt2l);if(ret)goto done;
	/* TH2 */
	uint8_t th2i[P2P_PQ_BUF]; memcpy(th2i,msg1,msg1_len);memcpy(th2i+msg1_len,ct_e2,PQ_KEM_CT_LEN);
	ret=pq_hash_sha256(th2i,msg1_len+PQ_KEM_CT_LEN,ctx.th2);if(ret)goto done;
	/* MAC2 verify */
	uint8_t mac2i[PQ_HASH_LEN+64]; memcpy(mac2i,ctx.th2,PQ_HASH_LEN);
	memcpy(mac2i+PQ_HASH_LEN,P0_IDR,sizeof(P0_IDR)-1);
	uint8_t mac2e[PQ_AEAD_TAG_LEN];
	ret=pq_hkdf_expand(ctx.prk2,mac2i,PQ_HASH_LEN+sizeof(P0_IDR)-1,mac2e,PQ_AEAD_TAG_LEN);if(ret)goto done;
	ret=pq_sig_verify(mac2e,PQ_AEAD_TAG_LEN,sig2,s2l,ctx.other_sig_pk);if(ret)goto done;
	/* PRK3 */
	ret=pq_hkdf_extract(ctx.prk2,PQ_PRK_LEN,ctx.th2,PQ_HASH_LEN,ctx.prk3);if(ret)goto done;
	/* TH3 */
	uint8_t th3i[P2P_PQ_BUF]; memcpy(th3i,ctx.th2,PQ_HASH_LEN);memcpy(th3i+PQ_HASH_LEN,msg2,msg2_len);
	ret=pq_hash_sha256(th3i,PQ_HASH_LEN+msg2_len,ctx.th3);if(ret)goto done;
	/* MAC3 + sign */
	uint8_t mac3i[PQ_HASH_LEN+64]; memcpy(mac3i,ctx.th3,PQ_HASH_LEN);
	memcpy(mac3i+PQ_HASH_LEN,P0_IDI,sizeof(P0_IDI)-1);
	uint8_t mac3[PQ_AEAD_TAG_LEN];
	ret=pq_hkdf_expand(ctx.prk3,mac3i,PQ_HASH_LEN+sizeof(P0_IDI)-1,mac3,PQ_AEAD_TAG_LEN);if(ret)goto done;
	uint8_t sig3[PQ_SIG_MAX_LEN];size_t sig3l=0;
	ret=pq_sig_sign(mac3,PQ_AEAD_TAG_LEN,ctx.sig_sk,sig3,&sig3l);if(ret)goto done;
	uint8_t k3[PQ_AEAD_KEY_LEN],iv3[PQ_AEAD_NONCE_LEN];
	ret=p2p_pq_dkiv(ctx.prk3,P0_K3,sizeof(P0_K3)-1,k3,iv3);if(ret)goto done;
	uint8_t ct3a[PQ_SIG_MAX_LEN+64+PQ_AEAD_TAG_LEN];size_t ct3al=0;
	ret=pq_aead_encrypt(k3,iv3,NULL,0,sig3,sig3l,ct3a,&ct3al);if(ret)goto done;
	/* Send msg3 */
	{uint64_t t=p2p_time_ns();ret=p2p_send(fd,(uint8_t*)ct3a,(uint32_t)ct3al);txrx+=(p2p_time_ns()-t);if(ret)goto done;}
	/* PRK_out */
	uint8_t th4i[PQ_HASH_LEN+PQ_SIG_MAX_LEN+64+PQ_AEAD_TAG_LEN];
	memcpy(th4i,ctx.th3,PQ_HASH_LEN);memcpy(th4i+PQ_HASH_LEN,ct3a,ct3al);
	ret=pq_hash_sha256(th4i,PQ_HASH_LEN+ct3al,ctx.th4);if(ret)goto done;
	ret=pq_hkdf_expand(ctx.prk3,ctx.th4,PQ_HASH_LEN,ctx.prk_out,PQ_PRK_LEN);if(ret)goto done;
	ctx.success=1;
done:
	{uint64_t we=p2p_time_ns(),ce=p2p_cpu_ns();
	 res.wall_us=p2p_us(ws,we);res.cpu_us=p2p_us(cs,ce);res.txrx_us=(double)txrx/1000.0;
	 res.success=ctx.success;}
	close(fd); return res;
}

/* PQ Type 0 — Responder */
static struct p2p_hs_result p2p_pq0_responder(int listen_fd,
	const uint8_t *resp_lt_pk, const uint8_t *resp_lt_sk, const uint8_t *init_lt_pk,
	const uint8_t *resp_sig_pk, const uint8_t *resp_sig_sk, const uint8_t *init_sig_pk)
{
	struct p2p_hs_result res={0};
	int fd=p2p_accept(listen_fd); if(fd<0)return res;
	p2p_nodelay(fd);
	struct pq_party_ctx ctx; memset(&ctx,0,sizeof(ctx));
	memcpy(ctx.lt_pk,resp_lt_pk,PQ_KEM_PK_LEN);memcpy(ctx.lt_sk,resp_lt_sk,PQ_KEM_SK_LEN);
	memcpy(ctx.other_lt_pk,init_lt_pk,PQ_KEM_PK_LEN);
	memcpy(ctx.sig_pk,resp_sig_pk,PQ_SIG_PK_LEN);memcpy(ctx.sig_sk,resp_sig_sk,PQ_SIG_SK_LEN);
	memcpy(ctx.other_sig_pk,init_sig_pk,PQ_SIG_PK_LEN);
	uint8_t msg1[P2P_PQ_BUF],msg2[P2P_PQ_BUF],msg3[P2P_PQ_BUF];
	uint32_t msg1_len=0,msg2_len=0,msg3_len=0;
	uint64_t txrx=0; int ret;
	uint64_t cs=p2p_cpu_ns(),ws=p2p_time_ns();
	/* Recv msg1 */
	{uint64_t t=p2p_time_ns();ret=p2p_recv(fd,msg1,P2P_PQ_BUF,&msg1_len);txrx+=(p2p_time_ns()-t);if(ret)goto done;}
	uint8_t *m1=msg1;uint32_t m1o=0;
	uint8_t pk_e[PQ_KEM_PK_LEN];memcpy(pk_e,m1+m1o,PQ_KEM_PK_LEN);m1o+=PQ_KEM_PK_LEN;
	uint8_t ct_R[PQ_KEM_CT_LEN];memcpy(ct_R,m1+m1o,PQ_KEM_CT_LEN);m1o+=PQ_KEM_CT_LEN;
	uint16_t c1al=(m1[m1o]<<8)|m1[m1o+1];m1o+=2;
	uint8_t ct1a[256+PQ_AEAD_TAG_LEN];memcpy(ct1a,m1+m1o,c1al);
	uint8_t ss_R[PQ_KEM_SS_LEN];
	ret=pq_kem_decaps(ss_R,ct_R,ctx.lt_sk);if(ret)goto done;
	ret=pq_hkdf_extract(NULL,0,ss_R,PQ_KEM_SS_LEN,ctx.prk1);if(ret)goto done;
	uint8_t k1[PQ_AEAD_KEY_LEN],iv1[PQ_AEAD_NONCE_LEN];
	ret=p2p_pq_dkiv(ctx.prk1,P0_K1,sizeof(P0_K1)-1,k1,iv1);if(ret)goto done;
	uint8_t pt1[256];size_t pt1l=0;
	ret=pq_aead_decrypt(k1,iv1,NULL,0,ct1a,c1al,pt1,&pt1l);if(ret)goto done;
	/* Encaps to pk_eph */
	uint8_t ct_e2[PQ_KEM_CT_LEN],ss_e[PQ_KEM_SS_LEN];
	ret=pq_kem_encaps(ct_e2,ss_e,pk_e);if(ret)goto done;
	ret=pq_hkdf_extract(ctx.prk1,PQ_PRK_LEN,ss_e,PQ_KEM_SS_LEN,ctx.prk2);if(ret)goto done;
	uint8_t k2[PQ_AEAD_KEY_LEN],iv2[PQ_AEAD_NONCE_LEN];
	ret=p2p_pq_dkiv(ctx.prk2,P0_K2,sizeof(P0_K2)-1,k2,iv2);if(ret)goto done;
	/* TH2 */
	uint8_t th2i[P2P_PQ_BUF];memcpy(th2i,msg1,msg1_len);memcpy(th2i+msg1_len,ct_e2,PQ_KEM_CT_LEN);
	ret=pq_hash_sha256(th2i,msg1_len+PQ_KEM_CT_LEN,ctx.th2);if(ret)goto done;
	/* MAC2 + Sign */
	uint8_t mac2i[PQ_HASH_LEN+64];memcpy(mac2i,ctx.th2,PQ_HASH_LEN);
	memcpy(mac2i+PQ_HASH_LEN,P0_IDR,sizeof(P0_IDR)-1);
	uint8_t mac2[PQ_AEAD_TAG_LEN];
	ret=pq_hkdf_expand(ctx.prk2,mac2i,PQ_HASH_LEN+sizeof(P0_IDR)-1,mac2,PQ_AEAD_TAG_LEN);if(ret)goto done;
	uint8_t sig2[PQ_SIG_MAX_LEN];size_t sig2l=0;
	ret=pq_sig_sign(mac2,PQ_AEAD_TAG_LEN,ctx.sig_sk,sig2,&sig2l);if(ret)goto done;
	ret=pq_hkdf_extract(ctx.prk2,PQ_PRK_LEN,ctx.th2,PQ_HASH_LEN,ctx.prk3);if(ret)goto done;
	uint8_t pt2[256];uint32_t pt2l=0;pt2[pt2l++]=0x27;
	memcpy(pt2+pt2l,P0_IDR,sizeof(P0_IDR)-1);pt2l+=sizeof(P0_IDR)-1;
	uint8_t ct2a[512+PQ_AEAD_TAG_LEN];size_t ct2al=0;
	ret=pq_aead_encrypt(k2,iv2,NULL,0,pt2,pt2l,ct2a,&ct2al);if(ret)goto done;
	/* Build msg2 */
	{uint8_t*p=msg2;uint32_t o=0;
	 memcpy(p+o,ct_e2,PQ_KEM_CT_LEN);o+=PQ_KEM_CT_LEN;
	 p[o++]=(uint8_t)(sig2l>>8);p[o++]=(uint8_t)(sig2l&0xFF);
	 memcpy(p+o,sig2,sig2l);o+=(uint32_t)sig2l;
	 p[o++]=(uint8_t)(ct2al>>8);p[o++]=(uint8_t)(ct2al&0xFF);
	 memcpy(p+o,ct2a,ct2al);o+=(uint32_t)ct2al;msg2_len=o;}
	{uint64_t t=p2p_time_ns();ret=p2p_send(fd,msg2,msg2_len);txrx+=(p2p_time_ns()-t);if(ret)goto done;}
	/* Recv msg3 */
	{uint64_t t=p2p_time_ns();ret=p2p_recv(fd,msg3,P2P_PQ_BUF,&msg3_len);txrx+=(p2p_time_ns()-t);if(ret)goto done;}
	uint8_t k3[PQ_AEAD_KEY_LEN],iv3[PQ_AEAD_NONCE_LEN];
	ret=p2p_pq_dkiv(ctx.prk3,P0_K3,sizeof(P0_K3)-1,k3,iv3);if(ret)goto done;
	uint8_t pt3[PQ_SIG_MAX_LEN+64];size_t pt3l=0;
	ret=pq_aead_decrypt(k3,iv3,NULL,0,msg3,msg3_len,pt3,&pt3l);if(ret)goto done;
	/* TH3 */
	uint8_t th3i[P2P_PQ_BUF];memcpy(th3i,ctx.th2,PQ_HASH_LEN);memcpy(th3i+PQ_HASH_LEN,msg2,msg2_len);
	ret=pq_hash_sha256(th3i,PQ_HASH_LEN+msg2_len,ctx.th3);if(ret)goto done;
	uint8_t mac3i[PQ_HASH_LEN+64];memcpy(mac3i,ctx.th3,PQ_HASH_LEN);
	memcpy(mac3i+PQ_HASH_LEN,P0_IDI,sizeof(P0_IDI)-1);
	uint8_t mac3e[PQ_AEAD_TAG_LEN];
	ret=pq_hkdf_expand(ctx.prk3,mac3i,PQ_HASH_LEN+sizeof(P0_IDI)-1,mac3e,PQ_AEAD_TAG_LEN);if(ret)goto done;
	ret=pq_sig_verify(mac3e,PQ_AEAD_TAG_LEN,pt3,pt3l,ctx.other_sig_pk);if(ret)goto done;
	/* PRK_out */
	uint8_t th4i[PQ_HASH_LEN+PQ_SIG_MAX_LEN+64+PQ_AEAD_TAG_LEN];
	memcpy(th4i,ctx.th3,PQ_HASH_LEN);memcpy(th4i+PQ_HASH_LEN,msg3,msg3_len);
	ret=pq_hash_sha256(th4i,PQ_HASH_LEN+msg3_len,ctx.th4);if(ret)goto done;
	ret=pq_hkdf_expand(ctx.prk3,ctx.th4,PQ_HASH_LEN,ctx.prk_out,PQ_PRK_LEN);if(ret)goto done;
	ctx.success=1;
done:
	{uint64_t we=p2p_time_ns(),ce=p2p_cpu_ns();
	 res.wall_us=p2p_us(ws,we);res.cpu_us=p2p_us(cs,ce);res.txrx_us=(double)txrx/1000.0;
	 res.success=ctx.success;}
	close(fd); return res;
}

/* =============================================================================
 * PQ Type 3 (MAC-MAC only)
 * ========================================================================== */
static const uint8_t T3_K1[]="EDHOC-T3PQ-K1",T3_K2[]="EDHOC-T3PQ-K2",T3_K3[]="EDHOC-T3PQ-K3";
static const uint8_t T3_IDI[]="EDHOC-T3PQ-Initiator",T3_IDR[]="EDHOC-T3PQ-Responder";

static struct p2p_hs_result p2p_pq3_initiator(const char *host, int port,
	const uint8_t *i_pk, const uint8_t *i_sk, const uint8_t *r_pk)
{
	struct p2p_hs_result res={0};
	int fd=p2p_connect(host,port); if(fd<0) return res;
	p2p_nodelay(fd);
	struct pq3_party_ctx ctx; memset(&ctx,0,sizeof(ctx));
	memcpy(ctx.lt_pk,i_pk,PQ_KEM_PK_LEN);memcpy(ctx.lt_sk,i_sk,PQ_KEM_SK_LEN);
	memcpy(ctx.other_lt_pk,r_pk,PQ_KEM_PK_LEN);
	uint8_t msg1[P2P_PQ_BUF],msg2[P2P_PQ_BUF];uint32_t msg1_len=0,msg2_len=0;
	uint64_t txrx=0;int ret;
	uint64_t cs=p2p_cpu_ns(),ws=p2p_time_ns();
	ret=pq_kem_keygen(ctx.eph_pk,ctx.eph_sk);if(ret)goto done;
	uint8_t ct_R[PQ_KEM_CT_LEN],ss_R[PQ_KEM_SS_LEN];
	ret=pq_kem_encaps(ct_R,ss_R,ctx.other_lt_pk);if(ret)goto done;
	ret=pq_hkdf_extract(NULL,0,ss_R,PQ_KEM_SS_LEN,ctx.prk1);if(ret)goto done;
	uint8_t k1[PQ_AEAD_KEY_LEN],iv1[PQ_AEAD_NONCE_LEN];
	ret=p2p_pq_dkiv(ctx.prk1,T3_K1,sizeof(T3_K1)-1,k1,iv1);if(ret)goto done;
	uint8_t pt1[256];uint32_t pt1l=0;
	pt1[pt1l++]=0x03;pt1[pt1l++]=0x00;
	memcpy(pt1+pt1l,T3_IDI,sizeof(T3_IDI)-1);pt1l+=sizeof(T3_IDI)-1;
	pt1[pt1l++]=0x37;
	uint8_t ct1a[256+PQ_AEAD_TAG_LEN];size_t ct1al=0;
	ret=pq_aead_encrypt(k1,iv1,NULL,0,pt1,pt1l,ct1a,&ct1al);if(ret)goto done;
	{uint8_t*p=msg1;uint32_t o=0;
	 memcpy(p+o,ctx.eph_pk,PQ_KEM_PK_LEN);o+=PQ_KEM_PK_LEN;
	 memcpy(p+o,ct_R,PQ_KEM_CT_LEN);o+=PQ_KEM_CT_LEN;
	 p[o++]=(uint8_t)(ct1al>>8);p[o++]=(uint8_t)(ct1al&0xFF);
	 memcpy(p+o,ct1a,ct1al);o+=(uint32_t)ct1al;msg1_len=o;}
	{uint64_t t=p2p_time_ns();ret=p2p_send(fd,msg1,msg1_len);txrx+=(p2p_time_ns()-t);if(ret)goto done;}
	{uint64_t t=p2p_time_ns();ret=p2p_recv(fd,msg2,P2P_PQ_BUF,&msg2_len);txrx+=(p2p_time_ns()-t);if(ret)goto done;}
	uint8_t *m2=msg2;uint32_t m2o=0;
	uint8_t ct_e2[PQ_KEM_CT_LEN];memcpy(ct_e2,m2+m2o,PQ_KEM_CT_LEN);m2o+=PQ_KEM_CT_LEN;
	uint8_t ct_I[PQ_KEM_CT_LEN];memcpy(ct_I,m2+m2o,PQ_KEM_CT_LEN);m2o+=PQ_KEM_CT_LEN;
	uint16_t c2al=(m2[m2o]<<8)|m2[m2o+1];m2o+=2;
	uint8_t ct2a[512+PQ_AEAD_TAG_LEN];memcpy(ct2a,m2+m2o,c2al);
	uint8_t ss_e[PQ_KEM_SS_LEN];
	ret=pq_kem_decaps(ss_e,ct_e2,ctx.eph_sk);if(ret)goto done;
	ret=pq_hkdf_extract(ctx.prk1,PQ_PRK_LEN,ss_e,PQ_KEM_SS_LEN,ctx.prk2);if(ret)goto done;
	uint8_t k2[PQ_AEAD_KEY_LEN],iv2[PQ_AEAD_NONCE_LEN];
	ret=p2p_pq_dkiv(ctx.prk2,T3_K2,sizeof(T3_K2)-1,k2,iv2);if(ret)goto done;
	uint8_t pt2[512];size_t pt2l=0;
	ret=pq_aead_decrypt(k2,iv2,NULL,0,ct2a,c2al,pt2,&pt2l);if(ret)goto done;
	uint8_t th2b[P2P_PQ_BUF];memcpy(th2b,msg1,msg1_len);memcpy(th2b+msg1_len,ct_e2,PQ_KEM_CT_LEN);
	ret=pq_hash_sha256(th2b,msg1_len+PQ_KEM_CT_LEN,ctx.th2);if(ret)goto done;
	uint8_t mac2i[PQ_HASH_LEN+64];memcpy(mac2i,ctx.th2,PQ_HASH_LEN);
	memcpy(mac2i+PQ_HASH_LEN,T3_IDR,sizeof(T3_IDR)-1);
	uint8_t mac2e[PQ_AEAD_TAG_LEN];
	ret=pq_hkdf_expand(ctx.prk2,mac2i,PQ_HASH_LEN+sizeof(T3_IDR)-1,mac2e,PQ_AEAD_TAG_LEN);if(ret)goto done;
	if(pt2l<PQ_AEAD_TAG_LEN||memcmp(mac2e,pt2+pt2l-PQ_AEAD_TAG_LEN,PQ_AEAD_TAG_LEN)!=0)goto done;
	uint8_t ss_I[PQ_KEM_SS_LEN];
	ret=pq_kem_decaps(ss_I,ct_I,ctx.lt_sk);if(ret)goto done;
	ret=pq_hkdf_extract(ctx.prk2,PQ_PRK_LEN,ss_I,PQ_KEM_SS_LEN,ctx.prk3);if(ret)goto done;
	uint8_t th3b[P2P_PQ_BUF];memcpy(th3b,ctx.th2,PQ_HASH_LEN);memcpy(th3b+PQ_HASH_LEN,msg2,msg2_len);
	ret=pq_hash_sha256(th3b,PQ_HASH_LEN+msg2_len,ctx.th3);if(ret)goto done;
	uint8_t mac3i[PQ_HASH_LEN+64];memcpy(mac3i,ctx.th3,PQ_HASH_LEN);
	memcpy(mac3i+PQ_HASH_LEN,T3_IDI,sizeof(T3_IDI)-1);
	uint8_t mac3[PQ_AEAD_TAG_LEN];
	ret=pq_hkdf_expand(ctx.prk3,mac3i,PQ_HASH_LEN+sizeof(T3_IDI)-1,mac3,PQ_AEAD_TAG_LEN);if(ret)goto done;
	uint8_t k3[PQ_AEAD_KEY_LEN],iv3[PQ_AEAD_NONCE_LEN];
	ret=p2p_pq_dkiv(ctx.prk3,T3_K3,sizeof(T3_K3)-1,k3,iv3);if(ret)goto done;
	uint8_t ct3a[64+PQ_AEAD_TAG_LEN];size_t ct3al=0;
	ret=pq_aead_encrypt(k3,iv3,NULL,0,mac3,PQ_AEAD_TAG_LEN,ct3a,&ct3al);if(ret)goto done;
	{uint64_t t=p2p_time_ns();ret=p2p_send(fd,(uint8_t*)ct3a,(uint32_t)ct3al);txrx+=(p2p_time_ns()-t);if(ret)goto done;}
	uint8_t th4i[PQ_HASH_LEN+64];memcpy(th4i,ctx.th3,PQ_HASH_LEN);memcpy(th4i+PQ_HASH_LEN,ct3a,ct3al);
	ret=pq_hash_sha256(th4i,PQ_HASH_LEN+ct3al,ctx.th4);if(ret)goto done;
	ret=pq_hkdf_expand(ctx.prk3,ctx.th4,PQ_HASH_LEN,ctx.prk_out,PQ_PRK_LEN);if(ret)goto done;
	ctx.success=1;
done:
	{uint64_t we=p2p_time_ns(),ce=p2p_cpu_ns();
	 res.wall_us=p2p_us(ws,we);res.cpu_us=p2p_us(cs,ce);res.txrx_us=(double)txrx/1000.0;
	 res.success=ctx.success;}
	close(fd); return res;
}

static struct p2p_hs_result p2p_pq3_responder(int lfd,
	const uint8_t *r_pk, const uint8_t *r_sk, const uint8_t *i_pk)
{
	struct p2p_hs_result res={0};
	int fd=p2p_accept(lfd);if(fd<0)return res;
	p2p_nodelay(fd);
	struct pq3_party_ctx ctx;memset(&ctx,0,sizeof(ctx));
	memcpy(ctx.lt_pk,r_pk,PQ_KEM_PK_LEN);memcpy(ctx.lt_sk,r_sk,PQ_KEM_SK_LEN);
	memcpy(ctx.other_lt_pk,i_pk,PQ_KEM_PK_LEN);
	uint8_t msg1[P2P_PQ_BUF],msg2[P2P_PQ_BUF],msg3[P2P_PQ_BUF];
	uint32_t msg1_len=0,msg2_len=0,msg3_len=0;
	uint64_t txrx=0;int ret;
	uint64_t cs=p2p_cpu_ns(),ws=p2p_time_ns();
	{uint64_t t=p2p_time_ns();ret=p2p_recv(fd,msg1,P2P_PQ_BUF,&msg1_len);txrx+=(p2p_time_ns()-t);if(ret)goto done;}
	uint8_t *m1=msg1;uint32_t m1o=0;
	uint8_t pk_e[PQ_KEM_PK_LEN];memcpy(pk_e,m1+m1o,PQ_KEM_PK_LEN);m1o+=PQ_KEM_PK_LEN;
	uint8_t ct_R[PQ_KEM_CT_LEN];memcpy(ct_R,m1+m1o,PQ_KEM_CT_LEN);m1o+=PQ_KEM_CT_LEN;
	uint16_t c1al=(m1[m1o]<<8)|m1[m1o+1];m1o+=2;
	uint8_t ct1a[256+PQ_AEAD_TAG_LEN];memcpy(ct1a,m1+m1o,c1al);
	uint8_t ss_R[PQ_KEM_SS_LEN];
	ret=pq_kem_decaps(ss_R,ct_R,ctx.lt_sk);if(ret)goto done;
	ret=pq_hkdf_extract(NULL,0,ss_R,PQ_KEM_SS_LEN,ctx.prk1);if(ret)goto done;
	uint8_t k1[PQ_AEAD_KEY_LEN],iv1[PQ_AEAD_NONCE_LEN];
	ret=p2p_pq_dkiv(ctx.prk1,T3_K1,sizeof(T3_K1)-1,k1,iv1);if(ret)goto done;
	uint8_t pt1[256];size_t pt1l=0;
	ret=pq_aead_decrypt(k1,iv1,NULL,0,ct1a,c1al,pt1,&pt1l);if(ret)goto done;
	uint8_t ct_e2[PQ_KEM_CT_LEN],ss_e[PQ_KEM_SS_LEN];
	ret=pq_kem_encaps(ct_e2,ss_e,pk_e);if(ret)goto done;
	ret=pq_hkdf_extract(ctx.prk1,PQ_PRK_LEN,ss_e,PQ_KEM_SS_LEN,ctx.prk2);if(ret)goto done;
	uint8_t k2[PQ_AEAD_KEY_LEN],iv2[PQ_AEAD_NONCE_LEN];
	ret=p2p_pq_dkiv(ctx.prk2,T3_K2,sizeof(T3_K2)-1,k2,iv2);if(ret)goto done;
	uint8_t th2b[P2P_PQ_BUF];memcpy(th2b,msg1,msg1_len);memcpy(th2b+msg1_len,ct_e2,PQ_KEM_CT_LEN);
	ret=pq_hash_sha256(th2b,msg1_len+PQ_KEM_CT_LEN,ctx.th2);if(ret)goto done;
	uint8_t mac2i[PQ_HASH_LEN+64];memcpy(mac2i,ctx.th2,PQ_HASH_LEN);
	memcpy(mac2i+PQ_HASH_LEN,T3_IDR,sizeof(T3_IDR)-1);
	uint8_t mac2[PQ_AEAD_TAG_LEN];
	ret=pq_hkdf_expand(ctx.prk2,mac2i,PQ_HASH_LEN+sizeof(T3_IDR)-1,mac2,PQ_AEAD_TAG_LEN);if(ret)goto done;
	uint8_t ct_I[PQ_KEM_CT_LEN],ss_I[PQ_KEM_SS_LEN];
	ret=pq_kem_encaps(ct_I,ss_I,ctx.other_lt_pk);if(ret)goto done;
	ret=pq_hkdf_extract(ctx.prk2,PQ_PRK_LEN,ss_I,PQ_KEM_SS_LEN,ctx.prk3);if(ret)goto done;
	uint8_t pt2[256];uint32_t pt2l=0;pt2[pt2l++]=0x27;
	memcpy(pt2+pt2l,T3_IDR,sizeof(T3_IDR)-1);pt2l+=sizeof(T3_IDR)-1;
	memcpy(pt2+pt2l,mac2,PQ_AEAD_TAG_LEN);pt2l+=PQ_AEAD_TAG_LEN;
	uint8_t ct2a[512+PQ_AEAD_TAG_LEN];size_t ct2al=0;
	ret=pq_aead_encrypt(k2,iv2,NULL,0,pt2,pt2l,ct2a,&ct2al);if(ret)goto done;
	{uint8_t*p=msg2;uint32_t o=0;
	 memcpy(p+o,ct_e2,PQ_KEM_CT_LEN);o+=PQ_KEM_CT_LEN;
	 memcpy(p+o,ct_I,PQ_KEM_CT_LEN);o+=PQ_KEM_CT_LEN;
	 p[o++]=(uint8_t)(ct2al>>8);p[o++]=(uint8_t)(ct2al&0xFF);
	 memcpy(p+o,ct2a,ct2al);o+=(uint32_t)ct2al;msg2_len=o;}
	{uint64_t t=p2p_time_ns();ret=p2p_send(fd,msg2,msg2_len);txrx+=(p2p_time_ns()-t);if(ret)goto done;}
	{uint64_t t=p2p_time_ns();ret=p2p_recv(fd,msg3,P2P_PQ_BUF,&msg3_len);txrx+=(p2p_time_ns()-t);if(ret)goto done;}
	uint8_t k3[PQ_AEAD_KEY_LEN],iv3[PQ_AEAD_NONCE_LEN];
	ret=p2p_pq_dkiv(ctx.prk3,T3_K3,sizeof(T3_K3)-1,k3,iv3);if(ret)goto done;
	uint8_t pt3[64];size_t pt3l=0;
	ret=pq_aead_decrypt(k3,iv3,NULL,0,msg3,msg3_len,pt3,&pt3l);if(ret)goto done;
	uint8_t th3b[P2P_PQ_BUF];memcpy(th3b,ctx.th2,PQ_HASH_LEN);memcpy(th3b+PQ_HASH_LEN,msg2,msg2_len);
	ret=pq_hash_sha256(th3b,PQ_HASH_LEN+msg2_len,ctx.th3);if(ret)goto done;
	uint8_t mac3i[PQ_HASH_LEN+64];memcpy(mac3i,ctx.th3,PQ_HASH_LEN);
	memcpy(mac3i+PQ_HASH_LEN,T3_IDI,sizeof(T3_IDI)-1);
	uint8_t mac3e[PQ_AEAD_TAG_LEN];
	ret=pq_hkdf_expand(ctx.prk3,mac3i,PQ_HASH_LEN+sizeof(T3_IDI)-1,mac3e,PQ_AEAD_TAG_LEN);if(ret)goto done;
	if(pt3l!=PQ_AEAD_TAG_LEN||memcmp(mac3e,pt3,PQ_AEAD_TAG_LEN)!=0)goto done;
	uint8_t th4i[PQ_HASH_LEN+64];memcpy(th4i,ctx.th3,PQ_HASH_LEN);memcpy(th4i+PQ_HASH_LEN,msg3,msg3_len);
	ret=pq_hash_sha256(th4i,PQ_HASH_LEN+msg3_len,ctx.th4);if(ret)goto done;
	ret=pq_hkdf_expand(ctx.prk3,ctx.th4,PQ_HASH_LEN,ctx.prk_out,PQ_PRK_LEN);if(ret)goto done;
	ctx.success=1;
done:
	{uint64_t we=p2p_time_ns(),ce=p2p_cpu_ns();
	 res.wall_us=p2p_us(ws,we);res.cpu_us=p2p_us(cs,ce);res.txrx_us=(double)txrx/1000.0;
	 res.success=ctx.success;}
	close(fd); return res;
}

/* =============================================================================
 * Hybrid Type 3 (X25519 + ML-KEM-768)
 * ========================================================================== */
static const uint8_t HB_EK2[]="EDHOC-HYB-EK2",HB_EK3[]="EDHOC-HYB-EK3";
static const uint8_t HB_IDI[]="EDHOC-HYB-Initiator",HB_IDR[]="EDHOC-HYB-Responder";

/* Hybrid helpers (same as edhoc_benchmark.c) */
static int hb_extract(const uint8_t *s,size_t sl,const uint8_t *i,size_t il,uint8_t *o){
	struct byte_array sa={.len=(uint32_t)sl,.ptr=(uint8_t*)s},ia={.len=(uint32_t)il,.ptr=(uint8_t*)i};
	if(!s||sl==0){sa.ptr=NULL;sa.len=0;} return (hkdf_extract(SHA_256,&sa,&ia,o)==ok)?0:-1;
}
static int hb_expand(const uint8_t *p,const uint8_t *i,size_t il,uint8_t *o,size_t ol){
	struct byte_array pa={.len=32,.ptr=(uint8_t*)p},ia={.len=(uint32_t)il,.ptr=(uint8_t*)i};
	struct byte_array oa={.len=(uint32_t)ol,.ptr=o}; return (hkdf_expand(SHA_256,&pa,&ia,&oa)==ok)?0:-1;
}
static int hb_hash(const uint8_t *d,size_t l,uint8_t *o){
	struct byte_array da={.len=(uint32_t)l,.ptr=(uint8_t*)d},oa={.len=32,.ptr=o};
	return (hash(SHA_256,&da,&oa)==ok)?0:-1;
}
static int hb_ecdh(const uint8_t *sk,const uint8_t *pk,uint8_t *o){
	struct byte_array s={.len=32,.ptr=(uint8_t*)sk},p={.len=32,.ptr=(uint8_t*)pk};
	return (shared_secret_derive(X25519,&s,&p,o)==ok)?0:-1;
}
static int hb_aead_enc(const uint8_t *k,const uint8_t *n,const uint8_t *a,size_t al,
	const uint8_t *p,size_t pl,uint8_t *c,size_t *cl){
	uint8_t t[PQ_AEAD_TAG_LEN];
	struct byte_array pa={.len=(uint32_t)pl,.ptr=(uint8_t*)p},ka={.len=PQ_AEAD_KEY_LEN,.ptr=(uint8_t*)k};
	struct byte_array na={.len=PQ_AEAD_NONCE_LEN,.ptr=(uint8_t*)n},aa={.len=(uint32_t)al,.ptr=(uint8_t*)a};
	struct byte_array ca={.len=(uint32_t)pl,.ptr=c},ta={.len=PQ_AEAD_TAG_LEN,.ptr=t};
	if(aead(ENCRYPT,&pa,&ka,&na,&aa,&ca,&ta)!=ok)return -1;
	memcpy(c+pl,t,PQ_AEAD_TAG_LEN);*cl=pl+PQ_AEAD_TAG_LEN;return 0;
}
static int hb_aead_dec(const uint8_t *k,const uint8_t *n,const uint8_t *a,size_t al,
	const uint8_t *c,size_t cl,uint8_t *p,size_t *pl){
	if(cl<PQ_AEAD_TAG_LEN)return -1;size_t ppl=cl-PQ_AEAD_TAG_LEN;
	struct byte_array ca={.len=(uint32_t)cl,.ptr=(uint8_t*)c},ka={.len=PQ_AEAD_KEY_LEN,.ptr=(uint8_t*)k};
	struct byte_array na={.len=PQ_AEAD_NONCE_LEN,.ptr=(uint8_t*)n},aa={.len=(uint32_t)al,.ptr=(uint8_t*)a};
	struct byte_array pa={.len=(uint32_t)ppl,.ptr=p},ta={.len=PQ_AEAD_TAG_LEN,.ptr=(uint8_t*)(c+ppl)};
	if(aead(DECRYPT,&ca,&ka,&na,&aa,&pa,&ta)!=ok)return -1;*pl=ppl;return 0;
}
static int hb_dkiv(const uint8_t *prk,const uint8_t *label,size_t ll,const uint8_t *th,size_t tl,uint8_t *k,uint8_t *iv){
	uint8_t info[128];memcpy(info,label,ll);memcpy(info+ll,th,tl);
	if(hb_expand(prk,info,ll+tl,k,PQ_AEAD_KEY_LEN)!=0)return -1;
	info[0]^=0xFF;
	if(hb_expand(prk,info,ll+tl,iv,PQ_AEAD_NONCE_LEN)!=0)return -1;
	return 0;
}

#define P2P_HYB_BUF 8192

static struct p2p_hs_result p2p_hyb_initiator(const char *host, int port,
	const uint8_t *i_ssk, const uint8_t *i_spk, const uint8_t *r_spk,
	const uint8_t *i_esk, const uint8_t *i_epk,
	const uint8_t *i_kpk, const uint8_t *i_ksk)
{
	struct p2p_hs_result res={0};
	int fd=p2p_connect(host,port);if(fd<0)return res;
	p2p_nodelay(fd);
	struct hybrid_party_ctx ctx;memset(&ctx,0,sizeof(ctx));
	memcpy(ctx.static_sk,i_ssk,32);memcpy(ctx.static_pk,i_spk,32);
	memcpy(ctx.other_static_pk,r_spk,32);
	memcpy(ctx.eph_sk,i_esk,32);memcpy(ctx.eph_pk,i_epk,32);
	memcpy(ctx.kem_pk,i_kpk,PQ_KEM_PK_LEN);memcpy(ctx.kem_sk,i_ksk,PQ_KEM_SK_LEN);
	uint8_t m1b[P2P_HYB_BUF],m2b[P2P_HYB_BUF];uint32_t m1l=0,m2l=0;
	uint64_t txrx=0;int ret;
	uint64_t cs=p2p_cpu_ns(),ws=p2p_time_ns();
	/* Build M1 */
	uint8_t m1[P2P_HYB_BUF];uint32_t m1_len=0;
	m1[m1_len++]=0x03;m1[m1_len++]=0xFE;m1[m1_len++]=0x37;
	memcpy(m1+m1_len,ctx.eph_pk,32);m1_len+=32;
	memcpy(m1+m1_len,ctx.kem_pk,PQ_KEM_PK_LEN);m1_len+=PQ_KEM_PK_LEN;
	memcpy(m1b,m1,m1_len);m1l=m1_len;
	{uint64_t t=p2p_time_ns();ret=p2p_send(fd,m1b,m1l);txrx+=(p2p_time_ns()-t);if(ret)goto done;}
	{uint64_t t=p2p_time_ns();ret=p2p_recv(fd,m2b,P2P_HYB_BUF,&m2l);txrx+=(p2p_time_ns()-t);if(ret)goto done;}
	uint8_t *m2=m2b;uint32_t off=0;
	uint8_t peer_eph[32];memcpy(peer_eph,m2+off,32);off+=32;
	uint8_t c_kem[PQ_KEM_CT_LEN];memcpy(c_kem,m2+off,PQ_KEM_CT_LEN);off+=PQ_KEM_CT_LEN;
	uint16_t ct2l=(m2[off]<<8)|m2[off+1];off+=2;
	uint8_t ct2a[512+PQ_AEAD_TAG_LEN];memcpy(ct2a,m2+off,ct2l);
	uint8_t k_kem[PQ_KEM_SS_LEN];
	ret=pq_kem_decaps(k_kem,c_kem,ctx.kem_sk);if(ret)goto done;
	uint8_t ss_eph[32];ret=hb_ecdh(ctx.eph_sk,peer_eph,ss_eph);if(ret)goto done;
	{uint8_t th2i[P2P_HYB_BUF];uint32_t tl=0;
	 memcpy(th2i,m1,m1_len);tl+=m1_len;memcpy(th2i+tl,peer_eph,32);tl+=32;
	 memcpy(th2i+tl,c_kem,PQ_KEM_CT_LEN);tl+=PQ_KEM_CT_LEN;
	 ret=hb_hash(th2i,tl,ctx.th2);if(ret)goto done;}
	{uint8_t ikm[PQ_KEM_SS_LEN+32];memcpy(ikm,k_kem,PQ_KEM_SS_LEN);memcpy(ikm+PQ_KEM_SS_LEN,ctx.th2,32);
	 ret=hb_extract(ss_eph,32,ikm,PQ_KEM_SS_LEN+32,ctx.prk2e);if(ret)goto done;}
	uint8_t ss_bx[32];ret=hb_ecdh(ctx.eph_sk,ctx.other_static_pk,ss_bx);if(ret)goto done;
	uint8_t ek2[PQ_AEAD_KEY_LEN],iv2[PQ_AEAD_NONCE_LEN];
	{uint8_t ec[64];memcpy(ec,ss_bx,32);memcpy(ec+32,ctx.th2,32);
	 ret=hb_dkiv(ctx.prk2e,HB_EK2,sizeof(HB_EK2)-1,ec,64,ek2,iv2);if(ret)goto done;}
	uint8_t pt2[512];size_t pt2l=0;
	ret=hb_aead_dec(ek2,iv2,NULL,0,ct2a,ct2l,pt2,&pt2l);if(ret)goto done;
	ret=hb_extract(ss_bx,32,ctx.prk2e,32,ctx.prk3e2m);if(ret)goto done;
	uint8_t mk2[PQ_AEAD_TAG_LEN];
	{uint8_t mi[32+64];memcpy(mi,ctx.th2,32);memcpy(mi+32,HB_IDR,sizeof(HB_IDR)-1);
	 ret=hb_expand(ctx.prk3e2m,mi,32+sizeof(HB_IDR)-1,mk2,PQ_AEAD_TAG_LEN);if(ret)goto done;}
	if(pt2l<PQ_AEAD_TAG_LEN||memcmp(mk2,pt2+pt2l-PQ_AEAD_TAG_LEN,PQ_AEAD_TAG_LEN)!=0)goto done;
	{uint8_t th3i[P2P_HYB_BUF];uint32_t len=0;
	 memcpy(th3i,ctx.th2,32);len+=32;memcpy(th3i+len,m2b,m2l);len+=m2l;
	 memcpy(th3i+len,ctx.other_static_pk,32);len+=32;
	 ret=hb_hash(th3i,len,ctx.th3);if(ret)goto done;}
	uint8_t ek3[PQ_AEAD_KEY_LEN],iv3[PQ_AEAD_NONCE_LEN];
	ret=hb_dkiv(ctx.prk3e2m,HB_EK3,sizeof(HB_EK3)-1,ctx.th3,32,ek3,iv3);if(ret)goto done;
	uint8_t ss_ya[32];ret=hb_ecdh(ctx.static_sk,peer_eph,ss_ya);if(ret)goto done;
	ret=hb_extract(ss_ya,32,ctx.prk3e2m,32,ctx.prk4e3m);if(ret)goto done;
	uint8_t mac3[PQ_AEAD_TAG_LEN];
	{uint8_t mi[32+64];memcpy(mi,ctx.th3,32);memcpy(mi+32,HB_IDI,sizeof(HB_IDI)-1);
	 ret=hb_expand(ctx.prk4e3m,mi,32+sizeof(HB_IDI)-1,mac3,PQ_AEAD_TAG_LEN);if(ret)goto done;}
	uint8_t pt3[128];uint32_t pt3l=0;
	memcpy(pt3+pt3l,HB_IDI,sizeof(HB_IDI)-1);pt3l+=sizeof(HB_IDI)-1;
	memcpy(pt3+pt3l,mac3,PQ_AEAD_TAG_LEN);pt3l+=PQ_AEAD_TAG_LEN;
	uint8_t ct3a[128+PQ_AEAD_TAG_LEN];size_t ct3l=0;
	ret=hb_aead_enc(ek3,iv3,NULL,0,pt3,pt3l,ct3a,&ct3l);if(ret)goto done;
	{uint8_t th4i[256];uint32_t len=0;memcpy(th4i,ctx.th3,32);len+=32;
	 memcpy(th4i+len,ct3a,ct3l);len+=(uint32_t)ct3l;memcpy(th4i+len,ctx.static_pk,32);len+=32;
	 ret=hb_hash(th4i,len,ctx.th4);if(ret)goto done;}
	ret=hb_expand(ctx.prk4e3m,ctx.th4,32,ctx.prk_out,32);if(ret)goto done;
	{uint64_t t=p2p_time_ns();ret=p2p_send(fd,(uint8_t*)ct3a,(uint32_t)ct3l);txrx+=(p2p_time_ns()-t);if(ret)goto done;}
	ctx.success=1;
done:
	{uint64_t we=p2p_time_ns(),ce=p2p_cpu_ns();
	 res.wall_us=p2p_us(ws,we);res.cpu_us=p2p_us(cs,ce);res.txrx_us=(double)txrx/1000.0;
	 res.success=ctx.success;}
	close(fd);return res;
}

static struct p2p_hs_result p2p_hyb_responder(int lfd,
	const uint8_t *r_ssk, const uint8_t *r_spk, const uint8_t *i_spk,
	const uint8_t *r_esk, const uint8_t *r_epk)
{
	struct p2p_hs_result res={0};
	int fd=p2p_accept(lfd);if(fd<0)return res;
	p2p_nodelay(fd);
	struct hybrid_party_ctx ctx;memset(&ctx,0,sizeof(ctx));
	memcpy(ctx.static_sk,r_ssk,32);memcpy(ctx.static_pk,r_spk,32);
	memcpy(ctx.other_static_pk,i_spk,32);
	memcpy(ctx.eph_sk,r_esk,32);memcpy(ctx.eph_pk,r_epk,32);
	uint8_t m1b[P2P_HYB_BUF],m2b[P2P_HYB_BUF],m3b[P2P_HYB_BUF];
	uint32_t m1l=0,m2l=0,m3l=0;
	uint64_t txrx=0;int ret;
	uint64_t cs=p2p_cpu_ns(),ws=p2p_time_ns();
	{uint64_t t=p2p_time_ns();ret=p2p_recv(fd,m1b,P2P_HYB_BUF,&m1l);txrx+=(p2p_time_ns()-t);if(ret)goto done;}
	uint32_t off=3;uint8_t peer_eph[32];memcpy(peer_eph,m1b+off,32);off+=32;
	uint8_t pk_kem[PQ_KEM_PK_LEN];memcpy(pk_kem,m1b+off,PQ_KEM_PK_LEN);
	uint8_t k_kem[PQ_KEM_SS_LEN],c_kem[PQ_KEM_CT_LEN];
	ret=pq_kem_encaps(c_kem,k_kem,pk_kem);if(ret)goto done;
	uint8_t ss_eph[32];ret=hb_ecdh(ctx.eph_sk,peer_eph,ss_eph);if(ret)goto done;
	{uint8_t th2i[P2P_HYB_BUF];uint32_t tl=0;
	 memcpy(th2i,m1b,m1l);tl+=m1l;memcpy(th2i+tl,ctx.eph_pk,32);tl+=32;
	 memcpy(th2i+tl,c_kem,PQ_KEM_CT_LEN);tl+=PQ_KEM_CT_LEN;
	 ret=hb_hash(th2i,tl,ctx.th2);if(ret)goto done;}
	{uint8_t ikm[PQ_KEM_SS_LEN+32];memcpy(ikm,k_kem,PQ_KEM_SS_LEN);memcpy(ikm+PQ_KEM_SS_LEN,ctx.th2,32);
	 ret=hb_extract(ss_eph,32,ikm,PQ_KEM_SS_LEN+32,ctx.prk2e);if(ret)goto done;}
	uint8_t ss_xb[32];ret=hb_ecdh(ctx.static_sk,peer_eph,ss_xb);if(ret)goto done;
	uint8_t ek2[PQ_AEAD_KEY_LEN],iv2[PQ_AEAD_NONCE_LEN];
	{uint8_t ec[64];memcpy(ec,ss_xb,32);memcpy(ec+32,ctx.th2,32);
	 ret=hb_dkiv(ctx.prk2e,HB_EK2,sizeof(HB_EK2)-1,ec,64,ek2,iv2);if(ret)goto done;}
	ret=hb_extract(ss_xb,32,ctx.prk2e,32,ctx.prk3e2m);if(ret)goto done;
	uint8_t mac2[PQ_AEAD_TAG_LEN];
	{uint8_t mi[32+64];memcpy(mi,ctx.th2,32);memcpy(mi+32,HB_IDR,sizeof(HB_IDR)-1);
	 ret=hb_expand(ctx.prk3e2m,mi,32+sizeof(HB_IDR)-1,mac2,PQ_AEAD_TAG_LEN);if(ret)goto done;}
	uint8_t pt2[256];uint32_t pt2l=0;pt2[pt2l++]=0x27;
	memcpy(pt2+pt2l,HB_IDR,sizeof(HB_IDR)-1);pt2l+=sizeof(HB_IDR)-1;
	memcpy(pt2+pt2l,mac2,PQ_AEAD_TAG_LEN);pt2l+=PQ_AEAD_TAG_LEN;
	uint8_t ct2a[512+PQ_AEAD_TAG_LEN];size_t ct2al=0;
	ret=hb_aead_enc(ek2,iv2,NULL,0,pt2,pt2l,ct2a,&ct2al);if(ret)goto done;
	{uint8_t*p=m2b;uint32_t o=0;
	 memcpy(p+o,ctx.eph_pk,32);o+=32;memcpy(p+o,c_kem,PQ_KEM_CT_LEN);o+=PQ_KEM_CT_LEN;
	 p[o++]=(uint8_t)(ct2al>>8);p[o++]=(uint8_t)(ct2al&0xFF);
	 memcpy(p+o,ct2a,ct2al);o+=(uint32_t)ct2al;m2l=o;}
	{uint64_t t=p2p_time_ns();ret=p2p_send(fd,m2b,m2l);txrx+=(p2p_time_ns()-t);if(ret)goto done;}
	{uint64_t t=p2p_time_ns();ret=p2p_recv(fd,m3b,P2P_HYB_BUF,&m3l);txrx+=(p2p_time_ns()-t);if(ret)goto done;}
	{uint8_t th3i[P2P_HYB_BUF];uint32_t len=0;
	 memcpy(th3i,ctx.th2,32);len+=32;memcpy(th3i+len,m2b,m2l);len+=m2l;
	 memcpy(th3i+len,ctx.static_pk,32);len+=32;
	 ret=hb_hash(th3i,len,ctx.th3);if(ret)goto done;}
	uint8_t ek3[PQ_AEAD_KEY_LEN],iv3[PQ_AEAD_NONCE_LEN];
	ret=hb_dkiv(ctx.prk3e2m,HB_EK3,sizeof(HB_EK3)-1,ctx.th3,32,ek3,iv3);if(ret)goto done;
	uint8_t pt3[128];size_t pt3l=0;
	ret=hb_aead_dec(ek3,iv3,NULL,0,m3b,m3l,pt3,&pt3l);if(ret)goto done;
	uint8_t ss_ay[32];ret=hb_ecdh(ctx.eph_sk,ctx.other_static_pk,ss_ay);if(ret)goto done;
	ret=hb_extract(ss_ay,32,ctx.prk3e2m,32,ctx.prk4e3m);if(ret)goto done;
	uint8_t mac3e[PQ_AEAD_TAG_LEN];
	{uint8_t mi[32+64];memcpy(mi,ctx.th3,32);memcpy(mi+32,HB_IDI,sizeof(HB_IDI)-1);
	 ret=hb_expand(ctx.prk4e3m,mi,32+sizeof(HB_IDI)-1,mac3e,PQ_AEAD_TAG_LEN);if(ret)goto done;}
	if(pt3l<PQ_AEAD_TAG_LEN||memcmp(mac3e,pt3+pt3l-PQ_AEAD_TAG_LEN,PQ_AEAD_TAG_LEN)!=0)goto done;
	{uint8_t th4i[256];uint32_t len=0;memcpy(th4i,ctx.th3,32);len+=32;
	 memcpy(th4i+len,m3b,m3l);len+=m3l;memcpy(th4i+len,ctx.other_static_pk,32);len+=32;
	 ret=hb_hash(th4i,len,ctx.th4);if(ret)goto done;}
	ret=hb_expand(ctx.prk4e3m,ctx.th4,32,ctx.prk_out,32);if(ret)goto done;
	ctx.success=1;
done:
	{uint64_t we=p2p_time_ns(),ce=p2p_cpu_ns();
	 res.wall_us=p2p_us(ws,we);res.cpu_us=p2p_us(cs,ce);res.txrx_us=(double)txrx/1000.0;
	 res.success=ctx.success;}
	close(fd);return res;
}

/* =============================================================================
 * Precomputation: keygen cost per variant (measured once, reused)
 * ========================================================================== */
struct p2p_precomp {
	double classic_keygen_us;   /* X25519 DH keygen */
	double pq_keygen_us;        /* ML-KEM-768 keygen */
};

static struct p2p_precomp p2p_measure_precomp(void)
{
	struct p2p_precomp pc = {0};
	const int WARM = 50, N = 200;

	/* X25519 keygen */
	for (int i = 0; i < WARM; i++) {
		uint8_t sk[32], pk[32];
		struct byte_array ska = {.len=32,.ptr=sk}, pka = {.len=32,.ptr=pk};
		ephemeral_dh_key_gen(X25519, 9000+i, &ska, &pka);
	}
	{
		uint64_t t0 = p2p_cpu_ns();
		for (int i = 0; i < N; i++) {
			uint8_t sk[32], pk[32];
			struct byte_array ska = {.len=32,.ptr=sk}, pka = {.len=32,.ptr=pk};
			ephemeral_dh_key_gen(X25519, 9500+i, &ska, &pka);
		}
		pc.classic_keygen_us = p2p_us(t0, p2p_cpu_ns()) / (double)N;
	}

	/* ML-KEM-768 keygen */
	for (int i = 0; i < WARM; i++) {
		uint8_t pk[PQ_KEM_PK_LEN], sk[PQ_KEM_SK_LEN];
		pq_kem_keygen(pk, sk);
	}
	{
		uint64_t t0 = p2p_cpu_ns();
		for (int i = 0; i < N; i++) {
			uint8_t pk[PQ_KEM_PK_LEN], sk[PQ_KEM_SK_LEN];
			pq_kem_keygen(pk, sk);
		}
		pc.pq_keygen_us = p2p_us(t0, p2p_cpu_ns()) / (double)N;
	}

	return pc;
}

/*
 * Return precomputation cost (µs) for a given variant index:
 *   0,1 = Classic (1x X25519 keygen)
 *   2,3 = PQ      (1x ML-KEM-768 keygen)
 *   4   = Hybrid  (1x X25519 + 1x ML-KEM-768 keygen)
 */
static double p2p_precomp_for_variant(int v, const struct p2p_precomp *pc)
{
	switch (v) {
	case 0: case 1: return pc->classic_keygen_us;
	case 2: case 3: return pc->pq_keygen_us;
	case 4:         return pc->classic_keygen_us + pc->pq_keygen_us;
	default:        return 0;
	}
}

/* =============================================================================
 * Memory estimators (same methodology as socket benchmark)
 * ========================================================================== */
static long p2p_estimate_classic_memory(int type_num, int is_initiator)
{
	long shared = 1536 + 640 + 256 + 128 + 256 + 384 + 512 + 256;
	if (is_initiator) {
		long ctx = 228;
		long keys = (type_num == 0) ? 512 : 0;
		return shared + ctx + keys;
	}
	/* responder */
	{
		long ctx = 240;
		long keys = (type_num == 0) ? 512 : 0;
		long server = 64;
		return shared + ctx + keys + server;
	}
}

static long p2p_estimate_pq_memory(int pq_type_num, int is_initiator)
{
	long ctx_base = PQ_KEM_PK_LEN*3 + PQ_KEM_SK_LEN*2 +
			PQ_PRK_LEN*4 + PQ_HASH_LEN*3 + PQ_PRK_LEN + 16;
	if (pq_type_num == 0)
		ctx_base += 2*PQ_SIG_PK_LEN + 2*PQ_SIG_SK_LEN;

	long thread_data = 3 * 8192 + 64;
	long peak_common;

	if (pq_type_num == 0) {
		peak_common = 87 + 1088 + 32 + 256 + 264 + 3309 +
			      512 + 520 + 8192 + 104 + 3413;
	} else {
		peak_common = 87 + 1088 + 32 + 256 + 264 +
			      512 + 520 + 8192 + 104 + 96;
	}

	if (is_initiator) {
		long extra = 1088;
		if (pq_type_num == 3)
			extra += 1088;
		return ctx_base + thread_data + peak_common + extra;
	}

	/* responder */
	{
		long extra = PQ_KEM_PK_LEN;
		if (pq_type_num == 3)
			extra += 1088 + 32;
		long server = 64;
		return ctx_base + thread_data + peak_common + extra + server;
	}
}

static long p2p_estimate_hybrid_memory(int is_initiator)
{
	long ctx_size = 5*32 + PQ_KEM_PK_LEN + PQ_KEM_SK_LEN + 4*32 + 32 + 16;
	long thread_data = 3 * 8192 + 64;
	long peak_common = 32 + 32 + 1088 + 32 + 8192 + 64 +
			   32 + 29 + 64 + 104 + 256 + 520 +
			   128 + 136 + 256;

	if (is_initiator)
		return ctx_size + thread_data + peak_common;

	/* responder */
	{
		long pk_kem_received = PQ_KEM_PK_LEN;
		long server = 64;
		return ctx_size + thread_data + peak_common + pk_kem_received + server;
	}
}

static long p2p_estimate_memory_by_variant(int v, int is_initiator)
{
	switch (v) {
	case 0: return p2p_estimate_classic_memory(0, is_initiator);
	case 1: return p2p_estimate_classic_memory(3, is_initiator);
	case 2: return p2p_estimate_pq_memory(0, is_initiator);
	case 3: return p2p_estimate_pq_memory(3, is_initiator);
	case 4: return p2p_estimate_hybrid_memory(is_initiator);
	default: return 0;
	}
}

/* =============================================================================
 * Crypto primitive benchmarking (same operations as socket benchmark)
 * ========================================================================== */
struct p2p_op_result {
	double avg_us;
	int    count;
	int    calls;
};

struct p2p_ops_benchmark {
	struct p2p_op_result keygen;
	struct p2p_op_result aead_enc;
	struct p2p_op_result aead_dec;
	struct p2p_op_result signature;
	struct p2p_op_result verification;
	struct p2p_op_result ecdh;
	struct p2p_op_result hkdf;
	struct p2p_op_result hash;
	struct p2p_op_result pq_keygen;
	struct p2p_op_result pq_encaps;
	struct p2p_op_result pq_decaps;
	struct p2p_op_result pq_sig_sign;
	struct p2p_op_result pq_sig_verify;
	struct p2p_op_result pq_aead_enc;
	struct p2p_op_result pq_aead_dec;
	struct p2p_op_result pq_hkdf;
	struct p2p_op_result pq_hash;
};

struct p2p_prim_cache {
	struct p2p_op_result keygen;
	struct p2p_op_result aead_enc;
	struct p2p_op_result aead_dec;
	struct p2p_op_result signature;
	struct p2p_op_result verification;
	struct p2p_op_result ecdh;
	struct p2p_op_result hkdf;
	struct p2p_op_result hash;
	struct p2p_op_result pq_keygen;
	struct p2p_op_result pq_encaps;
	struct p2p_op_result pq_decaps;
	struct p2p_op_result pq_sig_sign;
	struct p2p_op_result pq_sig_verify;
	struct p2p_op_result pq_aead_enc;
	struct p2p_op_result pq_aead_dec;
	struct p2p_op_result pq_hkdf;
	struct p2p_op_result pq_hash;
};

/* ---- Individual crypto benchmarks ---- */
static struct p2p_op_result p2p_bench_keygen(int iterations) {
	struct p2p_op_result r = {0}; uint64_t total = 0;
	for (int i = 0; i < iterations; i++) {
		uint8_t sk[32], pk[32];
		struct byte_array ska = {.len=32,.ptr=sk}, pka = {.len=32,.ptr=pk};
		uint64_t s = p2p_cpu_ns();
		enum err e = ephemeral_dh_key_gen(X25519, (uint32_t)(i*37+42), &ska, &pka);
		uint64_t end = p2p_cpu_ns();
		if (e == ok) { total += (end - s); r.count++; }
	}
	if (r.count > 0) r.avg_us = (double)total / (double)r.count / 1000.0;
	return r;
}

static struct p2p_op_result p2p_bench_aead_enc(int iterations) {
	struct p2p_op_result r = {0}; uint64_t total = 0;
	uint8_t pt[32], key[16], nonce[13], aad[16], ct[64], tag[8];
	memset(pt,0xAA,32); memset(key,0xBB,16); memset(nonce,0xCC,13); memset(aad,0xDD,16);
	struct byte_array pa={.len=32,.ptr=pt}, ka={.len=16,.ptr=key};
	struct byte_array na={.len=13,.ptr=nonce}, aa={.len=16,.ptr=aad};
	struct byte_array ca={.len=32,.ptr=ct}, ta={.len=8,.ptr=tag};
	for (int i = 0; i < iterations; i++) {
		ca.len=32; ta.len=8;
		uint64_t s = p2p_cpu_ns();
		enum err e = aead(ENCRYPT, &pa, &ka, &na, &aa, &ca, &ta);
		uint64_t end = p2p_cpu_ns();
		if (e == ok) { total += (end - s); r.count++; }
	}
	if (r.count > 0) r.avg_us = (double)total / (double)r.count / 1000.0;
	return r;
}

static struct p2p_op_result p2p_bench_aead_dec(int iterations) {
	struct p2p_op_result r = {0}; uint64_t total = 0;
	uint8_t pt[32], key[16], nonce[13], aad[16], ct[64], tag[8], dec[64];
	memset(pt,0xAA,32); memset(key,0xBB,16); memset(nonce,0xCC,13); memset(aad,0xDD,16);
	struct byte_array pa={.len=32,.ptr=pt}, ka={.len=16,.ptr=key};
	struct byte_array na={.len=13,.ptr=nonce}, aa={.len=16,.ptr=aad};
	struct byte_array ca={.len=32,.ptr=ct}, ta={.len=8,.ptr=tag};
	if (aead(ENCRYPT, &pa, &ka, &na, &aa, &ca, &ta) != ok) return r;
	uint8_t ct_tag[64]; memcpy(ct_tag, ct, ca.len); memcpy(ct_tag+ca.len, tag, ta.len);
	uint32_t ctl = ca.len + ta.len;
	struct byte_array ci={.len=ctl,.ptr=ct_tag}, da={.len=32,.ptr=dec}, dt={.len=8,.ptr=tag};
	for (int i = 0; i < iterations; i++) {
		da.len=32; dt.len=8;
		uint64_t s = p2p_cpu_ns();
		enum err e = aead(DECRYPT, &ci, &ka, &na, &aa, &da, &dt);
		uint64_t end = p2p_cpu_ns();
		if (e == ok) { total += (end - s); r.count++; }
	}
	if (r.count > 0) r.avg_us = (double)total / (double)r.count / 1000.0;
	return r;
}

static struct p2p_op_result p2p_bench_signature(int iterations) {
	struct p2p_op_result r = {0}; uint64_t total = 0;
	struct byte_array sk={.len=T1_RFC9529__SK_I_LEN,.ptr=(uint8_t*)T1_RFC9529__SK_I};
	struct byte_array pk={.len=T1_RFC9529__PK_I_LEN,.ptr=(uint8_t*)T1_RFC9529__PK_I};
	uint8_t msg[64]; memset(msg,0x42,64);
	struct byte_array ma={.len=64,.ptr=msg};
	uint8_t sig[64];
	for (int i = 0; i < iterations; i++) {
		uint64_t s = p2p_cpu_ns();
		enum err e = sign(EdDSA, &sk, &pk, &ma, sig);
		uint64_t end = p2p_cpu_ns();
		if (e == ok) { total += (end - s); r.count++; }
	}
	if (r.count > 0) r.avg_us = (double)total / (double)r.count / 1000.0;
	return r;
}

static struct p2p_op_result p2p_bench_verification(int iterations) {
	struct p2p_op_result r = {0}; uint64_t total = 0;
	struct byte_array sk={.len=T1_RFC9529__SK_I_LEN,.ptr=(uint8_t*)T1_RFC9529__SK_I};
	struct byte_array pk={.len=T1_RFC9529__PK_I_LEN,.ptr=(uint8_t*)T1_RFC9529__PK_I};
	uint8_t msg[64]; memset(msg,0x42,64);
	struct byte_array ma={.len=64,.ptr=msg}; uint8_t sig[64];
	if (sign(EdDSA, &sk, &pk, &ma, sig) != ok) return r;
	struct const_byte_array cm={.len=64,.ptr=msg}, cs={.len=64,.ptr=sig};
	for (int i = 0; i < iterations; i++) {
		bool verified = false;
		uint64_t s = p2p_cpu_ns();
		enum err e = verify(EdDSA, &pk, &cm, &cs, &verified);
		uint64_t end = p2p_cpu_ns();
		if (e == ok && verified) { total += (end - s); r.count++; }
	}
	if (r.count > 0) r.avg_us = (double)total / (double)r.count / 1000.0;
	return r;
}

static struct p2p_op_result p2p_bench_ecdh(int iterations) {
	struct p2p_op_result r = {0}; uint64_t total = 0;
	struct byte_array sk={.len=T1_RFC9529__X_LEN,.ptr=(uint8_t*)T1_RFC9529__X};
	struct byte_array pk={.len=T1_RFC9529__G_Y_LEN,.ptr=(uint8_t*)T1_RFC9529__G_Y};
	uint8_t ss[32];
	for (int i = 0; i < iterations; i++) {
		uint64_t s = p2p_cpu_ns();
		enum err e = shared_secret_derive(X25519, &sk, &pk, ss);
		uint64_t end = p2p_cpu_ns();
		if (e == ok) { total += (end - s); r.count++; }
	}
	if (r.count > 0) r.avg_us = (double)total / (double)r.count / 1000.0;
	return r;
}

static struct p2p_op_result p2p_bench_hkdf_op(int iterations) {
	struct p2p_op_result r = {0}; uint64_t total = 0;
	uint8_t salt[32], ikm[32], prk[32], info[16], okm[32];
	memset(salt,0x11,32); memset(ikm,0x22,32); memset(info,0x33,16);
	struct byte_array sa={.len=32,.ptr=salt}, ia={.len=32,.ptr=ikm};
	struct byte_array pa={.len=32,.ptr=prk}, fa={.len=16,.ptr=info};
	struct byte_array oa={.len=32,.ptr=okm};
	for (int i = 0; i < iterations; i++) {
		uint64_t s = p2p_cpu_ns();
		enum err e = hkdf_extract(SHA_256, &sa, &ia, prk);
		if (e != ok) continue;
		oa.len = 32;
		e = hkdf_expand(SHA_256, &pa, &fa, &oa);
		uint64_t end = p2p_cpu_ns();
		if (e == ok) { total += (end - s); r.count++; }
	}
	if (r.count > 0) r.avg_us = (double)total / (double)r.count / 1000.0;
	return r;
}

static struct p2p_op_result p2p_bench_hash_op(int iterations) {
	struct p2p_op_result r = {0}; uint64_t total = 0;
	uint8_t msg[128], out[32]; memset(msg,0x55,128);
	struct byte_array ma={.len=128,.ptr=msg}, oa={.len=32,.ptr=out};
	for (int i = 0; i < iterations; i++) {
		oa.len = 32;
		uint64_t s = p2p_cpu_ns();
		enum err e = hash(SHA_256, &ma, &oa);
		uint64_t end = p2p_cpu_ns();
		if (e == ok) { total += (end - s); r.count++; }
	}
	if (r.count > 0) r.avg_us = (double)total / (double)r.count / 1000.0;
	return r;
}

static struct p2p_op_result p2p_bench_pq_keygen_op(int iterations) {
	struct p2p_op_result r = {0}; uint64_t total = 0;
	uint8_t pk[PQ_KEM_PK_LEN], sk[PQ_KEM_SK_LEN];
	for (int i = 0; i < iterations; i++) {
		uint64_t s = p2p_cpu_ns();
		int ret = pq_kem_keygen(pk, sk);
		uint64_t end = p2p_cpu_ns();
		if (ret == 0) { total += (end - s); r.count++; }
	}
	if (r.count > 0) r.avg_us = (double)total / (double)r.count / 1000.0;
	return r;
}

static struct p2p_op_result p2p_bench_pq_encaps(int iterations) {
	struct p2p_op_result r = {0}; uint64_t total = 0;
	uint8_t pk[PQ_KEM_PK_LEN], sk[PQ_KEM_SK_LEN], ct[PQ_KEM_CT_LEN], ss[PQ_KEM_SS_LEN];
	if (pq_kem_keygen(pk, sk) != 0) return r;
	for (int i = 0; i < iterations; i++) {
		uint64_t s = p2p_cpu_ns();
		int ret = pq_kem_encaps(ct, ss, pk);
		uint64_t end = p2p_cpu_ns();
		if (ret == 0) { total += (end - s); r.count++; }
	}
	if (r.count > 0) r.avg_us = (double)total / (double)r.count / 1000.0;
	return r;
}

static struct p2p_op_result p2p_bench_pq_decaps(int iterations) {
	struct p2p_op_result r = {0}; uint64_t total = 0;
	uint8_t pk[PQ_KEM_PK_LEN], sk[PQ_KEM_SK_LEN], ct[PQ_KEM_CT_LEN], ss[PQ_KEM_SS_LEN], ss2[PQ_KEM_SS_LEN];
	if (pq_kem_keygen(pk, sk) != 0) return r;
	if (pq_kem_encaps(ct, ss, pk) != 0) return r;
	for (int i = 0; i < iterations; i++) {
		uint64_t s = p2p_cpu_ns();
		int ret = pq_kem_decaps(ss2, ct, sk);
		uint64_t end = p2p_cpu_ns();
		if (ret == 0) { total += (end - s); r.count++; }
	}
	if (r.count > 0) r.avg_us = (double)total / (double)r.count / 1000.0;
	return r;
}

static struct p2p_op_result p2p_bench_pq_sig_sign(int iterations) {
	struct p2p_op_result r = {0}; uint64_t total = 0;
	uint8_t pk[PQ_SIG_PK_LEN], sk[PQ_SIG_SK_LEN], sig[PQ_SIG_MAX_LEN], msg[64];
	memset(msg, 0xAA, 64);
	if (pq_sig_keygen(pk, sk) != 0) return r;
	for (int i = 0; i < iterations; i++) {
		size_t sl = 0;
		uint64_t s = p2p_cpu_ns();
		int ret = pq_sig_sign(msg, 64, sk, sig, &sl);
		uint64_t end = p2p_cpu_ns();
		if (ret == 0) { total += (end - s); r.count++; }
	}
	if (r.count > 0) r.avg_us = (double)total / (double)r.count / 1000.0;
	return r;
}

static struct p2p_op_result p2p_bench_pq_sig_verify(int iterations) {
	struct p2p_op_result r = {0}; uint64_t total = 0;
	uint8_t pk[PQ_SIG_PK_LEN], sk[PQ_SIG_SK_LEN], sig[PQ_SIG_MAX_LEN], msg[64];
	size_t sl = 0; memset(msg, 0xAA, 64);
	if (pq_sig_keygen(pk, sk) != 0) return r;
	if (pq_sig_sign(msg, 64, sk, sig, &sl) != 0) return r;
	for (int i = 0; i < iterations; i++) {
		uint64_t s = p2p_cpu_ns();
		int ret = pq_sig_verify(msg, 64, sig, sl, pk);
		uint64_t end = p2p_cpu_ns();
		if (ret == 0) { total += (end - s); r.count++; }
	}
	if (r.count > 0) r.avg_us = (double)total / (double)r.count / 1000.0;
	return r;
}

static struct p2p_op_result p2p_bench_pq_aead_enc(int iterations) {
	struct p2p_op_result r = {0}; uint64_t total = 0;
	uint8_t key[PQ_AEAD_KEY_LEN], iv[PQ_AEAD_NONCE_LEN], pt[32], ct[32+PQ_AEAD_TAG_LEN];
	memset(key,0xBB,sizeof(key)); memset(iv,0xCC,sizeof(iv)); memset(pt,0xAA,32);
	for (int i = 0; i < iterations; i++) {
		size_t cl = 0;
		uint64_t s = p2p_cpu_ns();
		int ret = pq_aead_encrypt(key, iv, NULL, 0, pt, 32, ct, &cl);
		uint64_t end = p2p_cpu_ns();
		if (ret == 0) { total += (end - s); r.count++; }
	}
	if (r.count > 0) r.avg_us = (double)total / (double)r.count / 1000.0;
	return r;
}

static struct p2p_op_result p2p_bench_pq_aead_dec(int iterations) {
	struct p2p_op_result r = {0}; uint64_t total = 0;
	uint8_t key[PQ_AEAD_KEY_LEN], iv[PQ_AEAD_NONCE_LEN], pt[32], ct[32+PQ_AEAD_TAG_LEN], dec[32];
	memset(key,0xBB,sizeof(key)); memset(iv,0xCC,sizeof(iv)); memset(pt,0xAA,32);
	size_t cl = 0;
	if (pq_aead_encrypt(key, iv, NULL, 0, pt, 32, ct, &cl) != 0) return r;
	for (int i = 0; i < iterations; i++) {
		size_t dl = 0;
		uint64_t s = p2p_cpu_ns();
		int ret = pq_aead_decrypt(key, iv, NULL, 0, ct, cl, dec, &dl);
		uint64_t end = p2p_cpu_ns();
		if (ret == 0) { total += (end - s); r.count++; }
	}
	if (r.count > 0) r.avg_us = (double)total / (double)r.count / 1000.0;
	return r;
}

static struct p2p_op_result p2p_bench_pq_hkdf_op(int iterations) {
	struct p2p_op_result r = {0}; uint64_t total = 0;
	uint8_t salt[32], ikm[32], prk[32], info[16], okm[32];
	memset(salt,0x11,32); memset(ikm,0x22,32); memset(info,0x33,16);
	for (int i = 0; i < iterations; i++) {
		uint64_t s = p2p_cpu_ns();
		int ret = pq_hkdf_extract(salt, 32, ikm, 32, prk);
		if (ret == 0) ret = pq_hkdf_expand(prk, info, 16, okm, 32);
		uint64_t end = p2p_cpu_ns();
		if (ret == 0) { total += (end - s); r.count++; }
	}
	if (r.count > 0) r.avg_us = (double)total / (double)r.count / 1000.0;
	return r;
}

static struct p2p_op_result p2p_bench_pq_hash_op(int iterations) {
	struct p2p_op_result r = {0}; uint64_t total = 0;
	uint8_t msg[128], out[32]; memset(msg,0x55,128);
	for (int i = 0; i < iterations; i++) {
		uint64_t s = p2p_cpu_ns();
		int ret = pq_hash_sha256(msg, 128, out);
		uint64_t end = p2p_cpu_ns();
		if (ret == 0) { total += (end - s); r.count++; }
	}
	if (r.count > 0) r.avg_us = (double)total / (double)r.count / 1000.0;
	return r;
}

/* Bench all primitives in one go */
static void p2p_bench_all_primitives(struct p2p_prim_cache *c)
{
	const int N = P2P_BENCH_ITERATIONS;
	const int W = 20;

	/* Warmup */
	(void)p2p_bench_keygen(W);
	(void)p2p_bench_aead_enc(W);
	(void)p2p_bench_aead_dec(W);
	(void)p2p_bench_signature(W);
	(void)p2p_bench_verification(W);
	(void)p2p_bench_ecdh(W);
	(void)p2p_bench_hkdf_op(W);
	(void)p2p_bench_hash_op(W);
	(void)p2p_bench_pq_keygen_op(W);
	(void)p2p_bench_pq_encaps(W);
	(void)p2p_bench_pq_decaps(W);
	(void)p2p_bench_pq_sig_sign(W);
	(void)p2p_bench_pq_sig_verify(W);
	(void)p2p_bench_pq_aead_enc(W);
	(void)p2p_bench_pq_aead_dec(W);
	(void)p2p_bench_pq_hkdf_op(W);
	(void)p2p_bench_pq_hash_op(W);

	/* Measurement */
	c->keygen       = p2p_bench_keygen(N);
	c->aead_enc     = p2p_bench_aead_enc(N);
	c->aead_dec     = p2p_bench_aead_dec(N);
	c->signature    = p2p_bench_signature(N);
	c->verification = p2p_bench_verification(N);
	c->ecdh         = p2p_bench_ecdh(N);
	c->hkdf         = p2p_bench_hkdf_op(N);
	c->hash         = p2p_bench_hash_op(N);
	c->pq_keygen    = p2p_bench_pq_keygen_op(N);
	c->pq_encaps    = p2p_bench_pq_encaps(N);
	c->pq_decaps    = p2p_bench_pq_decaps(N);
	c->pq_sig_sign  = p2p_bench_pq_sig_sign(N);
	c->pq_sig_verify = p2p_bench_pq_sig_verify(N);
	c->pq_aead_enc  = p2p_bench_pq_aead_enc(N);
	c->pq_aead_dec  = p2p_bench_pq_aead_dec(N);
	c->pq_hkdf      = p2p_bench_pq_hkdf_op(N);
	c->pq_hash      = p2p_bench_pq_hash_op(N);
}

/* Helper: copy timing from cache with call count */
static struct p2p_op_result p2p_op(const struct p2p_op_result *src, int calls) {
	if (calls <= 0) return (struct p2p_op_result){0};
	struct p2p_op_result r = *src; r.calls = calls; return r;
}
static struct p2p_op_result p2p_op_zero(void) { return (struct p2p_op_result){0}; }

/* Assemble ops per variant + role (same call counts as socket benchmark) */
static void p2p_assemble_classic_ops(const struct p2p_prim_cache *c,
	int type_num, int is_initiator, struct p2p_ops_benchmark *ops)
{
	ops->keygen       = p2p_op(&c->keygen, 1);
	ops->aead_enc     = p2p_op(&c->aead_enc, is_initiator ? 1 : 0);
	ops->aead_dec     = p2p_op(&c->aead_dec, is_initiator ? 0 : 1);
	if (type_num == 0) {
		ops->signature    = p2p_op(&c->signature, 1);
		ops->verification = p2p_op(&c->verification, 1);
	} else {
		ops->signature    = p2p_op_zero();
		ops->verification = p2p_op_zero();
	}
	ops->ecdh = p2p_op(&c->ecdh, (type_num == 0) ? 2 : 4);
	ops->hkdf = p2p_op(&c->hkdf, (type_num == 0) ? 8 : 10);
	ops->hash = p2p_op(&c->hash, 4);
	memset(&ops->pq_keygen, 0, sizeof(struct p2p_op_result) * 9);
}

static void p2p_assemble_pq_ops(const struct p2p_prim_cache *c,
	int pq_type_num, int is_initiator, struct p2p_ops_benchmark *ops)
{
	ops->pq_keygen = p2p_op(&c->pq_keygen, 1);
	ops->pq_encaps = p2p_op(&c->pq_encaps,
		(pq_type_num == 0) ? 1 : (is_initiator ? 1 : 2));
	ops->pq_decaps = p2p_op(&c->pq_decaps,
		(pq_type_num == 0) ? 1 : (is_initiator ? 2 : 1));
	if (pq_type_num == 0) {
		ops->pq_sig_sign   = p2p_op(&c->pq_sig_sign, 1);
		ops->pq_sig_verify = p2p_op(&c->pq_sig_verify, 1);
	} else {
		ops->pq_sig_sign   = p2p_op_zero();
		ops->pq_sig_verify = p2p_op_zero();
	}
	ops->pq_aead_enc = p2p_op(&c->pq_aead_enc, is_initiator ? 2 : 1);
	ops->pq_aead_dec = p2p_op(&c->pq_aead_dec, is_initiator ? 1 : 2);
	ops->pq_hkdf     = p2p_op(&c->pq_hkdf, 8);
	ops->pq_hash     = p2p_op(&c->pq_hash, 3);
	memset(&ops->keygen, 0, sizeof(struct p2p_op_result) * 8);
}

static void p2p_assemble_hybrid_ops(const struct p2p_prim_cache *c,
	int is_initiator, struct p2p_ops_benchmark *ops)
{
	ops->keygen       = p2p_op(&c->keygen, 1);
	ops->aead_enc     = p2p_op(&c->aead_enc, 1);
	ops->aead_dec     = p2p_op(&c->aead_dec, 1);
	ops->signature    = p2p_op_zero();
	ops->verification = p2p_op_zero();
	ops->ecdh         = p2p_op(&c->ecdh, 4);
	ops->hkdf         = p2p_op(&c->hkdf, 10);
	ops->hash         = p2p_op(&c->hash, 3);
	ops->pq_keygen    = p2p_op(&c->pq_keygen, is_initiator ? 1 : 0);
	ops->pq_encaps    = p2p_op(&c->pq_encaps, is_initiator ? 0 : 1);
	ops->pq_decaps    = p2p_op(&c->pq_decaps, is_initiator ? 1 : 0);
	ops->pq_sig_sign  = p2p_op_zero();
	ops->pq_sig_verify = p2p_op_zero();
	ops->pq_aead_enc  = p2p_op_zero();
	ops->pq_aead_dec  = p2p_op_zero();
	ops->pq_hkdf      = p2p_op_zero();
	ops->pq_hash      = p2p_op_zero();
}

/* =============================================================================
 * CSV writers
 * ========================================================================== */
static void p2p_write_hs_csv(const char *path, const char *role,
	const char **names, struct p2p_hs_accum *acc, int n_variants,
	const struct p2p_precomp *pc)
{
	FILE *fp=fopen(path,"w"); if(!fp) return;
	fprintf(fp,"type,role,processing_us,txrx_us,precomputation_us,overhead_us,total_us,success_count\n");
	for(int i=0;i<n_variants;i++){
		double avg_wall=0,avg_cpu=0,avg_txrx=0;
		if(acc[i].success_count>0){
			double n=(double)acc[i].success_count;
			avg_wall=acc[i].total_wall/n;avg_cpu=acc[i].total_cpu/n;avg_txrx=acc[i].total_txrx/n;
		}
		double precomp = p2p_precomp_for_variant(i, pc);
		double processing = avg_cpu - precomp;
		if (processing < 0) processing = 0;
		double overhead = avg_wall - processing - avg_txrx - precomp;
		if (overhead < 0) { overhead = 0; avg_wall = processing + avg_txrx + precomp; }
		fprintf(fp,"%s,%s,%.3f,%.3f,%.3f,%.3f,%.3f,%d\n",
			names[i],role,processing,avg_txrx,precomp,overhead,avg_wall,acc[i].success_count);
	}
	fclose(fp);
}

static void p2p_write_overhead_csv(const char *path, const char *role,
	struct p2p_hs_accum *acc, const struct p2p_precomp *pc, int is_initiator)
{
	FILE *fp = fopen(path, "w");
	if (!fp) return;

	fprintf(fp, "type,role,cpu_time_us,memory_bytes,memory_note\n");
	for (int v = 0; v < 5; v++) {
		double avg_cpu = 0.0;
		if (acc[v].success_count > 0)
			avg_cpu = acc[v].total_cpu / (double)acc[v].success_count;

		double pre = p2p_precomp_for_variant(v, pc);
		double processing = avg_cpu - pre;
		if (processing < 0) processing = 0;

		long mem = p2p_estimate_memory_by_variant(v, is_initiator);
		const char *note = (v == 4) ? "estimated_stack_heap_hybrid" :
				   ((v == 2 || v == 3) ? "estimated_stack_heap_pq" : "estimated_stack_heap");

		fprintf(fp, "%s,%s,%.3f,%ld,%s\n",
			P2P_TYPE_LABELS[v], role, processing, mem, note);
	}

	fclose(fp);
}

static void p2p_write_operations_csv(const char *path, const char *role,
	int is_initiator, const struct p2p_prim_cache *cache)
{
	FILE *fp = fopen(path, "w");
	if (!fp) return;

	fprintf(fp, "type,role,operation,avg_time_us,calls_per_handshake,total_per_handshake_us,iterations\n");

#define P2P_WROP(TYPE, ROLE, OP_NAME, OP) \
	fprintf(fp, "%s,%s,%s,%.3f,%d,%.3f,%d\n", \
		TYPE, ROLE, OP_NAME, (OP).avg_us, (OP).calls, \
		(OP).avg_us * (double)(OP).calls, (OP).count)

	struct p2p_ops_benchmark ops;

	/* Classic Type 0 */
	memset(&ops, 0, sizeof(ops));
	p2p_assemble_classic_ops(cache, 0, is_initiator, &ops);
	P2P_WROP("Type0_SigSig", role, "KeyGen", ops.keygen);
	P2P_WROP("Type0_SigSig", role, "Encap", ops.pq_encaps);
	P2P_WROP("Type0_SigSig", role, "Decap", ops.pq_decaps);
	P2P_WROP("Type0_SigSig", role, "AEAD_Enc", ops.aead_enc);
	P2P_WROP("Type0_SigSig", role, "AEAD_Dec", ops.aead_dec);
	P2P_WROP("Type0_SigSig", role, "Signature", ops.signature);
	P2P_WROP("Type0_SigSig", role, "Verification", ops.verification);
	P2P_WROP("Type0_SigSig", role, "ECDH", ops.ecdh);
	P2P_WROP("Type0_SigSig", role, "HKDF", ops.hkdf);
	P2P_WROP("Type0_SigSig", role, "Hash", ops.hash);

	/* Classic Type 3 */
	memset(&ops, 0, sizeof(ops));
	p2p_assemble_classic_ops(cache, 3, is_initiator, &ops);
	P2P_WROP("Type3_MACMAC", role, "KeyGen", ops.keygen);
	P2P_WROP("Type3_MACMAC", role, "Encap", ops.pq_encaps);
	P2P_WROP("Type3_MACMAC", role, "Decap", ops.pq_decaps);
	P2P_WROP("Type3_MACMAC", role, "AEAD_Enc", ops.aead_enc);
	P2P_WROP("Type3_MACMAC", role, "AEAD_Dec", ops.aead_dec);
	P2P_WROP("Type3_MACMAC", role, "Signature", ops.signature);
	P2P_WROP("Type3_MACMAC", role, "Verification", ops.verification);
	P2P_WROP("Type3_MACMAC", role, "ECDH", ops.ecdh);
	P2P_WROP("Type3_MACMAC", role, "HKDF", ops.hkdf);
	P2P_WROP("Type3_MACMAC", role, "Hash", ops.hash);

	/* PQ Type 0 */
	memset(&ops, 0, sizeof(ops));
	p2p_assemble_pq_ops(cache, 0, is_initiator, &ops);
	P2P_WROP("Type0_PQ", role, "PQ_KeyGen", ops.pq_keygen);
	P2P_WROP("Type0_PQ", role, "PQ_Encaps", ops.pq_encaps);
	P2P_WROP("Type0_PQ", role, "PQ_Decaps", ops.pq_decaps);
	P2P_WROP("Type0_PQ", role, "PQ_Signature", ops.pq_sig_sign);
	P2P_WROP("Type0_PQ", role, "PQ_Verification", ops.pq_sig_verify);
	P2P_WROP("Type0_PQ", role, "PQ_AEAD_Enc", ops.pq_aead_enc);
	P2P_WROP("Type0_PQ", role, "PQ_AEAD_Dec", ops.pq_aead_dec);
	P2P_WROP("Type0_PQ", role, "PQ_HKDF", ops.pq_hkdf);
	P2P_WROP("Type0_PQ", role, "PQ_Hash", ops.pq_hash);

	/* PQ Type 3 */
	memset(&ops, 0, sizeof(ops));
	p2p_assemble_pq_ops(cache, 3, is_initiator, &ops);
	P2P_WROP("Type3_PQ", role, "PQ_KeyGen", ops.pq_keygen);
	P2P_WROP("Type3_PQ", role, "PQ_Encaps", ops.pq_encaps);
	P2P_WROP("Type3_PQ", role, "PQ_Decaps", ops.pq_decaps);
	P2P_WROP("Type3_PQ", role, "PQ_Signature", ops.pq_sig_sign);
	P2P_WROP("Type3_PQ", role, "PQ_Verification", ops.pq_sig_verify);
	P2P_WROP("Type3_PQ", role, "PQ_AEAD_Enc", ops.pq_aead_enc);
	P2P_WROP("Type3_PQ", role, "PQ_AEAD_Dec", ops.pq_aead_dec);
	P2P_WROP("Type3_PQ", role, "PQ_HKDF", ops.pq_hkdf);
	P2P_WROP("Type3_PQ", role, "PQ_Hash", ops.pq_hash);

	/* Hybrid Type 3 */
	memset(&ops, 0, sizeof(ops));
	p2p_assemble_hybrid_ops(cache, is_initiator, &ops);
	P2P_WROP("Type3_Hybrid", role, "KeyGen", ops.keygen);
	P2P_WROP("Type3_Hybrid", role, "AEAD_Enc", ops.aead_enc);
	P2P_WROP("Type3_Hybrid", role, "AEAD_Dec", ops.aead_dec);
	P2P_WROP("Type3_Hybrid", role, "ECDH", ops.ecdh);
	P2P_WROP("Type3_Hybrid", role, "HKDF", ops.hkdf);
	P2P_WROP("Type3_Hybrid", role, "Hash", ops.hash);
	P2P_WROP("Type3_Hybrid", role, "PQ_KeyGen", ops.pq_keygen);
	P2P_WROP("Type3_Hybrid", role, "PQ_Encaps", ops.pq_encaps);
	P2P_WROP("Type3_Hybrid", role, "PQ_Decaps", ops.pq_decaps);

#undef P2P_WROP

	fclose(fp);
}

/* =============================================================================
 * The main P2P loop logic (shared between responder/initiator)
 * ========================================================================== */
static const char *VARIANT_NAMES[5] = {
	"Classic_Type0", "Classic_Type3", "PQ_Type0", "PQ_Type3", "Hybrid_Type3"
};

/* =============================================================================
 * run_p2p_responder()
 * ========================================================================== */
int run_p2p_responder(int port)
{
	signal(SIGPIPE, SIG_IGN);
	print_header("EDHOC P2P Benchmark — RESPONDER (Server)");
	char buf[256];
	snprintf(buf,sizeof(buf),"  Listening on 0.0.0.0:%d  |  %d iterations per variant",port,P2P_BENCH_HANDSHAKE_ITERATIONS);
	print_info(buf);
	mkdir(P2P_BENCH_OUTPUT_DIR,0755);

	/* Measure keygen precomputation costs */
	print_info("  Measuring keygen precomputation costs...");
	struct p2p_precomp precomp = p2p_measure_precomp();
	snprintf(buf,sizeof(buf),"  Precomp: X25519 keygen=%.3f µs, ML-KEM-768 keygen=%.3f µs",
		precomp.classic_keygen_us, precomp.pq_keygen_us);
	print_info(buf);

	/* Benchmark all crypto primitives for operations CSV */
	print_info("  Benchmarking crypto primitives...");
	struct p2p_prim_cache prim_cache;
	p2p_bench_all_primitives(&prim_cache);
	print_success("  Crypto primitives benchmarked.");

	/* Pre-generate PQ key material (shared across iterations) */
	uint8_t r_lt_pk[PQ_KEM_PK_LEN],r_lt_sk[PQ_KEM_SK_LEN];
	uint8_t i_lt_pk[PQ_KEM_PK_LEN],i_lt_sk[PQ_KEM_SK_LEN];
	pq_kem_keygen(r_lt_pk,r_lt_sk); pq_kem_keygen(i_lt_pk,i_lt_sk);
	uint8_t r_sig_pk[PQ_SIG_PK_LEN],r_sig_sk[PQ_SIG_SK_LEN];
	uint8_t i_sig_pk[PQ_SIG_PK_LEN],i_sig_sk[PQ_SIG_SK_LEN];
	pq_sig_keygen(r_sig_pk,r_sig_sk); pq_sig_keygen(i_sig_pk,i_sig_sk);
	/* Hybrid static DH keys */
	uint8_t r_ssk[32],r_spk[32],i_ssk[32],i_spk[32];
	{struct byte_array sk={.len=32,.ptr=r_ssk},pk={.len=32,.ptr=r_spk};ephemeral_dh_key_gen(X25519,200,&sk,&pk);}
	{struct byte_array sk={.len=32,.ptr=i_ssk},pk={.len=32,.ptr=i_spk};ephemeral_dh_key_gen(X25519,100,&sk,&pk);}

	/* Wait for Initiator on control channel */
	print_header("Waiting for Initiator...");
	int cl=p2p_server(port); if(cl<0){print_error("bind failed");return -1;}
	int cfd=accept(cl,NULL,NULL); close(cl);
	if(cfd<0){print_error("accept failed");return -1;}
	p2p_nodelay(cfd);
	print_success("Initiator connected!");

	/* Exchange key material over control channel */
	/* Send: r_lt_pk, r_sig_pk, r_spk */
	p2p_send(cfd,r_lt_pk,PQ_KEM_PK_LEN);
	p2p_send(cfd,r_sig_pk,PQ_SIG_PK_LEN);
	p2p_send(cfd,r_spk,32);
	/* Receive: i_lt_pk, i_sig_pk, i_spk */
	{uint32_t dummy;
	 p2p_recv(cfd,i_lt_pk,PQ_KEM_PK_LEN,&dummy);
	 p2p_recv(cfd,i_sig_pk,PQ_SIG_PK_LEN,&dummy);
	 p2p_recv(cfd,i_spk,32,&dummy);}

	/* Sync */
	char cb[256]; ctrl_r(cfd,cb,sizeof(cb)); ctrl_s(cfd,P2P_TAG_READY);

	struct p2p_hs_accum acc[5]; memset(acc,0,sizeof(acc));

	for(int v=0;v<5;v++){
		snprintf(buf,sizeof(buf),"[%d/5] %s",v+1,VARIANT_NAMES[v]); print_header(buf);
		/* Tell Initiator which variant + port */
		int hs_port = port + 1000 + v;
		snprintf(buf,sizeof(buf),"%d:%d",v,hs_port);
		ctrl_s(cfd,buf);
		ctrl_r(cfd,cb,sizeof(cb)); /* READY */

		/* Single listen socket per variant — reuse for all iterations */
		int lfd = p2p_server(hs_port);
		if(lfd<0){
			for(int iter=0;iter<P2P_BENCH_HANDSHAKE_ITERATIONS;iter++){
				ctrl_s(cfd,"FAIL"); ctrl_r(cfd,cb,sizeof(cb));
			}
			continue;
		}

		for(int iter=0;iter<P2P_BENCH_HANDSHAKE_ITERATIONS;iter++){
			ctrl_s(cfd,P2P_TAG_READY); /* tell Initiator to connect */

			struct p2p_hs_result r;
			switch(v){
			case 0: r=p2p_classic_responder(0,lfd); break;
			case 1: r=p2p_classic_responder(3,lfd); break;
			case 2: r=p2p_pq0_responder(lfd,r_lt_pk,r_lt_sk,i_lt_pk,r_sig_pk,r_sig_sk,i_sig_pk); break;
			case 3: r=p2p_pq3_responder(lfd,r_lt_pk,r_lt_sk,i_lt_pk); break;
			case 4: {
				uint8_t esk[32],epk[32];
				struct byte_array sk={.len=32,.ptr=esk},pk={.len=32,.ptr=epk};
				ephemeral_dh_key_gen(X25519,400+iter,&sk,&pk);
				r=p2p_hyb_responder(lfd,r_ssk,r_spk,i_spk,esk,epk);
			} break;
			default: r=(struct p2p_hs_result){0};
			}
			if(r.success){
				acc[v].total_wall+=r.wall_us; acc[v].total_cpu+=r.cpu_us;
				acc[v].total_txrx+=r.txrx_us; acc[v].success_count++;
			}
			ctrl_r(cfd,cb,sizeof(cb)); /* ITER_OK */
		}
		close(lfd);
		snprintf(buf,sizeof(buf),"%s: %d/%d ok",VARIANT_NAMES[v],acc[v].success_count,P2P_BENCH_HANDSHAKE_ITERATIONS);
		print_success(buf);
	}
	ctrl_s(cfd,P2P_TAG_DONE); close(cfd);

	/* Write CSV */
	p2p_write_hs_csv(P2P_BENCH_OUTPUT_DIR "/p2p_handshake_responder.csv","Responder",VARIANT_NAMES,acc,5,&precomp);
	p2p_write_overhead_csv(P2P_BENCH_OUTPUT_DIR "/p2p_overhead_responder.csv","Responder",acc,&precomp,0);
	p2p_write_operations_csv(P2P_BENCH_OUTPUT_DIR "/p2p_operations_responder.csv","Responder",0,&prim_cache);

	printf("\n"); print_header("Responder — Handshake Summary (µs, avg)");
	printf("  %-16s %14s %14s %14s %14s %14s %6s\n","Type","Processing","TxRx","Precompute","Overhead","Total","N");
	for(int v=0;v<5;v++){
		double n=(acc[v].success_count>0)?(double)acc[v].success_count:1;
		double avg_cpu=acc[v].total_cpu/n, avg_txrx=acc[v].total_txrx/n, avg_wall=acc[v].total_wall/n;
		double pre=p2p_precomp_for_variant(v,&precomp);
		double proc=avg_cpu-pre; if(proc<0) proc=0;
		double ovh=avg_wall-proc-avg_txrx-pre; if(ovh<0) ovh=0;
		printf("  %-16s %14.1f %14.1f %14.1f %14.1f %14.1f %6d\n",VARIANT_NAMES[v],
			proc,avg_txrx,pre,ovh,avg_wall,acc[v].success_count);
	}
	printf("\n"); print_success("P2P Responder benchmark completed!");
	return 0;
}

/* =============================================================================
 * run_p2p_initiator()
 * ========================================================================== */
int run_p2p_initiator(const char *host, int port)
{
	signal(SIGPIPE, SIG_IGN);
	print_header("EDHOC P2P Benchmark — INITIATOR (Client)");
	char buf[256];
	snprintf(buf,sizeof(buf),"  Connecting to %s:%d  |  %d iterations per variant",host,port,P2P_BENCH_HANDSHAKE_ITERATIONS);
	print_info(buf);
	mkdir(P2P_BENCH_OUTPUT_DIR,0755);

	/* Measure keygen precomputation costs */
	print_info("  Measuring keygen precomputation costs...");
	struct p2p_precomp precomp = p2p_measure_precomp();
	snprintf(buf,sizeof(buf),"  Precomp: X25519 keygen=%.3f µs, ML-KEM-768 keygen=%.3f µs",
		precomp.classic_keygen_us, precomp.pq_keygen_us);
	print_info(buf);

	/* Benchmark all crypto primitives for operations CSV */
	print_info("  Benchmarking crypto primitives...");
	struct p2p_prim_cache prim_cache;
	p2p_bench_all_primitives(&prim_cache);
	print_success("  Crypto primitives benchmarked.");

	/* Pre-generate own key material */
	uint8_t i_lt_pk[PQ_KEM_PK_LEN],i_lt_sk[PQ_KEM_SK_LEN];
	pq_kem_keygen(i_lt_pk,i_lt_sk);
	uint8_t i_sig_pk[PQ_SIG_PK_LEN],i_sig_sk[PQ_SIG_SK_LEN];
	pq_sig_keygen(i_sig_pk,i_sig_sk);
	uint8_t i_ssk[32],i_spk[32];
	{struct byte_array sk={.len=32,.ptr=i_ssk},pk={.len=32,.ptr=i_spk};ephemeral_dh_key_gen(X25519,100,&sk,&pk);}

	/* Connect control channel */
	print_header("Connecting to Responder...");
	int cfd=p2p_connect(host,port);
	if(cfd<0){print_error("Cannot connect");return -1;}
	p2p_nodelay(cfd);
	print_success("Connected!");

	/* Receive Responder key material */
	uint8_t r_lt_pk[PQ_KEM_PK_LEN],r_sig_pk[PQ_SIG_PK_LEN],r_spk[32];
	{uint32_t dummy;
	 p2p_recv(cfd,r_lt_pk,PQ_KEM_PK_LEN,&dummy);
	 p2p_recv(cfd,r_sig_pk,PQ_SIG_PK_LEN,&dummy);
	 p2p_recv(cfd,r_spk,32,&dummy);}
	/* Send own key material */
	p2p_send(cfd,i_lt_pk,PQ_KEM_PK_LEN);
	p2p_send(cfd,i_sig_pk,PQ_SIG_PK_LEN);
	p2p_send(cfd,i_spk,32);

	/* Sync */
	char cb[256]; ctrl_s(cfd,P2P_TAG_READY); ctrl_r(cfd,cb,sizeof(cb));

	struct p2p_hs_accum acc[5]; memset(acc,0,sizeof(acc));

	for(int v=0;v<5;v++){
		/* Receive variant info from Responder */
		ctrl_r(cfd,cb,sizeof(cb));
		int var_id,hs_port; sscanf(cb,"%d:%d",&var_id,&hs_port);
		snprintf(buf,sizeof(buf),"[%d/5] %s",v+1,VARIANT_NAMES[var_id]);
		print_header(buf);
		ctrl_s(cfd,P2P_TAG_READY);

		for(int iter=0;iter<P2P_BENCH_HANDSHAKE_ITERATIONS;iter++){
			ctrl_r(cfd,cb,sizeof(cb)); /* READY or FAIL */
			if(strcmp(cb,"FAIL")==0){ctrl_s(cfd,P2P_TAG_ITER_OK);continue;}

			struct p2p_hs_result r;
			switch(var_id){
			case 0: r=p2p_classic_initiator(0,host,hs_port); break;
			case 1: r=p2p_classic_initiator(3,host,hs_port); break;
			case 2: r=p2p_pq0_initiator(host,hs_port,i_lt_pk,i_lt_sk,r_lt_pk,i_sig_pk,i_sig_sk,r_sig_pk); break;
			case 3: r=p2p_pq3_initiator(host,hs_port,i_lt_pk,i_lt_sk,r_lt_pk); break;
			case 4: {
				uint8_t esk[32],epk[32],kpk[PQ_KEM_PK_LEN],ksk[PQ_KEM_SK_LEN];
				struct byte_array sk={.len=32,.ptr=esk},pk={.len=32,.ptr=epk};
				ephemeral_dh_key_gen(X25519,300+iter,&sk,&pk);
				pq_kem_keygen(kpk,ksk);
				r=p2p_hyb_initiator(host,hs_port,i_ssk,i_spk,r_spk,esk,epk,kpk,ksk);
			} break;
			default: r=(struct p2p_hs_result){0};
			}
			if(r.success){
				acc[var_id].total_wall+=r.wall_us; acc[var_id].total_cpu+=r.cpu_us;
				acc[var_id].total_txrx+=r.txrx_us; acc[var_id].success_count++;
			}
			ctrl_s(cfd,P2P_TAG_ITER_OK);
		}
		snprintf(buf,sizeof(buf),"%s: %d/%d ok",VARIANT_NAMES[var_id],acc[var_id].success_count,P2P_BENCH_HANDSHAKE_ITERATIONS);
		print_success(buf);
	}
	ctrl_r(cfd,cb,sizeof(cb)); close(cfd);

	/* Write CSV */
	p2p_write_hs_csv(P2P_BENCH_OUTPUT_DIR "/p2p_handshake_initiator.csv","Initiator",VARIANT_NAMES,acc,5,&precomp);
	p2p_write_overhead_csv(P2P_BENCH_OUTPUT_DIR "/p2p_overhead_initiator.csv","Initiator",acc,&precomp,1);
	p2p_write_operations_csv(P2P_BENCH_OUTPUT_DIR "/p2p_operations_initiator.csv","Initiator",1,&prim_cache);

	printf("\n"); print_header("Initiator — Handshake Summary (µs, avg)");
	printf("  %-16s %14s %14s %14s %14s %14s %6s\n","Type","Processing","TxRx","Precompute","Overhead","Total","N");
	for(int v=0;v<5;v++){
		double n=(acc[v].success_count>0)?(double)acc[v].success_count:1;
		double avg_cpu=acc[v].total_cpu/n, avg_txrx=acc[v].total_txrx/n, avg_wall=acc[v].total_wall/n;
		double pre=p2p_precomp_for_variant(v,&precomp);
		double proc=avg_cpu-pre; if(proc<0) proc=0;
		double ovh=avg_wall-proc-avg_txrx-pre; if(ovh<0) ovh=0;
		printf("  %-16s %14.1f %14.1f %14.1f %14.1f %14.1f %6d\n",VARIANT_NAMES[v],
			proc,avg_txrx,pre,ovh,avg_wall,acc[v].success_count);
	}
	printf("\n"); print_success("P2P Initiator benchmark completed!");
	return 0;
}

/* =============================================================================
 * CLI parser
 * ========================================================================== */
static void p2p_usage(void) {
	printf("\n  %sP2P Benchmark Usage:%s\n\n",CLR_BOLD,CLR_RESET);
	printf("  %sResponder (server):%s\n",CLR_CYAN,CLR_RESET);
	printf("    ./build/edhoc_hybrid 9 --responder [--port PORT]\n\n");
	printf("  %sInitiator (client):%s\n",CLR_CYAN,CLR_RESET);
	printf("    ./build/edhoc_hybrid 9 --initiator --host <SERVER_IP> [--port PORT]\n\n");
	printf("  Default port: %d\n\n",P2P_BENCH_DEFAULT_PORT);
}

int run_p2p_benchmark(int argc, char *argv[])
{
	int role=-1; char host[P2P_MAX_HOST_LEN]=""; int port=P2P_BENCH_DEFAULT_PORT;
	for(int i=2;i<argc;i++){
		if(strcmp(argv[i],"--responder")==0) role=0;
		else if(strcmp(argv[i],"--initiator")==0) role=1;
		else if(strcmp(argv[i],"--host")==0&&i+1<argc) strncpy(host,argv[++i],P2P_MAX_HOST_LEN-1);
		else if(strcmp(argv[i],"--port")==0&&i+1<argc) port=atoi(argv[++i]);
	}
	if(role<0){print_error("Specify --initiator or --responder");p2p_usage();return -1;}
	if(role==1&&strlen(host)==0){print_error("Initiator needs --host");p2p_usage();return -1;}

	int rc;
	const char *role_tag = role ? "initiator" : "responder";

	/* ── Phase A: Pure Crypto Benchmark (local, no network) ────────── */
	print_header("Phase A: Pure Cryptographic Operations Benchmark");
	printf("  → benchmark_crypto_ops_%s.csv, benchmark_crypto_matrix_%s.csv, benchmark_crypto_simple_%s.csv\n\n",
	       role_tag, role_tag, role_tag);
	rc = run_crypto_benchmark(role_tag);
	if (rc != 0) {
		print_error("Crypto benchmark failed!");
		return rc;
	}
	print_success("Phase A complete — 3 crypto CSV files written.");
	printf("\n");

	/* ── Phase B: Socket Benchmark (TCP localhost, all 5 variants) ── */
	print_header("Phase B: Socket-based Benchmark (TCP localhost)");
	printf("  → benchmark_operations_%s.csv, benchmark_overhead_%s.csv, benchmark_handshake_%s.csv\n\n",
	       role_tag, role_tag, role_tag);
	rc = run_edhoc_benchmark_socket(role_tag);
	if (rc != 0) {
		print_error("Socket benchmark failed!");
		return rc;
	}
	print_success("Phase B complete — 3 socket CSV files written.");
	printf("\n");

	/* ── Phase C: P2P Network Handshake Benchmark ──────────────────── */
	print_header("Phase C: P2P Network Benchmark (Initiator ↔ Responder)");
	printf("  → p2p_handshake_%s.csv, p2p_overhead_%s.csv, p2p_operations_%s.csv\n\n", role_tag, role_tag, role_tag);
	rc = role ? run_p2p_initiator(host,port) : run_p2p_responder(port);
	if (rc != 0) {
		print_error("P2P benchmark failed!");
		return rc;
	}
	print_success("Phase C complete — P2P CSV files written.");
	printf("\n");

	/* ── Summary ───────────────────────────────────────────────────── */
	print_header("All Benchmarks Complete!");
	printf("\n  Generated CSV files:\n");
	printf("    ✓ output/benchmark_crypto_ops_%s.csv\n", role_tag);
	printf("    ✓ output/benchmark_crypto_matrix_%s.csv\n", role_tag);
	printf("    ✓ output/benchmark_crypto_simple_%s.csv\n", role_tag);
	printf("    ✓ output/benchmark_operations_%s.csv\n", role_tag);
	printf("    ✓ output/benchmark_overhead_%s.csv\n", role_tag);
	printf("    ✓ output/benchmark_handshake_%s.csv\n", role_tag);
	printf("    ✓ output/p2p_handshake_%s.csv\n", role_tag);
	printf("    ✓ output/p2p_overhead_%s.csv\n", role_tag);
	printf("    ✓ output/p2p_operations_%s.csv\n", role_tag);
	printf("\n");

	return 0;
}
