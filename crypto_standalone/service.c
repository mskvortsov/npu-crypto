/* SPDX-License-Identifier: GPL-2.0-only */
#include "npu_types.h"
#include "npu_regs.h"
#include "npu_crypto.h"

#define SCRATCH_SIZE (NPU_CRYPTO_MAX_DATA + sizeof(struct npu_crypto_request_aad))
#define GROUPS AIROHA_CRYPTO_NPU_BATCH_SIZE
#define HARTS_PER_PACKET AIROHA_CRYPTO_NPU_HARTS_PER_PACKET
#define ACTIVE_HARTS 6
#define WORKERS_START 0x43525731
#define CRYPTO_READY 0x43525931

#if defined(NPU_CRYPTO_TEST) && !defined(NPU_CRYPTO_QEMU)
static u32 scratch[1][(SCRATCH_SIZE + 3) / 4];
static void parallel_xor(u8 *d, const u8 *s, u32 len, const u8 k[32], const u8 iv[12])
{
	u32 blocks = len / 64 + !!(len % 64), h;
	for (h = 0; h < 8; h++)
		npu_chacha20_xor_range(d, s, len, k, iv, blocks * h / 8,
				       blocks * (h + 1) / 8);
}
static void parallel_poly(u8 tag[16], const u8 key[32], const u8 *aad,
			  u32 aad_len, const u8 *data, u32 len)
{
	u32 blocks = aad_len / 16 + !!(aad_len % 16) + len / 16 + !!(len % 16) + 1;
	u32 parts[8][5], powers[8][5], lengths[8], h, first, end;
	for (h = 0; h < 8; h++) {
		first = blocks * h / 8;
		end = blocks * (h + 1) / 8;
		lengths[h] = end - first;
		npu_poly1305_segment(parts[h], key, aad, aad_len, data, len, first, end);
		npu_poly1305_power(powers[h], key, end - first);
	}
	npu_poly1305_combine(tag, key, parts, powers, lengths);
}
#else
struct crypto_job {
	u32 type;
	u8 *dst;
	const u8 *src, *key, *nonce, *aad;
	u32 aad_length, length, blocks;
};
struct crypto_group {
	volatile struct crypto_job job;
	u32 parts[8][5], powers[8][5];
	u8 poly_key[32];
	volatile u32 seq, done[6], ready[6];
};
static struct crypto_group group[GROUPS];
/* Three maximum-sized requests exceed the physical NPU SRAM. */
static u32 scratch[GROUPS][(SCRATCH_SIZE + 3) / 4]
	__attribute__((section(".scratch")));
#if defined(NPU_CRYPTO_QEMU) && !defined(NPU_CRYPTO_QEMU_MAILBOX)
volatile u32 npu_crypto_qemu_go;
u32 npu_crypto_qemu_ready(void)
{
	u32 h;
	for (h = 1; h < ACTIVE_HARTS; h++) {
		u32 g = h / HARTS_PER_PACKET, local = h % HARTS_PER_PACKET;
		if (g < GROUPS && local && !group[g].ready[local])
			return 0;
	}
	return 1;
}
#endif
static void fence_all(void) { __asm__ volatile("fence rw, rw" ::: "memory"); }
static void run_job(u32 g, u32 local)
{
	volatile struct crypto_job *j = &group[g].job;
	u32 first = j->blocks * local / HARTS_PER_PACKET;
	u32 end = j->blocks * (local + 1) / HARTS_PER_PACKET;
	if (!j->type)
		npu_chacha20_xor_range(j->dst, j->src, j->length, j->key,
				       j->nonce, first, end);
	else {
		npu_poly1305_segment(group[g].parts[local], j->key, j->aad,
				     j->aad_length, j->src, j->length, first, end);
		npu_poly1305_power(group[g].powers[local], j->key, end - first);
	}
}
void __attribute__((noreturn)) crypto_worker(u32 hart)
{
#if defined(NPU_CRYPTO_QEMU) && !defined(NPU_CRYPTO_QEMU_MAILBOX)
	while (!npu_crypto_qemu_go) ;
#else
	while (REG32(NPU_MIB(30)) != WORKERS_START) ;
#endif
	if (hart >= ACTIVE_HARTS || !(hart % HARTS_PER_PACKET))
		for (;;) ;
	{
		u32 g = hart / HARTS_PER_PACKET, local = hart % HARTS_PER_PACKET;
		u32 seen = 0, now;
		fence_all();
		group[g].ready[local] = 1;
		fence_all();
		for (;;) {
			now = group[g].seq;
			if (now == seen) continue;
			fence_all();
			run_job(g, local);
			fence_all();
			group[g].done[local] = now;
			seen = now;
		}
	}
}
static void dispatch(u32 g)
{
	u32 seq = group[g].seq + 1, h;
	fence_all();
	group[g].seq = seq;
	run_job(g, 0);
	for (h = 1; h < HARTS_PER_PACKET; h++)
		while (group[g].done[h] != seq) ;
	fence_all();
}
static void group_xor(u32 g, u8 *d, const u8 *s, u32 len,
		      const u8 key[32], const u8 iv[12])
{
	if (!len) return;
	group[g].job.type = 0; group[g].job.dst = d; group[g].job.src = s;
	group[g].job.key = key; group[g].job.nonce = iv; group[g].job.length = len;
	group[g].job.blocks = len / 64 + !!(len % 64);
	dispatch(g);
}
static void group_poly(u32 g, u8 tag[16], const u8 key[32], const u8 *aad,
		       u32 aad_len, const u8 *data, u32 len)
{
	u32 lengths[8], blocks, h, i;
	for (h = 0; h < 8; h++) lengths[h] = 0;
	for (i = 0; i < 32; i++) group[g].poly_key[i] = key[i];
	blocks = aad_len / 16 + !!(aad_len % 16) + len / 16 + !!(len % 16) + 1;
	for (h = 0; h < HARTS_PER_PACKET; h++)
		lengths[h] = blocks * (h + 1) / HARTS_PER_PACKET - blocks * h / HARTS_PER_PACKET;
	group[g].job.type = 1; group[g].job.key = group[g].poly_key;
	group[g].job.aad = aad; group[g].job.aad_length = aad_len;
	group[g].job.src = data; group[g].job.length = len; group[g].job.blocks = blocks;
	dispatch(g);
	npu_poly1305_combine(tag, group[g].poly_key, group[g].parts,
			    group[g].powers, lengths);
	for (i = 0; i < 32; i++) group[g].poly_key[i] = 0;
	for (i = 0; i < 40; i++) {
		((volatile u32 *)group[g].parts)[i] = 0;
		((volatile u32 *)group[g].powers)[i] = 0;
	}
}
#define CALLBACKS(n) \
static void xor_##n(u8 *d,const u8 *s,u32 l,const u8 k[32],const u8 iv[12]) \
{ group_xor(n,d,s,l,k,iv); } \
static void poly_##n(u8 t[16],const u8 k[32],const u8 *a,u32 al,const u8 *d,u32 l) \
{ group_poly(n,t,k,a,al,d,l); }
CALLBACKS(0)
#if GROUPS > 1
CALLBACKS(1)
#endif
#if GROUPS > 2
CALLBACKS(2)
#endif
static npu_crypto_xor_fn xor_fn[3] = { xor_0,
#if GROUPS > 1
 xor_1,
#else
 xor_0,
#endif
#if GROUPS > 2
 xor_2
#else
 xor_0
#endif
};
static npu_crypto_poly_fn poly_fn[3] = { poly_0,
#if GROUPS > 1
 poly_1,
#else
 poly_0,
#endif
#if GROUPS > 2
 poly_2
#else
 poly_0
#endif
};
#endif

static int copy_request(u32 g, volatile u32 *host, u32 length)
{
	volatile u8 *hb = (volatile u8 *)host;
	u32 *buffer;
	volatile u32 *clear;
	u8 *local;
	u32 words, i;
	int ret;
#if !defined(NPU_CRYPTO_TEST) && !defined(NPU_CRYPTO_QEMU_MAILBOX)
	/* The NPU harts do not share coherent DRAM caches. Use the host-memory
	 * alias for every access, including reads and writes by worker harts. */
	buffer = (u32 *)(((u32)scratch[g] & 0x3fffffff) | 0x40000000);
#else
	buffer = scratch[g];
#endif
	clear = buffer;
	local = (u8 *)buffer;
	if (length < sizeof(struct npu_crypto_request) || length > SCRATCH_SIZE)
		return 0;
	words = length / 4;
	for (i = 0; i < words; i++) buffer[i] = host[i];
	for (i = words * 4; i < length; i++) local[i] = hb[i];
#if defined(NPU_CRYPTO_TEST) && !defined(NPU_CRYPTO_QEMU)
	ret = npu_crypto_process_with_workers(buffer, length, parallel_xor, parallel_poly);
#else
	ret = npu_crypto_process_with_workers(buffer, length, xor_fn[g], poly_fn[g]);
#endif
	if (ret == 1) {
		for (i = 0; i < words; i++) host[i] = buffer[i];
		for (i = words * 4; i < length; i++) hb[i] = local[i];
	}
	for (i = 0; i < (length + 3) / 4; i++) clear[i] = 0;
	return ret;
}
#ifdef NPU_CRYPTO_TEST
int npu_crypto_test_request(void *host, u32 length) { return copy_request(0, host, length); }
int npu_crypto_test_request_group(u32 g, void *host, u32 length)
{
	if (g >= GROUPS) return 0;
	return copy_request(g, host, length);
}
int npu_crypto_test_scratch_clear(void)
{
	u32 i;
	for (i = 0; i < sizeof(scratch[0]) / sizeof(scratch[0][0]); i++)
		if (scratch[0][i]) return 0;
	return 1;
}
#else
static int crypto_request(u32 g, u32 base, u32 len)
{
#ifdef NPU_CRYPTO_QEMU_MAILBOX
	return copy_request(g, (volatile u32 *)base, len);
#else
	if ((base & 3) || len > 0x40000000 - (base & 0x3fffffff)) return 0;
	return copy_request(g, (volatile u32 *)((base & 0x3fffffff) | 0x40000000), len);
#endif
}
static void __attribute__((noreturn)) service_group(u32 g)
{
	u32 queue = AIROHA_CRYPTO_NPU_QUEUE(g);
	u32 seq = REG32(MBQ_CTRL2(queue)), start, h, other;
	if (!g) REG32(NPU_MIB(30)) = WORKERS_START;
	else while (REG32(NPU_MIB(30)) != WORKERS_START) ;
	start = csr_read(mcycle);
	for (h = 1; h < HARTS_PER_PACKET; h++)
		while (!group[g].ready[h])
			if ((u32)csr_read(mcycle) - start > 200000000) for (;;) ;
	fence_all();
	for (other = 0; other < GROUPS; other++)
		for (h = 1; h < HARTS_PER_PACKET; h++)
			while (!group[other].ready[h]) ;
	REG32(NPU_MIB31) = CRYPTO_READY;
	for (;;) {
		u32 now = REG32(MBQ_CTRL2(queue)), arg, ret;
		if (now == seq) continue;
		seq = now;
		__asm__ volatile("fence iorw, iorw" ::: "memory");
		arg = REG32(MBQ_CTRL3(queue)); ret = 0;
		if ((arg & 0x7821) == 1)
			ret = crypto_request(g, REG32(MBQ_CTRL0(queue)), REG32(MBQ_CTRL1(queue)) & 0xffff);
		__asm__ volatile("fence iorw, iorw" ::: "memory");
		REG32(MBQ_CTRL3(queue)) = (arg & ~0x1cu) | (ret << 2) | 2;
	}
}
void __attribute__((noreturn)) crypto_service(u32 hart)
{
	u32 g;
	if (hart >= ACTIVE_HARTS) for (;;) ;
	g = hart / HARTS_PER_PACKET;
	if (hart % HARTS_PER_PACKET) crypto_worker(hart);
	service_group(g);
}
#endif
