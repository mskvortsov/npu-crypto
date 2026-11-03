/* SPDX-License-Identifier: GPL-2.0-only */
#include "npu_types.h"
#include "npu_regs.h"
#include "npu_crypto.h"
#include "npu_crypto_profile.h"

#define GROUPS AIROHA_CRYPTO_NPU_BATCH_SIZE
#define HARTS_PER_PACKET AIROHA_CRYPTO_NPU_HARTS_PER_PACKET
#define ACTIVE_HARTS 8
#define WORKERS_START 0x43525731
#define CRYPTO_READY 0x43525931

/* CTRL3 command validation checks bit 0, bit 5 and bits 14:11.
 * Completion/status and optional profiling/interrupt bits are excluded. */
#define CRYPTO_COMMAND_MASK 0x7821u
#define CRYPTO_COMMAND_REQUEST 1u
#define CRYPTO_DMA_ALIGNMENT 4u
/* Host addresses select an offset in a 1 GiB uncached NPU window. */
#define CRYPTO_DMA_WINDOW_SIZE 0x40000000u
#define CRYPTO_DMA_OFFSET_MASK (CRYPTO_DMA_WINDOW_SIZE - 1)
#define CRYPTO_DMA_WINDOW_BASE 0x40000000u

#if defined(NPU_CRYPTO_TEST) && !defined(NPU_CRYPTO_QEMU)
static void parallel_xor(u8 *d, const u8 *s, u32 len, const u8 k[32],
			 const u8 iv[12])
{
	u32 blocks = len / 64 + !!(len % 64), h;
	for (h = 0; h < 8; h++)
		npu_chacha20_xor_range(d, s, len, k, iv, blocks * h / 8,
				       blocks * (h + 1) / 8);
}
static void parallel_poly(u8 tag[16], const u8 key[32], const u8 *aad,
			  u32 aad_len, const u8 *data, u32 len)
{
	u32 blocks =
		aad_len / 16 + !!(aad_len % 16) + len / 16 + !!(len % 16) + 1;
	u32 parts[8][5], powers[8][5], lengths[8], h, first, end;
	for (h = 0; h < 8; h++) {
		first = blocks * h / 8;
		end = blocks * (h + 1) / 8;
		lengths[h] = end - first;
		npu_poly1305_segment(parts[h], key, aad, aad_len, data, len,
				     first, end);
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
	volatile u32 seq, done[8], ready[8];
	u32 profiling;
	struct airoha_profile_sample sample;
};
static struct crypto_group group[GROUPS];
static volatile u32 leader_ready[GROUPS];
/* The hardware mutex register address aliases hart pairs 0/4 through 3/7.
 * Serialize each pair before either attempts the shared hardware mutex. */
static volatile u32 notify_pair_want[4][2], notify_pair_turn[4];
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
static void fence_all(void)
{
	__asm__ volatile("fence rw, rw" ::: "memory");
}
/* The first portion does not calculate a power. Tune its share for the
 * number of harts, accounting for that extra work on the other portions. */
static u32 poly_boundary(u32 blocks, u32 portion)
{
#if HARTS_PER_PACKET >= 4
	if (!portion)
		return 0;
	return blocks * (portion + 1) / (HARTS_PER_PACKET + 1);
#elif HARTS_PER_PACKET == 2
	if (!portion)
		return 0;
	return portion == 1 ? blocks * 3 / 5 : blocks;
#else
	return blocks * portion / HARTS_PER_PACKET;
#endif
}
static void run_job(u32 g, u32 local)
{
	volatile struct crypto_job *j = &group[g].job;
	u32 first = j->blocks * local / HARTS_PER_PACKET;
	u32 end = j->blocks * (local + 1) / HARTS_PER_PACKET;
	if (!j->type)
		npu_chacha20_xor_range(j->dst, j->src, j->length, j->key,
				       j->nonce, first, end);
	else {
		first = poly_boundary(j->blocks, local);
		end = poly_boundary(j->blocks, local + 1);
		npu_poly1305_segment(group[g].parts[local], j->key, j->aad,
				     j->aad_length, j->src, j->length, first,
				     end);
		/* The combiner starts with portion zero and never uses
		 * r^len[0]. */
		if (local)
			npu_poly1305_power(group[g].powers[local], j->key,
					   end - first);
	}
}
void __attribute__((noreturn)) crypto_worker(u32 hart)
{
#if defined(NPU_CRYPTO_QEMU) && !defined(NPU_CRYPTO_QEMU_MAILBOX)
	while (!npu_crypto_qemu_go)
		;
#else
	while (REG32(NPU_MIB(30)) != WORKERS_START)
		;
#endif
	if (hart >= ACTIVE_HARTS || !(hart % HARTS_PER_PACKET)) {
		/* Park harts that cannot participate as workers. */
		for (;;) {
		}
	}
	{
		u32 g = hart / HARTS_PER_PACKET,
		    local = hart % HARTS_PER_PACKET;
		u32 seen = 0, now;
		fence_all();
		group[g].ready[local] = 1;
		fence_all();
		for (;;) {
			now = group[g].seq;
			if (now == seen)
				continue;
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
	u32 seq = group[g].seq + 1, h, start = 0, middle = 0, end;
	if (group[g].profiling)
		start = csr_read(mcycle);
	fence_all();
	group[g].seq = seq;
	run_job(g, 0);
	if (group[g].profiling)
		middle = csr_read(mcycle);
	for (h = 1; h < HARTS_PER_PACKET; h++)
		while (group[g].done[h] != seq)
			;
	fence_all();
	if (group[g].profiling) {
		end = csr_read(mcycle);
		if (group[g].job.type) {
			group[g].sample.poly_leader += middle - start;
			group[g].sample.poly_wait += end - middle;
		} else {
			group[g].sample.chacha_leader += middle - start;
			group[g].sample.chacha_wait += end - middle;
		}
	}
}
static void group_xor(u32 g, u8 *d, const u8 *s, u32 len, const u8 key[32],
		      const u8 iv[12])
{
	u32 start = 0;
	if (!len)
		return;
	if (group[g].profiling)
		start = csr_read(mcycle);
	group[g].job.type = 0;
	group[g].job.dst = d;
	group[g].job.src = s;
	group[g].job.key = key;
	group[g].job.nonce = iv;
	group[g].job.length = len;
	group[g].job.blocks = len / 64 + !!(len % 64);
	dispatch(g);
	if (group[g].profiling)
		group[g].sample.chacha += (u32)csr_read(mcycle) - start;
}
static void group_poly(u32 g, u8 tag[16], const u8 key[32], const u8 *aad,
		       u32 aad_len, const u8 *data, u32 len)
{
	u32 lengths[8], blocks, h, i, start = 0;
	if (group[g].profiling)
		start = csr_read(mcycle);
	for (h = 0; h < 8; h++)
		lengths[h] = 0;
	for (i = 0; i < 32; i++)
		group[g].poly_key[i] = key[i];
	blocks = aad_len / 16 + !!(aad_len % 16) + len / 16 + !!(len % 16) + 1;
	for (h = 0; h < HARTS_PER_PACKET; h++)
		lengths[h] =
			poly_boundary(blocks, h + 1) - poly_boundary(blocks, h);
	group[g].job.type = 1;
	group[g].job.key = group[g].poly_key;
	group[g].job.aad = aad;
	group[g].job.aad_length = aad_len;
	group[g].job.src = data;
	group[g].job.length = len;
	group[g].job.blocks = blocks;
	dispatch(g);
	npu_poly1305_combine(tag, group[g].poly_key, group[g].parts,
			     group[g].powers, lengths);
	for (i = 0; i < 32; i++)
		group[g].poly_key[i] = 0;
	for (i = 0; i < 40; i++) {
		((volatile u32 *)group[g].parts)[i] = 0;
		((volatile u32 *)group[g].powers)[i] = 0;
	}
	if (group[g].profiling)
		group[g].sample.poly += (u32)csr_read(mcycle) - start;
}
#define CALLBACKS(n)                                                           \
	static void xor_##n(u8 *d, const u8 *s, u32 l, const u8 k[32],         \
			    const u8 iv[12])                                   \
	{                                                                      \
		group_xor(n, d, s, l, k, iv);                                  \
	}                                                                      \
	static void poly_##n(u8 t[16], const u8 k[32], const u8 *a, u32 al,    \
			     const u8 *d, u32 l)                               \
	{                                                                      \
		group_poly(n, t, k, a, al, d, l);                              \
	}
CALLBACKS(0)
#if GROUPS > 1
CALLBACKS(1)
#endif
#if GROUPS > 2
CALLBACKS(2)
CALLBACKS(3)
#endif
#if GROUPS > 4
CALLBACKS(4)
CALLBACKS(5)
CALLBACKS(6)
CALLBACKS(7)
#endif
static npu_crypto_xor_fn xor_fn[GROUPS] = {
	xor_0,
#if GROUPS > 1
	xor_1,
#endif
#if GROUPS > 2
	xor_2, xor_3,
#endif
#if GROUPS > 4
	xor_4, xor_5, xor_6, xor_7,
#endif
};
static npu_crypto_poly_fn poly_fn[GROUPS] = {
	poly_0,
#if GROUPS > 1
	poly_1,
#endif
#if GROUPS > 2
	poly_2, poly_3,
#endif
#if GROUPS > 4
	poly_4, poly_5, poly_6, poly_7,
#endif
};
#endif

/* The host retains each DMA slot until completion and clears it afterwards. */
static int process_request(u32 g, void *buffer, u32 length)
{
	if (length < sizeof(struct npu_crypto_request) ||
	    length > AIROHA_CRYPTO_MAX_REQUEST)
		return 0;
#if defined(NPU_CRYPTO_TEST) && !defined(NPU_CRYPTO_QEMU)
	(void)g;
	return npu_crypto_process_with_workers(buffer, length, parallel_xor,
					       parallel_poly);
#else
	return npu_crypto_process_with_workers(buffer, length, xor_fn[g],
					       poly_fn[g]);
#endif
}
#ifdef NPU_CRYPTO_TEST
int npu_crypto_test_request(void *host, u32 length)
{
	return process_request(0, host, length);
}
int npu_crypto_test_request_group(u32 g, void *host, u32 length)
{
	if (g >= GROUPS)
		return 0;
	return process_request(g, host, length);
}
#else
static int crypto_request(u32 g, u32 base, u32 len)
{
#ifdef NPU_CRYPTO_QEMU_MAILBOX
	return process_request(g, (void *)base, len);
#else
	if ((base & (CRYPTO_DMA_ALIGNMENT - 1)) ||
	    len > CRYPTO_DMA_WINDOW_SIZE - (base & CRYPTO_DMA_OFFSET_MASK))
		return 0;
	return process_request(g,
			       (void *)((base & CRYPTO_DMA_OFFSET_MASK) |
					CRYPTO_DMA_WINDOW_BASE),
			       len);
#endif
}

/* Queue 8 is shared by packet leaders. Keep it owned until Linux acks it. */
static void notify_host(u32 hart)
{
	u32 pair = hart & 3, side = hart >> 2;
	notify_pair_want[pair][side] = 1;
	fence_all();
	notify_pair_turn[pair] = 1 - side;
	fence_all();
	while (notify_pair_want[pair][1 - side] &&
	       notify_pair_turn[pair] == 1 - side)
		;
	fence_all();
#ifdef NPU_CRYPTO_QEMU_MAILBOX
	extern volatile u32 npu_qemu_notify_lock;
	while (__sync_lock_test_and_set(&npu_qemu_notify_lock, 1))
		;
#else
	u32 off = (30 * 4) & HW_MUTEX_OFF_MASK, status;
	do {
		REG32(HW_MUTEX_ACQ(off)) = (hart << 8) | 0x40;
		status = REG32(HW_MUTEX_STATUS(hart, off));
	} while (!(status & HW_MUTEX_HELD) || ((status >> 8) & 0xff) != hart);
#endif
	REG32(MBQ_CTRL0(MBQ_NOTIFY)) = hart;
	REG32(MBQ_CTRL1(MBQ_NOTIFY)) = 0;
	REG32(MBQ_CTRL3(MBQ_NOTIFY)) = 0;
	__asm__ volatile("fence iorw, iorw" ::: "memory");
	REG32(MBQ_CTRL2(MBQ_NOTIFY)) = REG32(MBQ_CTRL2(MBQ_NOTIFY)) + 1;
	while (!(REG32(MBQ_CTRL3(MBQ_NOTIFY)) & 2))
		;
#ifdef NPU_CRYPTO_QEMU_MAILBOX
	__sync_lock_release(&npu_qemu_notify_lock);
#else
	REG32(HW_MUTEX_REL(hart, off)) = hart << 8;
#endif
	fence_all();
	notify_pair_want[pair][side] = 0;
}
static void __attribute__((noreturn)) service_group(u32 g)
{
	u32 queue = AIROHA_CRYPTO_NPU_QUEUE(g);
	u32 seq = REG32(MBQ_CTRL2(queue)), start, h, other;
	if (!g)
		REG32(NPU_MIB(30)) = WORKERS_START;
	else
		while (REG32(NPU_MIB(30)) != WORKERS_START)
			;
	start = csr_read(mcycle);
	for (h = 1; h < HARTS_PER_PACKET; h++)
		while (!group[g].ready[h])
			if ((u32)csr_read(mcycle) - start > 200000000)
				for (;;)
					;
	fence_all();
	for (other = 0; other < GROUPS; other++)
		for (h = 1; h < HARTS_PER_PACKET; h++)
			while (!group[other].ready[h])
				;
	leader_ready[g] = 1;
	fence_all();
	for (other = 0; other < GROUPS; other++)
		while (!leader_ready[other])
			;
	fence_all();
	REG32(NPU_MIB31) = CRYPTO_READY;
	for (;;) {
		u32 now = REG32(MBQ_CTRL2(queue)), arg, ret, base, len, valid,
		    t = 0, i;
		if (now == seq)
			continue;
		seq = now;
		__asm__ volatile("fence iorw, iorw" ::: "memory");
		arg = REG32(MBQ_CTRL3(queue));
		ret = 0;
		base = REG32(MBQ_CTRL0(queue));
		len = REG32(MBQ_CTRL1(queue)) & 0xffff;
		valid = (arg & CRYPTO_COMMAND_MASK) == CRYPTO_COMMAND_REQUEST &&
			!(base & (CRYPTO_DMA_ALIGNMENT - 1)) &&
			len <= CRYPTO_DMA_WINDOW_SIZE -
					(base & CRYPTO_DMA_OFFSET_MASK);
		group[g].profiling = !!(arg & AIROHA_PROFILE_FLAG);
		/* Validate the complete trailer before any profiled DMA access.
		 */
		if (group[g].profiling &&
		    (len > AIROHA_PROFILE_OFFSET ||
		     AIROHA_PROFILE_OFFSET + sizeof(group[g].sample) >
			     CRYPTO_DMA_WINDOW_SIZE -
				     (base & CRYPTO_DMA_OFFSET_MASK)))
			valid = 0;
		if (group[g].profiling) {
			u32 *p = (u32 *)&group[g].sample;
			for (i = 0; i < sizeof(group[g].sample) / 4; i++)
				p[i] = 0;
			t = csr_read(mcycle);
		}
		if (valid)
			ret = crypto_request(g, base, len);
		if (valid && group[g].profiling) {
			volatile u32 *dst;
			u32 *src = (u32 *)&group[g].sample;
			group[g].sample.total = (u32)csr_read(mcycle) - t;
#ifdef NPU_CRYPTO_QEMU_MAILBOX
			dst = (volatile u32 *)(base + AIROHA_PROFILE_OFFSET);
#else
			dst = (volatile u32 *)(((base &
						 CRYPTO_DMA_OFFSET_MASK) |
						CRYPTO_DMA_WINDOW_BASE) +
					       AIROHA_PROFILE_OFFSET);
#endif
			for (i = 0; i < sizeof(group[g].sample) / 4; i++)
				dst[i] = src[i];
		}
		__asm__ volatile("fence iorw, iorw" ::: "memory");
		REG32(MBQ_CTRL3(queue)) = (arg & ~0x1cu) | (ret << 2) | 2;
		if (arg & AIROHA_INTERRUPT_FLAG) {
			__asm__ volatile("fence iorw, iorw" ::: "memory");
			notify_host(g * HARTS_PER_PACKET);
		}
	}
}
void __attribute__((noreturn)) crypto_service(u32 hart)
{
	u32 g;
	if (hart >= ACTIVE_HARTS)
		for (;;)
			;
	g = hart / HARTS_PER_PACKET;
	if (hart % HARTS_PER_PACKET)
		crypto_worker(hart);
	service_group(g);
}
#endif
