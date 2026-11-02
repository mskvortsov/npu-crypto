/* SPDX-License-Identifier: GPL-2.0-only */
#include "npu_types.h"
#include "npu_regs.h"
#include "npu_crypto.h"

#define CRYPTO_SCRATCH_SIZE (NPU_CRYPTO_MAX_DATA + sizeof(struct npu_crypto_request_aad))

static u32 scratch[(CRYPTO_SCRATCH_SIZE + 3) / 4];

#if defined(NPU_CRYPTO_TEST) && !defined(NPU_CRYPTO_QEMU)
static void crypto_parallel_xor(u8 *dst, const u8 *src, u32 len,
				const u8 key[32], const u8 nonce[12])
{
	u32 blocks = len / 64 + !!(len % 64), hart;

	for (hart = 0; hart < 8; hart++)
		npu_chacha20_xor_range(dst, src, len, key, nonce,
				       blocks * hart / 8,
				       blocks * (hart + 1) / 8);
}

static void crypto_parallel_poly(u8 tag[16], const u8 key[32], const u8 *aad,
				 u32 aad_len, const u8 *data, u32 len)
{
	u32 blocks = aad_len / 16 + !!(aad_len % 16) +
		     len / 16 + !!(len % 16) + 1;
	u32 parts[8][5], powers[8][5], lengths[8], hart, first, end;

	for (hart = 0; hart < 8; hart++) {
		first = blocks * hart / 8;
		end = blocks * (hart + 1) / 8;
		lengths[hart] = end - first;
		npu_poly1305_segment(parts[hart], key, aad, aad_len, data, len,
				     first, end);
		npu_poly1305_power(powers[hart], key, end - first);
	}
	npu_poly1305_combine(tag, key, parts, powers, lengths);
}
#else
struct crypto_job {
	u32 type;
	u8 *dst;
	const u8 *src;
	const u8 *key;
	const u8 *nonce;
	const u8 *aad;
	u32 aad_length;
	u32 length;
	u32 blocks;
};

static volatile struct crypto_job job;
static u32 poly_parts[8][5];
static u32 poly_powers[8][5];
static u8 shared_poly_key[32];
static volatile u32 job_sequence;
static volatile u32 job_done[8];
static volatile u32 worker_ready[8];

#define CRYPTO_WORKERS_START 0x43525731
#define CRYPTO_READY 0x43525931

#ifdef NPU_CRYPTO_QEMU
volatile u32 npu_crypto_qemu_go;

u32 npu_crypto_qemu_ready(void)
{
	u32 hart;

	for (hart = 1; hart < 8; hart++)
		if (!worker_ready[hart])
			return 0;
	return 1;
}
#endif

static void crypto_fence(void)
{
	__asm__ volatile("fence rw, rw" ::: "memory");
}

static void crypto_job_run(u32 hart)
{
	u32 first = job.blocks * hart / 8;
	u32 end = job.blocks * (hart + 1) / 8;

	if (job.type == 0)
		npu_chacha20_xor_range(job.dst, job.src, job.length, job.key,
				       job.nonce, first, end);
	else {
		npu_poly1305_segment(poly_parts[hart], job.key, job.aad,
				     job.aad_length, job.src, job.length,
				     first, end);
		npu_poly1305_power(poly_powers[hart], job.key, end - first);
	}
}

void __attribute__((noreturn)) crypto_worker(u32 hart)
{
	u32 seen = 0, current;

	while (
#ifdef NPU_CRYPTO_QEMU
	       !npu_crypto_qemu_go
#else
	       REG32(NPU_MIB(30)) != CRYPTO_WORKERS_START
#endif
	      )
		;
	crypto_fence();
	worker_ready[hart] = 1;
	crypto_fence();
	for (;;) {
		current = job_sequence;
		if (current == seen)
			continue;
		crypto_fence();
		crypto_job_run(hart);
		crypto_fence();
		job_done[hart] = current;
		seen = current;
	}
}

static void crypto_dispatch_job(void)
{
	u32 seq, hart;

	seq = job_sequence + 1;
	crypto_fence();
	job_sequence = seq;
	crypto_job_run(0);
	for (hart = 1; hart < 8; hart++)
		while (job_done[hart] != seq)
			;
	crypto_fence();
}

static void crypto_parallel_xor(u8 *dst, const u8 *src, u32 len,
				const u8 key[32], const u8 nonce[12])
{
	if (!len)
		return;
	job.type = 0;
	job.dst = dst;
	job.src = src;
	job.key = key;
	job.nonce = nonce;
	job.length = len;
	job.blocks = len / 64 + !!(len % 64);
	crypto_dispatch_job();
}

static void crypto_parallel_poly(u8 tag[16], const u8 key[32], const u8 *aad,
				 u32 aad_len, const u8 *data, u32 len)
{
	u32 lengths[8], blocks, hart, i;
	volatile u8 *clear_key = shared_poly_key;
	volatile u32 *clear_parts = &poly_parts[0][0];
	volatile u32 *clear_powers = &poly_powers[0][0];

	for (i = 0; i < 32; i++)
		shared_poly_key[i] = key[i];
	blocks = aad_len / 16 + !!(aad_len % 16) +
		 len / 16 + !!(len % 16) + 1;
	for (hart = 0; hart < 8; hart++)
		lengths[hart] = blocks * (hart + 1) / 8 - blocks * hart / 8;
	job.type = 1;
	job.key = shared_poly_key;
	job.aad = aad;
	job.aad_length = aad_len;
	job.src = data;
	job.length = len;
	job.blocks = blocks;
	crypto_dispatch_job();
	npu_poly1305_combine(tag, shared_poly_key, poly_parts, poly_powers, lengths);
	for (i = 0; i < 32; i++)
		clear_key[i] = 0;
	for (i = 0; i < 8 * 5; i++) {
		clear_parts[i] = 0;
		clear_powers[i] = 0;
	}
}
#endif

static int crypto_copy_request(volatile u32 *host, u32 length)
{
	volatile u8 *host_bytes = (volatile u8 *)host;
	volatile u32 *clear = scratch;
	u8 *local_bytes = (u8 *)scratch;
	u32 words, i;
	int ret;

	if (length < sizeof(struct npu_crypto_request) ||
	    length > CRYPTO_SCRATCH_SIZE)
		return 0;
	words = length / 4;
	for (i = 0; i < words; i++)
		scratch[i] = host[i];
	for (i = words * 4; i < length; i++)
		local_bytes[i] = host_bytes[i];
	ret = npu_crypto_process_with_workers(scratch, length, crypto_parallel_xor,
					      crypto_parallel_poly);
	if (ret == 1) {
		for (i = 0; i < words; i++)
			host[i] = scratch[i];
		for (i = words * 4; i < length; i++)
			host_bytes[i] = local_bytes[i];
	}
	for (i = 0; i < (length + 3) / 4; i++)
		clear[i] = 0;
	return ret;
}

#ifdef NPU_CRYPTO_TEST
int npu_crypto_test_request(void *host, u32 length)
{
	return crypto_copy_request(host, length);
}

int npu_crypto_test_scratch_clear(void)
{
	u32 i;

	for (i = 0; i < sizeof(scratch) / sizeof(scratch[0]); i++)
		if (scratch[i])
			return 0;
	return 1;
}
#else
static int crypto_request(u32 base, u32 length)
{
	if ((base & 3) || length > 0x40000000 - (base & 0x3fffffff))
		return 0;
	return crypto_copy_request((volatile u32 *)((base & 0x3fffffff) |
						   0x40000000), length);
}

/* The host owns queue 0 and writes the doorbell after the other registers. */
void __attribute__((noreturn)) crypto_service(void)
{
	u32 seq = REG32(MBQ_CTRL2(0));
	u32 start, hart;

	crypto_fence();
	REG32(NPU_MIB(30)) = CRYPTO_WORKERS_START;
	start = csr_read(mcycle);
	for (hart = 1; hart < 8; hart++) {
		while (!worker_ready[hart]) {
			if ((u32)csr_read(mcycle) - start > 200000000)
				for (;;)
					;
		}
	}
	crypto_fence();
	REG32(NPU_MIB31) = CRYPTO_READY;
	for (;;) {
		u32 now = REG32(MBQ_CTRL2(0));
		u32 arg, ret;

		if (now == seq)
			continue;
		seq = now;
		__asm__ volatile("fence iorw, iorw" ::: "memory");
		arg = REG32(MBQ_CTRL3(0));
		ret = 0;
		if ((arg & 0x7821) == 1)
			ret = crypto_request(REG32(MBQ_CTRL0(0)),
					     REG32(MBQ_CTRL1(0)) & 0xffff);
		__asm__ volatile("fence iorw, iorw" ::: "memory");
		REG32(MBQ_CTRL3(0)) = (arg & ~0x1cu) | (ret << 2) | 2;
	}
}
#endif
