// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights
 * Reserved.
 *
 * This is based in part on Andrew Moon's poly1305-donna, which is in the
 * public domain.
 */

#include "npu_crypto.h"

static u32 get_unaligned_le32(const u8 *p)
{
	return (u32)p[0] | (u32)p[1] << 8 | (u32)p[2] << 16 | (u32)p[3] << 24;
}

static void put_unaligned_le32(u32 v, u8 *p)
{
	p[0] = v;
	p[1] = v >> 8;
	p[2] = v >> 16;
	p[3] = v >> 24;
}

struct poly1305_internal {
	u32 h[5];
	u32 r[5];
	u32 s[4];
};

static void poly1305_init_generic(void *ctx, const u8 key[16])
{
	struct poly1305_internal *st = (struct poly1305_internal *)ctx;

	/* r &= 0xffffffc0ffffffc0ffffffc0fffffff */
	st->r[0] = (get_unaligned_le32(&key[0])) & 0x3ffffff;
	st->r[1] = (get_unaligned_le32(&key[3]) >> 2) & 0x3ffff03;
	st->r[2] = (get_unaligned_le32(&key[6]) >> 4) & 0x3ffc0ff;
	st->r[3] = (get_unaligned_le32(&key[9]) >> 6) & 0x3f03fff;
	st->r[4] = (get_unaligned_le32(&key[12]) >> 8) & 0x00fffff;

	/* s = 5*r */
	st->s[0] = st->r[1] * 5;
	st->s[1] = st->r[2] * 5;
	st->s[2] = st->r[3] * 5;
	st->s[3] = st->r[4] * 5;

	/* h = 0 */
	st->h[0] = 0;
	st->h[1] = 0;
	st->h[2] = 0;
	st->h[3] = 0;
	st->h[4] = 0;
}

static void poly1305_blocks_generic(void *ctx, const u8 *input, u32 len,
				    const u32 padbit)
{
	struct poly1305_internal *st = (struct poly1305_internal *)ctx;
	const u32 hibit = padbit << 24;
	u32 r0, r1, r2, r3, r4;
	u32 s1, s2, s3, s4;
	u32 h0, h1, h2, h3, h4;
	u64 d0, d1, d2, d3, d4;
	u32 c;

	r0 = st->r[0];
	r1 = st->r[1];
	r2 = st->r[2];
	r3 = st->r[3];
	r4 = st->r[4];

	s1 = st->s[0];
	s2 = st->s[1];
	s3 = st->s[2];
	s4 = st->s[3];

	h0 = st->h[0];
	h1 = st->h[1];
	h2 = st->h[2];
	h3 = st->h[3];
	h4 = st->h[4];

	while (len >= 16) {
		/* h += m[i] */
		h0 += (get_unaligned_le32(&input[0])) & 0x3ffffff;
		h1 += (get_unaligned_le32(&input[3]) >> 2) & 0x3ffffff;
		h2 += (get_unaligned_le32(&input[6]) >> 4) & 0x3ffffff;
		h3 += (get_unaligned_le32(&input[9]) >> 6) & 0x3ffffff;
		h4 += (get_unaligned_le32(&input[12]) >> 8) | hibit;

		/* h *= r */
		d0 = ((u64)h0 * r0) + ((u64)h1 * s4) + ((u64)h2 * s3) +
		     ((u64)h3 * s2) + ((u64)h4 * s1);
		d1 = ((u64)h0 * r1) + ((u64)h1 * r0) + ((u64)h2 * s4) +
		     ((u64)h3 * s3) + ((u64)h4 * s2);
		d2 = ((u64)h0 * r2) + ((u64)h1 * r1) + ((u64)h2 * r0) +
		     ((u64)h3 * s4) + ((u64)h4 * s3);
		d3 = ((u64)h0 * r3) + ((u64)h1 * r2) + ((u64)h2 * r1) +
		     ((u64)h3 * r0) + ((u64)h4 * s4);
		d4 = ((u64)h0 * r4) + ((u64)h1 * r3) + ((u64)h2 * r2) +
		     ((u64)h3 * r1) + ((u64)h4 * r0);

		/* (partial) h %= p */
		c = (u32)(d0 >> 26);
		h0 = (u32)d0 & 0x3ffffff;
		d1 += c;
		c = (u32)(d1 >> 26);
		h1 = (u32)d1 & 0x3ffffff;
		d2 += c;
		c = (u32)(d2 >> 26);
		h2 = (u32)d2 & 0x3ffffff;
		d3 += c;
		c = (u32)(d3 >> 26);
		h3 = (u32)d3 & 0x3ffffff;
		d4 += c;
		c = (u32)(d4 >> 26);
		h4 = (u32)d4 & 0x3ffffff;
		h0 += c * 5;
		c = (h0 >> 26);
		h0 = h0 & 0x3ffffff;
		h1 += c;

		input += 16;
		len -= 16;
	}

	st->h[0] = h0;
	st->h[1] = h1;
	st->h[2] = h2;
	st->h[3] = h3;
	st->h[4] = h4;
}

static void poly1305_emit_generic(void *ctx, u8 mac[16], const u32 nonce[4])
{
	struct poly1305_internal *st = (struct poly1305_internal *)ctx;
	u32 h0, h1, h2, h3, h4, c;
	u32 g0, g1, g2, g3, g4;
	u64 f;
	u32 mask;

	/* fully carry h */
	h0 = st->h[0];
	h1 = st->h[1];
	h2 = st->h[2];
	h3 = st->h[3];
	h4 = st->h[4];

	c = h1 >> 26;
	h1 = h1 & 0x3ffffff;
	h2 += c;
	c = h2 >> 26;
	h2 = h2 & 0x3ffffff;
	h3 += c;
	c = h3 >> 26;
	h3 = h3 & 0x3ffffff;
	h4 += c;
	c = h4 >> 26;
	h4 = h4 & 0x3ffffff;
	h0 += c * 5;
	c = h0 >> 26;
	h0 = h0 & 0x3ffffff;
	h1 += c;

	/* compute h + -p */
	g0 = h0 + 5;
	c = g0 >> 26;
	g0 &= 0x3ffffff;
	g1 = h1 + c;
	c = g1 >> 26;
	g1 &= 0x3ffffff;
	g2 = h2 + c;
	c = g2 >> 26;
	g2 &= 0x3ffffff;
	g3 = h3 + c;
	c = g3 >> 26;
	g3 &= 0x3ffffff;
	g4 = h4 + c - (1UL << 26);

	/* select h if h < p, or h + -p if h >= p */
	mask = (g4 >> ((sizeof(u32) * 8) - 1)) - 1;
	g0 &= mask;
	g1 &= mask;
	g2 &= mask;
	g3 &= mask;
	g4 &= mask;
	mask = ~mask;

	h0 = (h0 & mask) | g0;
	h1 = (h1 & mask) | g1;
	h2 = (h2 & mask) | g2;
	h3 = (h3 & mask) | g3;
	h4 = (h4 & mask) | g4;

	/* h = h % (2^128) */
	h0 = ((h0) | (h1 << 26)) & 0xffffffff;
	h1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffff;
	h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
	h3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffff;

	/* mac = (h + nonce) % (2^128) */
	f = (u64)h0 + nonce[0];
	h0 = (u32)f;
	f = (u64)h1 + nonce[1] + (f >> 32);
	h1 = (u32)f;
	f = (u64)h2 + nonce[2] + (f >> 32);
	h2 = (u32)f;
	f = (u64)h3 + nonce[3] + (f >> 32);
	h3 = (u32)f;

	put_unaligned_le32(h0, &mac[0]);
	put_unaligned_le32(h1, &mac[4]);
	put_unaligned_le32(h2, &mac[8]);
	put_unaligned_le32(h3, &mac[12]);
}

static void clear_bytes(void *p, u32 len);

extern void ChaCha20_ctr32(u8 *dst, const u8 *src, u32 len, const u32 key[8],
			   const u32 counter[4]);

static void chacha_asm_xor(u8 *dst, const u8 *src, u32 len, const u8 key[32],
			   const u8 nonce[12], u32 counter)
{
	u32 key_words[8], state[4], i;

	if (!len)
		return;
	for (i = 0; i < 8; i++)
		key_words[i] = get_unaligned_le32(key + 4 * i);
	state[0] = counter;
	for (i = 0; i < 3; i++)
		state[i + 1] = get_unaligned_le32(nonce + 4 * i);
	ChaCha20_ctr32(dst, src, len, key_words, state);
	clear_bytes(key_words, sizeof(key_words));
	clear_bytes(state, sizeof(state));
}

static void chacha_block(u8 out[64], const u8 key[32], const u8 nonce[12],
			 u32 counter)
{
	static const u8 zero[64] = {0};

	chacha_asm_xor(out, zero, 64, key, nonce, counter);
}

static void poly_padded(struct poly1305_internal *st, const u8 *p, u32 len)
{
	u8 tail[16] = {0};
	u32 full = len & ~15u, i;

	poly1305_blocks_generic(st, p, full, 1);
	if (len != full) {
		for (i = 0; i < len - full; i++)
			tail[i] = p[full + i];
		poly1305_blocks_generic(st, tail, 16, 1);
	}
}

static void clear_bytes(void *p, u32 len)
{
	volatile u8 *v = p;

	while (len--)
		*v++ = 0;
}

/* Cryptogams RV32 uses four 32-bit words plus a high word for h, while the
 * parallel combiner uses five radix-2^26 limbs. */
struct segment_poly {
	u32 words[12];
};
extern int poly1305_init(void *ctx, const u8 key[16]);
extern void poly1305_blocks(void *ctx, const u8 *input, u32 len, u32 padbit);
static void segment_init(struct segment_poly *st, const u8 *key)
{
	/* The generator's unaligned-key path reads beyond the key. */
	u32 aligned_key[4];
	u32 i;
	for (i = 0; i < 16; i++)
		((u8 *)aligned_key)[i] = key[i];
	poly1305_init(st, (const u8 *)aligned_key);
	clear_bytes(aligned_key, sizeof(aligned_key));
}
static void segment_blocks(struct segment_poly *st, const u8 *p, u32 len)
{
	if (((unsigned long)p & 3) == 0) {
		poly1305_blocks(st, p, len, 1);
	} else {
		/* Avoid the assembly's aligned-down reads outside the input. */
		u32 block[4], i;
		while (len) {
			for (i = 0; i < 16; i++)
				((u8 *)block)[i] = p[i];
			poly1305_blocks(st, (const u8 *)block, 16, 1);
			p += 16;
			len -= 16;
		}
		clear_bytes(block, sizeof(block));
	}
}
static void segment_result(struct segment_poly *st, u32 out[5])
{
	u32 *h = st->words, carry, i;
	u64 sum;
	/* The assembly leaves the top word partially reduced. Fold all bits
	 * above bit 129 using 2^130 == 5 (mod 2^130 - 5). */
	sum = (u64)h[0] + (u64)(h[4] >> 2) * 5;
	h[0] = (u32)sum;
	carry = sum >> 32;
	for (i = 1; i < 4; i++) {
		sum = (u64)h[i] + carry;
		h[i] = (u32)sum;
		carry = sum >> 32;
	}
	h[4] = (h[4] & 3) + carry;
	out[0] = h[0] & 0x3ffffff;
	out[1] = ((h[0] >> 26) | (h[1] << 6)) & 0x3ffffff;
	out[2] = ((h[1] >> 20) | (h[2] << 12)) & 0x3ffffff;
	out[3] = ((h[2] >> 14) | (h[3] << 18)) & 0x3ffffff;
	out[4] = (h[3] >> 8) | (h[4] << 24);
}

static void segment_data(struct segment_poly *poly, const u8 *src, u32 len,
			 u32 *scratch, u32 scratch_len)
{
	u32 count, i;
	if (!scratch || scratch_len < 16) {
		segment_blocks(poly, src, len);
		return;
	}
	scratch_len &= ~15u;
	while (len) {
		count = len < scratch_len ? len : scratch_len;
		if (!((unsigned long)src & 3)) {
			const u32 *words = (const u32 *)src;
			for (i = 0; i < count / 4; i++)
				scratch[i] = words[i];
		} else {
			for (i = 0; i < count; i++)
				((u8 *)scratch)[i] = src[i];
		}
		segment_blocks(poly, (const u8 *)scratch, count);
		src += count;
		len -= count;
	}
}

void npu_poly1305_segment_buffered(u32 out[5], const u8 key[32], const u8 *aad,
				   u32 aad_len, const u8 *data, u32 len,
				   u32 first, u32 end, u32 *scratch,
				   u32 scratch_len)
{
	struct segment_poly poly;
	u8 block[16];
	u32 aad_blocks = aad_len / 16 + !!(aad_len % 16);
	u32 data_blocks = len / 16 + !!(len % 16);
	u32 index, offset, count, i;
	const u8 *src;

	segment_init(&poly, key);
	for (index = first; index < end;) {
		if (index < aad_len / 16) {
			count = aad_len / 16 - index;
			if (count > end - index)
				count = end - index;
			segment_blocks(&poly, aad + index * 16, count * 16);
			index += count;
			continue;
		}
		if (index >= aad_blocks && index - aad_blocks < len / 16) {
			offset = index - aad_blocks;
			count = len / 16 - offset;
			if (count > end - index)
				count = end - index;
			segment_data(&poly, data + offset * 16, count * 16,
				     scratch, scratch_len);
			index += count;
			continue;
		}
		for (i = 0; i < 16; i++)
			block[i] = 0;
		if (index < aad_blocks) {
			offset = index * 16;
			count = aad_len - offset;
			src = aad + offset;
		} else if (index < aad_blocks + data_blocks) {
			offset = (index - aad_blocks) * 16;
			count = len - offset;
			src = data + offset;
		} else {
			put_unaligned_le32(aad_len, block);
			put_unaligned_le32(len, block + 8);
			count = 0;
			src = block;
		}
		if (count > 16)
			count = 16;
		for (i = 0; i < count; i++)
			block[i] = src[i];
		segment_blocks(&poly, block, 16);
		index++;
	}
	segment_result(&poly, out);
	clear_bytes(&poly, sizeof(poly));
	clear_bytes(block, sizeof(block));
}

void npu_poly1305_segment(u32 out[5], const u8 key[32], const u8 *aad,
			  u32 aad_len, const u8 *data, u32 len, u32 first,
			  u32 end)
{
	npu_poly1305_segment_buffered(out, key, aad, aad_len, data, len, first,
				      end, 0, 0);
}

/* Multiply two field elements using the existing Poly1305 block operation. */
static void poly_field_mul(u32 out[5], const u32 a[5], const u32 b[5])
{
	struct poly1305_internal poly;
	const u8 zero[16] = {0};
	u32 i;

	for (i = 0; i < 5; i++) {
		poly.h[i] = a[i];
		poly.r[i] = b[i];
		if (i)
			poly.s[i - 1] = b[i] * 5;
	}
	poly1305_blocks_generic(&poly, zero, 16, 0);
	for (i = 0; i < 5; i++)
		out[i] = poly.h[i];
	clear_bytes(&poly, sizeof(poly));
}

static void poly_field_add(u32 out[5], const u32 b[5])
{
	u32 i, carry;

	for (i = 0; i < 5; i++)
		out[i] += b[i];
	for (i = 0; i < 4; i++) {
		carry = out[i] >> 26;
		out[i] &= 0x3ffffff;
		out[i + 1] += carry;
	}
	carry = out[4] >> 26;
	out[4] &= 0x3ffffff;
	out[0] += carry * 5;
	carry = out[0] >> 26;
	out[0] &= 0x3ffffff;
	out[1] += carry;
}

void npu_poly1305_power(u32 out[5], const u8 key[32], u32 exponent)
{
	struct poly1305_internal poly;
	u32 power[5], base[5], i;

	poly1305_init_generic(&poly, key);
	for (i = 0; i < 5; i++) {
		base[i] = poly.r[i];
		power[i] = i == 0;
	}
	while (exponent) {
		if (exponent & 1)
			poly_field_mul(power, power, base);
		exponent >>= 1;
		if (exponent)
			poly_field_mul(base, base, base);
	}
	for (i = 0; i < 5; i++)
		out[i] = power[i];
	clear_bytes(&poly, sizeof(poly));
	clear_bytes(power, sizeof(power));
	clear_bytes(base, sizeof(base));
}

void npu_poly1305_combine(u8 tag[16], const u8 key[32], const u32 parts[8][5],
			  const u32 powers[8][5], const u32 lengths[8])
{
	struct poly1305_internal poly;
	u32 acc[5] = {0}, pad[4];
	u32 hart, i, have_part = 0;

	for (hart = 0; hart < 8; hart++) {
		if (!lengths[hart])
			continue;
		if (have_part)
			poly_field_mul(acc, acc, powers[hart]);
		poly_field_add(acc, parts[hart]);
		have_part = 1;
	}
	for (i = 0; i < 5; i++)
		poly.h[i] = acc[i];
	for (i = 0; i < 4; i++)
		pad[i] = get_unaligned_le32(key + 16 + i * 4);
	poly1305_emit_generic(&poly, tag, pad);
	clear_bytes(&poly, sizeof(poly));
	clear_bytes(acc, sizeof(acc));
	clear_bytes(pad, sizeof(pad));
}

void npu_chacha20_xor_range(u8 *dst, const u8 *src, u32 len, const u8 key[32],
			    const u8 nonce[12], u32 first_block, u32 end_block)
{
	u32 first, end;

	if (!len || end_block <= first_block || first_block > (len - 1) / 64)
		return;
	first = first_block * 64;
	end = end_block > len / 64 ? len : end_block * 64;
	chacha_asm_xor(dst + first, src + first, end - first, key, nonce,
		       first_block + 1);
}

static void chacha_xor_serial(u8 *dst, const u8 *src, u32 len, const u8 key[32],
			      const u8 nonce[12])
{
	npu_chacha20_xor_range(dst, src, len, key, nonce, 0,
			       len / 64 + !!(len % 64));
}

static void poly_serial(u8 tag[16], const u8 key[32], const u8 *aad,
			u32 aad_len, const u8 *data, u32 len)
{
	struct poly1305_internal poly;
	u8 lengths[16] = {0};
	u32 pad[4], i;

	poly1305_init_generic(&poly, key);
	for (i = 0; i < 4; i++)
		pad[i] = get_unaligned_le32(key + 16 + 4 * i);
	poly_padded(&poly, aad, aad_len);
	poly_padded(&poly, data, len);
	put_unaligned_le32(aad_len, lengths);
	put_unaligned_le32(len, lengths + 8);
	poly1305_blocks_generic(&poly, lengths, 16, 1);
	poly1305_emit_generic(&poly, tag, pad);
	clear_bytes(&poly, sizeof(poly));
	clear_bytes(pad, sizeof(pad));
}

static int chacha20poly1305_with_xor(u8 *dst, const u8 *src, u32 len,
				     const u8 *aad, u32 aad_len,
				     const u8 key[32], const u8 nonce[12],
				     u8 tag[16], int decrypt,
				     npu_crypto_xor_fn xor_fn,
				     npu_crypto_poly_fn poly_fn)
{
	u8 block[64], actual[16];
	u32 i, diff = 0;

	chacha_block(block, key, nonce, 0);
	if (!decrypt)
		xor_fn(dst, src, len, key, nonce);
	poly_fn(actual, block, aad, aad_len, decrypt ? src : dst, len);
	if (decrypt) {
		for (i = 0; i < 16; i++)
			diff |= actual[i] ^ tag[i];
		if (!diff)
			xor_fn(dst, src, len, key, nonce);
	} else {
		for (i = 0; i < 16; i++)
			tag[i] = actual[i];
	}
	clear_bytes(block, sizeof(block));
	clear_bytes(actual, sizeof(actual));
	return diff ? -1 : 0;
}

int npu_chacha20poly1305(u8 *dst, const u8 *src, u32 len, const u8 *aad,
			 u32 aad_len, const u8 key[32], const u8 nonce[12],
			 u8 tag[16], int decrypt)
{
	return chacha20poly1305_with_xor(dst, src, len, aad, aad_len, key,
					 nonce, tag, decrypt, chacha_xor_serial,
					 poly_serial);
}

#if defined(AN7581) && defined(NOWIFI)
int npu_crypto_process_with_workers(void *buffer, u32 length,
				    npu_crypto_xor_fn xor_fn,
				    npu_crypto_poly_fn poly_fn)
{
	struct npu_crypto_request *req = buffer;
	struct npu_crypto_request_aad *req_aad = buffer;
	u32 size, op, aad_len = 0, header = sizeof(*req);
	u8 *data, *aad, *key, *nonce, *tag;
	int ret;

	if (!xor_fn || !poly_fn || length < sizeof(*req))
		return 0;
	size = req->length;
	op = req->operation;
	if (req->version == NPU_CRYPTO_VERSION_AAD) {
		header = sizeof(*req_aad);
		if (length < header)
			return 0;
		aad_len = req_aad->aad_length;
		aad = req_aad->data;
		key = req_aad->key;
		nonce = req_aad->nonce;
		tag = req_aad->tag;
	} else if (req->version == NPU_CRYPTO_VERSION) {
		aad = req->data;
		key = req->key;
		nonce = req->nonce;
		tag = req->tag;
	} else {
		return 0;
	}
	if (size > NPU_CRYPTO_MAX_DATA || op > NPU_CRYPTO_DECRYPT ||
	    aad_len > length - header || size > length - header - aad_len)
		return 0;
	data = aad + aad_len;
	ret = chacha20poly1305_with_xor(data, data, size, aad, aad_len, key,
					nonce, tag, op == NPU_CRYPTO_DECRYPT,
					xor_fn, poly_fn);
	return ret ? 2 : 1;
}

int npu_crypto_process_with_xor(void *buffer, u32 length,
				npu_crypto_xor_fn xor_fn)
{
	return npu_crypto_process_with_workers(buffer, length, xor_fn,
					       poly_serial);
}

int npu_crypto_process(void *buffer, u32 length)
{
	return npu_crypto_process_with_xor(buffer, length, chacha_xor_serial);
}

#ifndef NPU_CRYPTO_TEST
/* The host owns this uncached DMA buffer until completion. */
int npu_crypto_mail(u32 base, u32 length)
{
	void *buffer;
	int ret;

	if ((base & 3) || length < sizeof(struct npu_crypto_request) ||
	    length > 0x40000000 - (base & 0x3fffffff))
		return 0;
	buffer = (void *)((base & 0x3fffffff) | 0x40000000);
	__asm__ volatile("fence iorw, iorw" ::: "memory");
	ret = npu_crypto_process(buffer, length);
	__asm__ volatile("fence iorw, iorw" ::: "memory");
	return ret;
}
#endif
#endif
