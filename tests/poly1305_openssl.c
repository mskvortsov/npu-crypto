/* Native-test model of Cryptogams' RV32 Poly1305 segment interface. */
#include <openssl/bn.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* First five words match the assembly accumulator consumed by segment_result. */
struct poly_ctx { uint32_t h[5]; unsigned char r[16]; };

int poly1305_init(void *ctx, const unsigned char key[16])
{
	struct poly_ctx *st = ctx;
	memset(st, 0, sizeof(*st));
	memcpy(st->r, key, 16);
	st->r[3] &= 15; st->r[7] &= 15; st->r[11] &= 15; st->r[15] &= 15;
	st->r[4] &= 252; st->r[8] &= 252; st->r[12] &= 252;
	return 1;
}

void poly1305_blocks(void *ctx, const unsigned char *input, uint32_t len,
		     uint32_t padbit)
{
	struct poly_ctx *st = ctx;
	BN_CTX *bnctx = BN_CTX_new();
	BIGNUM *r = BN_lebin2bn(st->r, 16, NULL), *h = BN_new();
	BIGNUM *m = BN_new(), *prime = BN_new();
	unsigned char bytes[20];
	unsigned int i;

	for (i = 0; i < 5; i++) {
		bytes[4*i] = st->h[i]; bytes[4*i+1] = st->h[i] >> 8;
		bytes[4*i+2] = st->h[i] >> 16; bytes[4*i+3] = st->h[i] >> 24;
	}
	if (!bnctx || !r || !h || !m || !prime || !BN_lebin2bn(bytes, 20, h) ||
	    !BN_one(prime) || !BN_lshift(prime, prime, 130) || !BN_sub_word(prime, 5))
		abort();
	while (len >= 16) {
		if (!BN_lebin2bn(input, 16, m) || (padbit && !BN_set_bit(m, 128)) ||
		    !BN_mod_add(h, h, m, prime, bnctx) || !BN_mod_mul(h, h, r, prime, bnctx))
			abort();
		input += 16; len -= 16;
	}
	if (BN_bn2lebinpad(h, bytes, 20) != 20)
		abort();
	for (i = 0; i < 5; i++)
		st->h[i] = (uint32_t)bytes[4*i] | (uint32_t)bytes[4*i+1] << 8 |
			(uint32_t)bytes[4*i+2] << 16 | (uint32_t)bytes[4*i+3] << 24;
	BN_clear_free(r); BN_clear_free(h); BN_clear_free(m); BN_free(prime);
	BN_CTX_free(bnctx);
}
