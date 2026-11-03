#ifndef NPU_CRYPTO_H
#define NPU_CRYPTO_H

#include "npu_types.h"
#include "npu_crypto_config.h"

/* RFC 8439; src and dst must be identical or non-overlapping. */
int npu_chacha20poly1305(u8 *dst, const u8 *src, u32 len, const u8 *aad,
			 u32 aad_len, const u8 key[32], const u8 nonce[12],
			 u8 tag[16], int decrypt);

typedef void (*npu_crypto_xor_fn)(u8 *dst, const u8 *src, u32 len,
				  const u8 key[32], const u8 nonce[12]);
typedef void (*npu_crypto_poly_fn)(u8 tag[16], const u8 key[32], const u8 *aad,
				   u32 aad_len, const u8 *data, u32 len);
void npu_poly1305_segment(u32 out[5], const u8 key[32], const u8 *aad,
			  u32 aad_len, const u8 *data, u32 len, u32 first,
			  u32 end);
void npu_poly1305_segment_buffered(u32 out[5], const u8 key[32], const u8 *aad,
				   u32 aad_len, const u8 *data, u32 len,
				   u32 first, u32 end, u32 *scratch,
				   u32 scratch_len);
void npu_poly1305_power(u32 out[5], const u8 key[32], u32 exponent);
void npu_poly1305_combine(u8 tag[16], const u8 key[32], const u32 parts[8][5],
			  const u32 powers[8][5], const u32 lengths[8]);
void npu_chacha20_xor_range(u8 *dst, const u8 *src, u32 len, const u8 key[32],
			    const u8 nonce[12], u32 first_block, u32 end_block);

#if defined(AN7581) && defined(NOWIFI)
#define NPU_CRYPTO_HART 4
#define NPU_CRYPTO_SLOT 0
#define NPU_CRYPTO_VERSION 1
#define NPU_CRYPTO_VERSION_AAD 2
#define NPU_CRYPTO_MAX_DATA 16384
#define NPU_CRYPTO_ENCRYPT 0
#define NPU_CRYPTO_DECRYPT 1

struct npu_crypto_request {
	u32 version;
	u32 operation;
	u32 length;
	u8 nonce[12];
	u8 key[32];
	u8 tag[16];
	u8 data[];
};

struct npu_crypto_request_aad {
	u32 version;
	u32 operation;
	u32 length;
	u32 aad_length;
	u8 nonce[12];
	u8 key[32];
	u8 tag[16];
	u8 data[]; /* associated data, followed by plaintext or ciphertext */
};

int npu_crypto_process(void *buffer, u32 length);
int npu_crypto_process_with_xor(void *buffer, u32 length,
				npu_crypto_xor_fn xor_fn);
int npu_crypto_process_with_workers(void *buffer, u32 length,
				    npu_crypto_xor_fn xor_fn,
				    npu_crypto_poly_fn poly_fn);
int npu_crypto_mail(u32 base, u32 length);
#endif

#endif /* NPU_CRYPTO_H */
