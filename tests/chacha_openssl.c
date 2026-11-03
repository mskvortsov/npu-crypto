/* Native-test adapter for the Cryptogams ChaCha20_ctr32 interface. */
#include <openssl/evp.h>
#include <stdint.h>
#include <stdlib.h>

static void store_le32(unsigned char *out, uint32_t value)
{
	out[0] = value;
	out[1] = value >> 8;
	out[2] = value >> 16;
	out[3] = value >> 24;
}

void ChaCha20_ctr32(unsigned char *dst, const unsigned char *src, uint32_t len,
		    const uint32_t key[8], const uint32_t counter[4])
{
	unsigned char key_bytes[32], iv[16];
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	int written, final;
	unsigned int i;

	for (i = 0; i < 8; i++)
		store_le32(key_bytes + 4 * i, key[i]);
	for (i = 0; i < 4; i++)
		store_le32(iv + 4 * i, counter[i]);
	if (!ctx || len > INT32_MAX ||
	    EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, key_bytes, iv) != 1 ||
	    EVP_EncryptUpdate(ctx, dst, &written, src, (int)len) != 1 ||
	    EVP_EncryptFinal_ex(ctx, dst + written, &final) != 1 ||
	    written + final != (int)len)
		abort();
	EVP_CIPHER_CTX_free(ctx);
}
