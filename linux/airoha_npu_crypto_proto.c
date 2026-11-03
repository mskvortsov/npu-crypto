// SPDX-License-Identifier: GPL-2.0-only
/* Scatterlist conversion for the AN7581 dedicated crypto firmware. */
#include <linux/errno.h>
#include <linux/limits.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/string.h>
#include "airoha_npu_crypto_proto.h"

int airoha_crypto_pack(struct airoha_crypto_request *out, size_t capacity,
		       struct scatterlist *src, unsigned int aad_len,
		       unsigned int crypt_len, const u8 key[32],
		       const u8 nonce[12], bool decrypt)
{
	unsigned int data_len, input_len, payload_len;
	int nents;

	if (decrypt && crypt_len < AIROHA_CRYPTO_TAG_SIZE)
		return -EINVAL;
	data_len = crypt_len - (decrypt ? AIROHA_CRYPTO_TAG_SIZE : 0);
	if (data_len > AIROHA_CRYPTO_MAX_DATA ||
	    aad_len > AIROHA_CRYPTO_MAX_REQUEST - sizeof(*out) - data_len)
		return -EMSGSIZE;
	payload_len = aad_len + data_len;
	input_len = aad_len + crypt_len;
	if (capacity < sizeof(*out) + payload_len)
		return -ENOSPC;
	nents = input_len ? sg_nents_for_len(src, input_len) : 0;
	if (nents < 0)
		return -EINVAL;

	out->version = cpu_to_le32(AIROHA_CRYPTO_VERSION);
	out->operation = cpu_to_le32(decrypt);
	out->length = cpu_to_le32(data_len);
	out->aad_length = cpu_to_le32(aad_len);
	memcpy(out->key, key, sizeof(out->key));
	memcpy(out->nonce, nonce, sizeof(out->nonce));
	memset(out->tag, 0, sizeof(out->tag));
	if (payload_len && sg_pcopy_to_buffer(src, nents, out->data,
					      payload_len, 0) != payload_len)
		return -EINVAL;
	if (decrypt &&
	    sg_pcopy_to_buffer(src, nents, out->tag, AIROHA_CRYPTO_TAG_SIZE,
			       payload_len) != AIROHA_CRYPTO_TAG_SIZE)
		return -EINVAL;
	/* The request-size checks above bound this result to 65535. */
	return (int)(sizeof(*out) + payload_len);
}

int airoha_crypto_unpack(struct airoha_crypto_request *in, size_t capacity,
			 struct scatterlist *dst, unsigned int status)
{
	unsigned int data_len = le32_to_cpu(in->length);
	unsigned int aad_len = le32_to_cpu(in->aad_length);
	unsigned int op = le32_to_cpu(in->operation);
	unsigned int payload_len, output_len;
	int nents;

	if (status == 2)
		return -EBADMSG;
	if (status != 1 || le32_to_cpu(in->version) != AIROHA_CRYPTO_VERSION ||
	    op > 1 || data_len > AIROHA_CRYPTO_MAX_DATA ||
	    aad_len > AIROHA_CRYPTO_MAX_REQUEST - sizeof(*in) - data_len ||
	    capacity < sizeof(*in) + data_len + aad_len)
		return -EIO;
	payload_len = aad_len + data_len;
	output_len = payload_len + (op ? 0 : AIROHA_CRYPTO_TAG_SIZE);
	nents = output_len ? sg_nents_for_len(dst, output_len) : 0;
	if (nents < 0)
		return -EINVAL;
	if (payload_len && sg_pcopy_from_buffer(dst, nents, in->data,
						payload_len, 0) != payload_len)
		return -EINVAL;
	if (!op &&
	    sg_pcopy_from_buffer(dst, nents, in->tag, AIROHA_CRYPTO_TAG_SIZE,
				 payload_len) != AIROHA_CRYPTO_TAG_SIZE)
		return -EINVAL;
	return 0;
}

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Airoha NPU crypto request marshaling");
