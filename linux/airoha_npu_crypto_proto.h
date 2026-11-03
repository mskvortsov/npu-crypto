/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _AIROHA_NPU_CRYPTO_PROTO_H
#define _AIROHA_NPU_CRYPTO_PROTO_H

#include <linux/types.h>
#include "../npu/npu_crypto_config.h"

struct scatterlist;

#define AIROHA_CRYPTO_VERSION 2
#define AIROHA_CRYPTO_MAX_DATA 16384
#define AIROHA_CRYPTO_TAG_SIZE 16

struct airoha_crypto_request {
	__le32 version;
	__le32 operation;
	__le32 length;
	__le32 aad_length;
	u8 nonce[12];
	u8 key[32];
	u8 tag[AIROHA_CRYPTO_TAG_SIZE];
	u8 data[];
};

int airoha_crypto_pack(struct airoha_crypto_request *out, size_t capacity,
		       struct scatterlist *src, unsigned int aad_len,
		       unsigned int crypt_len, const u8 key[32],
		       const u8 nonce[12], bool decrypt);
int airoha_crypto_unpack(struct airoha_crypto_request *in, size_t capacity,
			 struct scatterlist *dst, unsigned int status);

#endif
