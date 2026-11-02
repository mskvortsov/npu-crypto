/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef AIROHA_NPU_CRYPTO_CONFIG_H
#define AIROHA_NPU_CRYPTO_CONFIG_H

/* Six compute harts are split evenly across this many packet workers. */
#ifndef AIROHA_CRYPTO_NPU_BATCH_SIZE
#define AIROHA_CRYPTO_NPU_BATCH_SIZE 3
#endif

#if AIROHA_CRYPTO_NPU_BATCH_SIZE < 1 || AIROHA_CRYPTO_NPU_BATCH_SIZE > 3
#error "AIROHA_CRYPTO_NPU_BATCH_SIZE must be 1, 2, or 3"
#endif

#define AIROHA_CRYPTO_NPU_HARTS_PER_PACKET \
	(6 / AIROHA_CRYPTO_NPU_BATCH_SIZE)
#define AIROHA_CRYPTO_NPU_QUEUE(group) \
	((group) * AIROHA_CRYPTO_NPU_HARTS_PER_PACKET)

#endif
