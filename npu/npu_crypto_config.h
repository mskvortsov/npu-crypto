/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef AIROHA_NPU_CRYPTO_CONFIG_H
#define AIROHA_NPU_CRYPTO_CONFIG_H

/* Eight compute harts are split evenly across this many packet workers. */
#ifndef AIROHA_CRYPTO_NPU_BATCH_SIZE
#define AIROHA_CRYPTO_NPU_BATCH_SIZE 4
#endif

#if AIROHA_CRYPTO_NPU_BATCH_SIZE != 1 && AIROHA_CRYPTO_NPU_BATCH_SIZE != 2 && \
    AIROHA_CRYPTO_NPU_BATCH_SIZE != 4 && AIROHA_CRYPTO_NPU_BATCH_SIZE != 8
#error "AIROHA_CRYPTO_NPU_BATCH_SIZE must be 1, 2, 4, or 8"
#endif

#define AIROHA_CRYPTO_NPU_HARTS_PER_PACKET \
	(8 / AIROHA_CRYPTO_NPU_BATCH_SIZE)
#define AIROHA_CRYPTO_NPU_QUEUE(group) \
	((group) * AIROHA_CRYPTO_NPU_HARTS_PER_PACKET)

#endif
