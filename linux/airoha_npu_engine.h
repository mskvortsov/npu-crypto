/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _AIROHA_NPU_ENGINE_H
#define _AIROHA_NPU_ENGINE_H

#include <linux/types.h>

struct device;
struct airoha_crypto_engine;

/* The engine owns a slot exclusively from buffer() through release().
 * transfer() returns after DMA completes, or quarantines the buffer on error.
 * release() clears the used bytes unless the transport is quarantined.
 */
struct airoha_crypto_transport {
	void *(*buffer)(void *ctx, unsigned int slot);
	int (*transfer)(void *ctx, unsigned int slot, size_t length);
	void (*release)(void *ctx, unsigned int slot, size_t length);
	void *ctx;
};

struct airoha_crypto_engine *
airoha_crypto_engine_register(struct device *dev,
			      const struct airoha_crypto_transport *transport);
void airoha_crypto_engine_unregister(struct airoha_crypto_engine *engine);

#endif
