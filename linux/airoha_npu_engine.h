/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _AIROHA_NPU_ENGINE_H
#define _AIROHA_NPU_ENGINE_H

#include <linux/types.h>

struct device;
struct airoha_crypto_engine;

/* transfer must return only after releasing all access to request. */
struct airoha_crypto_transport {
	int (*transfer)(void *ctx, unsigned int slot, void *request,
			size_t length);
	void *ctx;
};

struct airoha_crypto_engine *
airoha_crypto_engine_register(struct device *dev,
			      const struct airoha_crypto_transport *transport);
void airoha_crypto_engine_unregister(struct airoha_crypto_engine *engine);

#endif
