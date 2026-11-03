/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _AIROHA_NPU_ENGINE_H
#define _AIROHA_NPU_ENGINE_H

#include <linux/types.h>

struct device;
struct airoha_crypto_engine;

/* The engine owns a slot exclusively from buffer() through release().
 * submit() starts DMA without waiting. result() returns -EINPROGRESS until
 * completion, or quarantines the buffer on timeout. Calls for each slot are
 * serialized by its workqueue; different slots may call the transport
 * concurrently. stop() disables and synchronizes completion interrupts.
 * release() clears the used bytes unless the transport is quarantined.
 */
struct airoha_crypto_transport {
	void *(*buffer)(void *ctx, unsigned int slot);
	int (*submit)(void *ctx, unsigned int slot, size_t length);
	int (*result)(void *ctx, unsigned int slot);
	void (*stop)(void *ctx);
	void (*release)(void *ctx, unsigned int slot, size_t length);
	void *ctx;
};

struct airoha_crypto_engine *
airoha_crypto_engine_register(struct device *dev,
			      const struct airoha_crypto_transport *transport);
/* IRQ notification selects finished slots; the watchdog also checks busy slots. */
void airoha_crypto_engine_notify(struct airoha_crypto_engine *engine,
				 unsigned int slots);
void airoha_crypto_engine_unregister(struct airoha_crypto_engine *engine);

#endif
