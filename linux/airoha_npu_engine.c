// SPDX-License-Identifier: GPL-2.0-only
#include <crypto/engine.h>
#include <crypto/internal/aead.h>
#include <linux/atomic.h>
#include <linux/err.h>
#include <linux/completion.h>
#include <linux/module.h>
#include <linux/refcount.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include "airoha_npu_crypto_proto.h"
#include "airoha_npu_engine.h"

struct airoha_crypto_engine {
	struct aead_engine_alg alg;
	struct crypto_engine *engine;
	struct airoha_crypto_transport transport;
	refcount_t references;
	struct completion released;
	spinlock_t lock;
	atomic_t in_flight;
	bool stopping;
};

static atomic64_t npu_submitted = ATOMIC64_INIT(0);
static atomic64_t npu_busy = ATOMIC64_INIT(0);

static int airoha_counter_get(char *buffer, const struct kernel_param *param)
{
	return scnprintf(buffer, PAGE_SIZE, "%lld",
			 (long long)atomic64_read(param->arg));
}

static const struct kernel_param_ops airoha_counter_ops = {
	.get = airoha_counter_get,
};

module_param_cb(npu_submitted, &airoha_counter_ops, &npu_submitted, 0444);
MODULE_PARM_DESC(npu_submitted, "Requests accepted by the NPU engine");
module_param_cb(npu_busy, &airoha_counter_ops, &npu_busy, 0444);
MODULE_PARM_DESC(npu_busy, "Requests refused because the NPU is busy");

struct airoha_crypto_ctx {
	struct airoha_crypto_engine *engine;
	u8 key[32];
};

struct airoha_crypto_reqctx {
	bool decrypt;
};

static struct airoha_crypto_engine *engine_from_tfm(struct crypto_aead *tfm)
{
	return container_of(crypto_aead_alg(tfm), struct airoha_crypto_engine,
			    alg.base);
}

static int airoha_setkey(struct crypto_aead *tfm, const u8 *key,
			 unsigned int len)
{
	struct airoha_crypto_ctx *ctx = crypto_aead_ctx(tfm);

	if (len != sizeof(ctx->key))
		return -EINVAL;
	memcpy(ctx->key, key, len);
	return 0;
}

static int airoha_setauthsize(struct crypto_aead *tfm, unsigned int len)
{
	return len == AIROHA_CRYPTO_TAG_SIZE ? 0 : -EINVAL;
}

static int airoha_init_tfm(struct crypto_aead *tfm)
{
	struct airoha_crypto_ctx *ctx = crypto_aead_ctx(tfm);
	struct airoha_crypto_engine *e = engine_from_tfm(tfm);
	unsigned long flags;
	bool stopping;

	spin_lock_irqsave(&e->lock, flags);
	stopping = e->stopping;
	if (!stopping)
		refcount_inc(&e->references);
	spin_unlock_irqrestore(&e->lock, flags);
	if (stopping)
		return -ENODEV;
	ctx->engine = e;
	crypto_aead_set_reqsize(tfm, sizeof(struct airoha_crypto_reqctx));
	return 0;
}

static void airoha_exit_tfm(struct crypto_aead *tfm)
{
	struct airoha_crypto_ctx *ctx = crypto_aead_ctx(tfm);

	memzero_explicit(ctx->key, sizeof(ctx->key));
	if (refcount_dec_and_test(&ctx->engine->references))
		complete(&ctx->engine->released);
}

static int airoha_enqueue(struct aead_request *req, bool decrypt)
{
	struct airoha_crypto_ctx *ctx = crypto_aead_ctx(crypto_aead_reqtfm(req));
	struct airoha_crypto_reqctx *rctx = aead_request_ctx(req);
	int ret;

	if (atomic_cmpxchg(&ctx->engine->in_flight, 0, 1)) {
		atomic64_inc(&npu_busy);
		return -EAGAIN;
	}
	rctx->decrypt = decrypt;
	ret = crypto_transfer_aead_request_to_engine(ctx->engine->engine, req);
	if (ret == -EINPROGRESS || ret == -EBUSY)
		atomic64_inc(&npu_submitted);
	else
		atomic_set_release(&ctx->engine->in_flight, 0);
	return ret;
}

static int airoha_encrypt(struct aead_request *req)
{
	return airoha_enqueue(req, false);
}

static int airoha_decrypt(struct aead_request *req)
{
	return airoha_enqueue(req, true);
}

static int airoha_do_one(struct crypto_engine *engine, void *request)
{
	struct aead_request *req = container_of(request, struct aead_request, base);
	struct airoha_crypto_ctx *ctx = crypto_aead_ctx(crypto_aead_reqtfm(req));
	struct airoha_crypto_reqctx *rctx = aead_request_ctx(req);
	struct airoha_crypto_request *buffer;
	u32 data_len = req->cryptlen;
	size_t capacity;
	int len, status, err;

	if (rctx->decrypt) {
		if (data_len < AIROHA_CRYPTO_TAG_SIZE) {
			err = -EINVAL;
			goto done;
		}
		data_len -= AIROHA_CRYPTO_TAG_SIZE;
	}
	if (data_len > AIROHA_CRYPTO_MAX_DATA ||
	    req->assoclen > AIROHA_CRYPTO_MAX_REQUEST - sizeof(*buffer) - data_len) {
		err = -EMSGSIZE;
		goto done;
	}
	capacity = sizeof(*buffer) + req->assoclen + data_len;
	buffer = kmalloc(capacity, GFP_KERNEL);
	if (!buffer) {
		err = -ENOMEM;
		goto done;
	}
	len = airoha_crypto_pack(buffer, capacity, req->src,
				req->assoclen, req->cryptlen, ctx->key,
				req->iv, rctx->decrypt);
	if (len < 0) {
		err = len;
		goto free;
	}
	status = ctx->engine->transport.transfer(ctx->engine->transport.ctx,
						 buffer, len);
	if (status < 0) {
		err = status;
		goto free;
	}
	err = airoha_crypto_unpack(buffer, len, req->dst, status);
free:
	kfree_sensitive(buffer);
done:
	atomic_set_release(&ctx->engine->in_flight, 0);
	local_bh_disable();
	crypto_finalize_aead_request(engine, req, err);
	local_bh_enable();
	return 0;
}

struct airoha_crypto_engine *
airoha_crypto_engine_register(struct device *dev,
			      const struct airoha_crypto_transport *transport)
{
	struct airoha_crypto_engine *e;
	int ret;

	if (!transport || !transport->transfer)
		return ERR_PTR(-EINVAL);
	e = kzalloc(sizeof(*e), GFP_KERNEL);
	if (!e)
		return ERR_PTR(-ENOMEM);
	e->transport = *transport;
	refcount_set(&e->references, 1);
	init_completion(&e->released);
	spin_lock_init(&e->lock);
	atomic_set(&e->in_flight, 0);
	e->alg.base.setkey = airoha_setkey;
	e->alg.base.setauthsize = airoha_setauthsize;
	e->alg.base.encrypt = airoha_encrypt;
	e->alg.base.decrypt = airoha_decrypt;
	e->alg.base.init = airoha_init_tfm;
	e->alg.base.exit = airoha_exit_tfm;
	e->alg.base.ivsize = 12;
	e->alg.base.maxauthsize = AIROHA_CRYPTO_TAG_SIZE;
	strscpy(e->alg.base.base.cra_name, "airoha-npu-chacha20poly1305",
		sizeof(e->alg.base.base.cra_name));
	strscpy(e->alg.base.base.cra_driver_name, "airoha-npu-chacha20poly1305",
		sizeof(e->alg.base.base.cra_driver_name));
	e->alg.base.base.cra_priority = 100;
	e->alg.base.base.cra_flags = CRYPTO_ALG_ASYNC;
	e->alg.base.base.cra_blocksize = 1;
	e->alg.base.base.cra_ctxsize = sizeof(struct airoha_crypto_ctx);
	e->alg.base.base.cra_module = THIS_MODULE;
	e->alg.op.do_one_request = airoha_do_one;
	e->engine = crypto_engine_alloc_init(dev, false);
	if (!e->engine) {
		ret = -ENOMEM;
		goto free;
	}
	ret = crypto_engine_start(e->engine);
	if (ret)
		goto exit_engine;
	ret = crypto_engine_register_aead(&e->alg);
	if (ret)
		goto stop;
	return e;
stop:
	crypto_engine_stop(e->engine);
exit_engine:
	crypto_engine_exit(e->engine);
free:
	kfree(e);
	return ERR_PTR(ret);
}

void airoha_crypto_engine_unregister(struct airoha_crypto_engine *e)
{
	unsigned long flags;

	spin_lock_irqsave(&e->lock, flags);
	e->stopping = true;
	if (refcount_dec_and_test(&e->references))
		complete(&e->released);
	spin_unlock_irqrestore(&e->lock, flags);
	wait_for_completion(&e->released);
	crypto_engine_unregister_aead(&e->alg);
	crypto_engine_stop(e->engine);
	crypto_engine_exit(e->engine);
	kfree(e);
}

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Airoha NPU AEAD crypto engine");
