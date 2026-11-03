// SPDX-License-Identifier: GPL-2.0-only
#include <crypto/internal/aead.h>
#include <linux/atomic.h>
#include <linux/err.h>
#include <linux/completion.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/refcount.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include "airoha_npu_crypto_proto.h"
#include "airoha_npu_engine.h"

#define AIROHA_CRYPTO_MIN_NPU_PAYLOAD_SIZE 1024
#define AIROHA_CRYPTO_MAX_PENDING 128

struct airoha_crypto_work;
struct airoha_crypto_engine;

struct airoha_crypto_slot {
	struct workqueue_struct *workqueue;
	struct work_struct completions;
	struct airoha_crypto_engine *engine;
	unsigned int index;
};

struct airoha_crypto_engine {
	struct aead_alg alg;
	struct airoha_crypto_slot slots[AIROHA_CRYPTO_NPU_BATCH_SIZE];
	struct delayed_work watchdog;
	struct airoha_crypto_work *active[AIROHA_CRYPTO_NPU_BATCH_SIZE];
	struct airoha_crypto_transport transport;
	refcount_t references;
	struct completion released;
	spinlock_t lock;
	atomic_t slots_in_use;
	struct list_head pending;
	unsigned int pending_count;
	bool stopping;
};

static atomic64_t npu_submitted = ATOMIC64_INIT(0);
static atomic64_t npu_busy = ATOMIC64_INIT(0);
static bool npu_enable = true;

module_param(npu_enable, bool, 0644);
MODULE_PARM_DESC(
	npu_enable,
	"Enable NPU offload above the minimum payload size (default: true)");

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

struct airoha_crypto_work {
	struct work_struct work;
	struct list_head pending;
	struct rcu_head rcu;
	struct aead_request *req;
	unsigned int slot;
	size_t length;
	bool decrypt;
};

static void airoha_do_work(struct work_struct *work);

static struct airoha_crypto_engine *engine_from_tfm(struct crypto_aead *tfm)
{
	return container_of(crypto_aead_alg(tfm), struct airoha_crypto_engine,
			    alg);
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
	crypto_aead_set_reqsize(tfm, 0);
	return 0;
}

static void airoha_exit_tfm(struct crypto_aead *tfm)
{
	struct airoha_crypto_ctx *ctx = crypto_aead_ctx(tfm);

	memzero_explicit(ctx->key, sizeof(ctx->key));
	if (refcount_dec_and_test(&ctx->engine->references))
		complete(&ctx->engine->released);
}

static int airoha_reserve_slot(struct airoha_crypto_engine *e)
{
	int old, new, slot;
	unsigned int mask = (1U << AIROHA_CRYPTO_NPU_BATCH_SIZE) - 1;

	for (;;) {
		old = atomic_read(&e->slots_in_use);
		if ((unsigned int)old == mask)
			return -EBUSY;
		for (slot = 0; slot < AIROHA_CRYPTO_NPU_BATCH_SIZE; slot++)
			if (!(old & BIT(slot)))
				break;
		if (slot == AIROHA_CRYPTO_NPU_BATCH_SIZE)
			return -EBUSY;
		new = old | (1 << slot);
		if (atomic_cmpxchg(&e->slots_in_use, old, new) == old)
			return slot;
	}
}

static int airoha_enqueue(struct aead_request *req, bool decrypt)
{
	struct airoha_crypto_ctx *ctx =
		crypto_aead_ctx(crypto_aead_reqtfm(req));
	struct airoha_crypto_work *job;
	u32 data_len = req->cryptlen;
	unsigned long flags;
	int slot;

	if (!READ_ONCE(npu_enable))
		return -EAGAIN;
	if (decrypt && data_len >= AIROHA_CRYPTO_TAG_SIZE)
		data_len -= AIROHA_CRYPTO_TAG_SIZE;
	if ((!decrypt || req->cryptlen >= AIROHA_CRYPTO_TAG_SIZE) &&
	    data_len <= AIROHA_CRYPTO_MIN_NPU_PAYLOAD_SIZE &&
	    !(req->base.flags & CRYPTO_TFM_REQ_MAY_BACKLOG))
		return -EAGAIN;
	job = kzalloc(sizeof(*job), GFP_ATOMIC);
	if (!job)
		return -ENOMEM;
	spin_lock_irqsave(&ctx->engine->lock, flags);
	if (ctx->engine->stopping) {
		spin_unlock_irqrestore(&ctx->engine->lock, flags);
		kfree(job);
		return -EAGAIN;
	}
	if (list_empty(&ctx->engine->pending))
		slot = airoha_reserve_slot(ctx->engine);
	else
		slot = -EBUSY;
	if (slot < 0) {
		if ((req->base.flags & CRYPTO_TFM_REQ_MAY_BACKLOG) &&
		    ctx->engine->pending_count < AIROHA_CRYPTO_MAX_PENDING) {
			job->req = req;
			job->decrypt = decrypt;
			INIT_WORK(&job->work, airoha_do_work);
			list_add_tail(&job->pending, &ctx->engine->pending);
			ctx->engine->pending_count++;
			spin_unlock_irqrestore(&ctx->engine->lock, flags);
			atomic64_inc(&npu_submitted);
			return -EINPROGRESS;
		}
		spin_unlock_irqrestore(&ctx->engine->lock, flags);
		kfree(job);
		atomic64_inc(&npu_busy);
		return -EAGAIN;
	}
	job->req = req;
	job->slot = slot;
	job->decrypt = decrypt;
	INIT_WORK(&job->work, airoha_do_work);
	if (unlikely(!queue_work(ctx->engine->slots[slot].workqueue,
				 &job->work))) {
		atomic_andnot(BIT(slot), &ctx->engine->slots_in_use);
		spin_unlock_irqrestore(&ctx->engine->lock, flags);
		kfree(job);
		return -EIO;
	}
	spin_unlock_irqrestore(&ctx->engine->lock, flags);
	atomic64_inc(&npu_submitted);
	return -EINPROGRESS;
}

static int airoha_encrypt(struct aead_request *req)
{
	return airoha_enqueue(req, false);
}

static int airoha_decrypt(struct aead_request *req)
{
	return airoha_enqueue(req, true);
}

/* Submission and completion are serialized within each slot only. */
static void airoha_finish(struct airoha_crypto_engine *e,
			  struct airoha_crypto_work *job, int err)
{
	struct airoha_crypto_work *next = NULL;
	unsigned long flags;

	e->active[job->slot] = NULL;
	spin_lock_irqsave(&e->lock, flags);
	if (!list_empty(&e->pending)) {
		next = list_first_entry(&e->pending, struct airoha_crypto_work,
					pending);
		list_del_init(&next->pending);
		e->pending_count--;
		next->slot = job->slot;
		WARN_ON_ONCE(!queue_work(e->slots[job->slot].workqueue,
					 &next->work));
	} else {
		atomic_andnot(BIT(job->slot), &e->slots_in_use);
	}
	spin_unlock_irqrestore(&e->lock, flags);
	aead_request_complete(job->req, err);
	kfree_rcu(job, rcu);
}

static void airoha_do_work(struct work_struct *work)
{
	struct airoha_crypto_work *job =
		container_of(work, struct airoha_crypto_work, work);
	struct aead_request *req = job->req;
	struct airoha_crypto_ctx *ctx =
		crypto_aead_ctx(crypto_aead_reqtfm(req));
	struct airoha_crypto_engine *e = ctx->engine;
	struct airoha_crypto_request *buffer;
	u32 data_len = req->cryptlen;
	size_t capacity;
	int len, err;

	if (job->decrypt) {
		if (data_len < AIROHA_CRYPTO_TAG_SIZE) {
			err = -EINVAL;
			goto done;
		}
		data_len -= AIROHA_CRYPTO_TAG_SIZE;
	}
	if (data_len > AIROHA_CRYPTO_MAX_DATA ||
	    req->assoclen >
		    AIROHA_CRYPTO_MAX_REQUEST - sizeof(*buffer) - data_len) {
		err = -EMSGSIZE;
		goto done;
	}
	capacity = sizeof(*buffer) + req->assoclen + data_len;
	buffer = e->transport.buffer(e->transport.ctx, job->slot);
	if (!buffer) {
		err = -ENODEV;
		goto done;
	}
	len = airoha_crypto_pack(buffer, capacity, req->src, req->assoclen,
				 req->cryptlen, ctx->key, req->iv,
				 job->decrypt);
	if (len < 0) {
		err = len;
		goto release;
	}
	err = e->transport.submit(e->transport.ctx, job->slot, len);
	if (err)
		goto release;
	job->length = len;
	e->active[job->slot] = job;
	/* Covers lost interrupts, timeout detection, and diagnostic polling.
	 * The slot completion work cannot run until this worker returns.
	 */
	queue_delayed_work(e->slots[0].workqueue, &e->watchdog, 1);
	return;
release:
	e->transport.release(e->transport.ctx, job->slot, capacity);
done:
	airoha_finish(e, job, err);
}

static void airoha_completions(struct work_struct *work)
{
	struct airoha_crypto_slot *slot =
		container_of(work, struct airoha_crypto_slot, completions);
	struct airoha_crypto_engine *e = slot->engine;
	struct airoha_crypto_work *job = e->active[slot->index];
	struct airoha_crypto_request *buffer;
	int status, err;

	if (!job)
		return;
	status = e->transport.result(e->transport.ctx, slot->index);
	if (status == -EINPROGRESS) {
		queue_delayed_work(e->slots[0].workqueue, &e->watchdog, 1);
		return;
	}
	err = status;
	if (status >= 0) {
		buffer = e->transport.buffer(e->transport.ctx, slot->index);
		err = buffer ? airoha_crypto_unpack(buffer, job->length,
						    job->req->dst, status) :
			       -ENODEV;
	}
	e->transport.release(e->transport.ctx, slot->index, job->length);
	airoha_finish(e, job, err);
}

void airoha_crypto_engine_notify(struct airoha_crypto_engine *e,
				 unsigned int slots)
{
	unsigned int slot;

	slots &= atomic_read(&e->slots_in_use);
	for (slot = 0; slot < AIROHA_CRYPTO_NPU_BATCH_SIZE; slot++)
		if (slots & BIT(slot))
			queue_work(e->slots[slot].workqueue,
				   &e->slots[slot].completions);
}

static void airoha_watchdog(struct work_struct *work)
{
	struct airoha_crypto_engine *e = container_of(
		to_delayed_work(work), struct airoha_crypto_engine, watchdog);

	airoha_crypto_engine_notify(e, atomic_read(&e->slots_in_use));
}

struct airoha_crypto_engine *
airoha_crypto_engine_register(struct device *dev,
			      const struct airoha_crypto_transport *transport)
{
	struct airoha_crypto_engine *e;
	int ret;
	unsigned int slot;

	if (!transport || !transport->buffer || !transport->submit ||
	    !transport->result || !transport->stop || !transport->release)
		return ERR_PTR(-EINVAL);
	(void)dev;
	e = kzalloc(sizeof(*e), GFP_KERNEL);
	if (!e)
		return ERR_PTR(-ENOMEM);
	e->transport = *transport;
	refcount_set(&e->references, 1);
	init_completion(&e->released);
	spin_lock_init(&e->lock);
	atomic_set(&e->slots_in_use, 0);
	INIT_LIST_HEAD(&e->pending);
	e->alg.setkey = airoha_setkey;
	e->alg.setauthsize = airoha_setauthsize;
	e->alg.encrypt = airoha_encrypt;
	e->alg.decrypt = airoha_decrypt;
	e->alg.init = airoha_init_tfm;
	e->alg.exit = airoha_exit_tfm;
	e->alg.ivsize = 12;
	e->alg.maxauthsize = AIROHA_CRYPTO_TAG_SIZE;
	strscpy(e->alg.base.cra_name, "airoha-npu-chacha20poly1305",
		sizeof(e->alg.base.cra_name));
	strscpy(e->alg.base.cra_driver_name, "airoha-npu-chacha20poly1305",
		sizeof(e->alg.base.cra_driver_name));
	e->alg.base.cra_priority = 100;
	e->alg.base.cra_flags = CRYPTO_ALG_ASYNC;
	e->alg.base.cra_blocksize = 1;
	e->alg.base.cra_ctxsize = sizeof(struct airoha_crypto_ctx);
	e->alg.base.cra_module = THIS_MODULE;
	INIT_DELAYED_WORK(&e->watchdog, airoha_watchdog);
	for (slot = 0; slot < AIROHA_CRYPTO_NPU_BATCH_SIZE; slot++) {
		e->slots[slot].engine = e;
		e->slots[slot].index = slot;
		INIT_WORK(&e->slots[slot].completions, airoha_completions);
		e->slots[slot].workqueue = alloc_ordered_workqueue(
			"airoha-npu-crypto-%u", WQ_MEM_RECLAIM, slot);
		if (!e->slots[slot].workqueue) {
			ret = -ENOMEM;
			goto destroy_workqueue;
		}
	}
	ret = crypto_register_aead(&e->alg);
	if (ret)
		goto destroy_workqueue;
	return e;
destroy_workqueue:
	while (slot)
		destroy_workqueue(e->slots[--slot].workqueue);
	kfree(e);
	return ERR_PTR(ret);
}

void airoha_crypto_engine_unregister(struct airoha_crypto_engine *e)
{
	unsigned long flags;
	unsigned int slot;

	spin_lock_irqsave(&e->lock, flags);
	e->stopping = true;
	if (refcount_dec_and_test(&e->references))
		complete(&e->released);
	spin_unlock_irqrestore(&e->lock, flags);
	crypto_unregister_aead(&e->alg);
	/* Transform users retain their references until requests complete. Keep
	 * IRQs, watchdog and queue alive while accepted requests drain.
	 */
	wait_for_completion(&e->released);
	e->transport.stop(e->transport.ctx);
	cancel_delayed_work_sync(&e->watchdog);
	for (slot = 0; slot < AIROHA_CRYPTO_NPU_BATCH_SIZE; slot++)
		destroy_workqueue(e->slots[slot].workqueue);
	kfree(e);
}

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Airoha NPU AEAD crypto engine");
