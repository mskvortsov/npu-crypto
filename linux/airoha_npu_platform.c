// SPDX-License-Identifier: GPL-2.0-only
/* AN7581 dedicated NPU crypto firmware transport. */
#include <linux/dma-mapping.h>
#include <linux/debugfs.h>
#include <linux/firmware.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/of_reserved_mem.h>
#include <linux/platform_device.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/ktime.h>
#include <linux/wait.h>
#include "airoha_npu_crypto_proto.h"
#include "airoha_npu_engine.h"
#include "airoha_npu_test_vector.h"
#include "../npu/npu_crypto_profile.h"

#define NPU_FW_NAME "airoha/an7581_crypto.bin"
#define NPU_FW_ADDR 0x84000000
#define NPU_FW_MAX_SIZE 0x200000
#define NPU_BOOT_TRIGGER 0x306000
#define NPU_BOOT_CONFIG 0x306004
#define NPU_BOOT_BASE0 0x306020
#define NPU_MBOX_CTRL0(q) (0x30c030 + (q) * 0x10)
#define NPU_MBOX_CTRL1(q) (0x30c034 + (q) * 0x10)
#define NPU_MBOX_CTRL2(q) (0x30c038 + (q) * 0x10)
#define NPU_MBOX_CTRL3(q) (0x30c03c + (q) * 0x10)
#define NPU_MBOX_INT_STATUS 0x30c000
#define NPU_MBOX_INT_MASK0 0x30c004
#define NPU_MBOX_HOST_BIT BIT(8)
#define NPU_MBOX_NOTIFY 8
#define NPU_MIB30 0x30c1b8
#define NPU_MIB31 0x30c1bc
#define NPU_READY 0x43525931
#define NPU_WAIT 1
#define NPU_DONE 2
#define NPU_STATUS_MASK 7
#define NPU_TIMEOUT_US 1000000
#define NPU_DMA_SLOT_SIZE ((AIROHA_CRYPTO_MAX_REQUEST + 3UL) & ~3UL)

/* There is no known safe way to stop the harts once boot is attempted. */
static DEFINE_MUTEX(airoha_boot_lock);
static bool airoha_boot_attempted;

static bool npu_profile;
module_param(npu_profile, bool, 0644);
MODULE_PARM_DESC(npu_profile, "Collect NPU timing samples (default: false)");
static bool npu_interrupt = true;
module_param(npu_interrupt, bool, 0644);
MODULE_PARM_DESC(npu_interrupt,
		 "Use mailbox completion interrupts (default: true)");

struct airoha_profile_aggregate {
	u64 count, host_ns_sum, host_ns_max;
#define HOST_PROFILE_FIELDS(X) X(copy_in) X(submit) X(poll) X(copy_out) X(clear)
#define HOST_AGG_FIELD(name) u64 host_##name##_ns_sum, host_##name##_ns_max;
	HOST_PROFILE_FIELDS(HOST_AGG_FIELD)
#undef HOST_AGG_FIELD
#define PROFILE_AGG_FIELD(name) u64 name##_sum, name##_max;
	AIROHA_PROFILE_FIELDS(PROFILE_AGG_FIELD)
#undef PROFILE_AGG_FIELD
};

struct airoha_crypto_dev {
	struct device *dev;
	void __iomem *regs;
	void *bounce;
	dma_addr_t dma;
	struct airoha_crypto_engine *engine;
	bool poisoned;
	spinlock_t profile_lock;
	struct airoha_profile_aggregate profile[AIROHA_CRYPTO_NPU_BATCH_SIZE];
	struct dentry *profile_dir;
	wait_queue_head_t completion_wait;
	atomic_t irq_count;
};

static irqreturn_t airoha_crypto_irq(int irq, void *data)
{
	struct airoha_crypto_dev *npu = data;
	u32 ctrl;

	if (!(readl(npu->regs + NPU_MBOX_INT_STATUS) & NPU_MBOX_HOST_BIT))
		return IRQ_NONE;
	writel(NPU_MBOX_HOST_BIT, npu->regs + NPU_MBOX_INT_STATUS);
	ctrl = readl(npu->regs + NPU_MBOX_CTRL3(NPU_MBOX_NOTIFY));
	writel((ctrl & ~(NPU_STATUS_MASK << 2)) | NPU_DONE,
	       npu->regs + NPU_MBOX_CTRL3(NPU_MBOX_NOTIFY));
	atomic_inc(&npu->irq_count);
	wake_up_all(&npu->completion_wait);
	return IRQ_HANDLED;
}

static int airoha_profile_show(struct seq_file *s, void *unused)
{
	struct airoha_crypto_dev *npu = s->private;
	struct airoha_profile_aggregate snapshot;
	unsigned long flags;
	unsigned int slot;

	seq_printf(s, "enabled %u\nbatch_size %u\n", READ_ONCE(npu_profile),
		   AIROHA_CRYPTO_NPU_BATCH_SIZE);
	seq_puts(
		s,
		"Firmware values are cycles; host values are nanoseconds. Sums and maxima are cumulative since probe.\n");
	for (slot = 0; slot < AIROHA_CRYPTO_NPU_BATCH_SIZE; slot++) {
		spin_lock_irqsave(&npu->profile_lock, flags);
		snapshot = npu->profile[slot];
		spin_unlock_irqrestore(&npu->profile_lock, flags);
		seq_printf(
			s,
			"slot %u count %llu host_ns_sum %llu host_ns_max %llu\n",
			slot, snapshot.count, snapshot.host_ns_sum,
			snapshot.host_ns_max);
#define HOST_PRINT(name)                                      \
	seq_printf(s,                                         \
		   "  host_" #name "_ns_sum %llu host_" #name \
		   "_ns_max %llu\n",                          \
		   snapshot.host_##name##_ns_sum,             \
		   snapshot.host_##name##_ns_max);
		HOST_PROFILE_FIELDS(HOST_PRINT)
#undef HOST_PRINT
#define PROFILE_PRINT(name)                                                   \
	seq_printf(s,                                                         \
		   "  " #name "_cycles_sum %llu " #name "_cycles_max %llu\n", \
		   snapshot.name##_sum, snapshot.name##_max);
		AIROHA_PROFILE_FIELDS(PROFILE_PRINT)
#undef PROFILE_PRINT
	}
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(airoha_profile);

static bool airoha_crypto_has_network_consumer(struct device_node *target)
{
	struct device_node *np;

	for_each_node_with_property(np, "airoha,npu") {
		struct device_node *npu;
		bool match;

		if (!of_device_is_available(np))
			continue;
		npu = of_parse_phandle(np, "airoha,npu", 0);
		match = npu == target;
		of_node_put(npu);
		if (match) {
			of_node_put(np);
			return true;
		}
	}
	return false;
}

/* The engine reserves each slot until unpacking and clearing have finished. */
static void *airoha_crypto_buffer(void *context, unsigned int slot)
{
	struct airoha_crypto_dev *npu = context;

	if (slot >= AIROHA_CRYPTO_NPU_BATCH_SIZE || READ_ONCE(npu->poisoned))
		return NULL;
	return npu->bounce + (size_t)slot * NPU_DMA_SLOT_SIZE;
}

static void airoha_crypto_release(void *context, unsigned int slot, size_t len)
{
	struct airoha_crypto_dev *npu = context;

	/* After a timeout firmware may still be reading or writing this slot. */
	if (!READ_ONCE(npu->poisoned))
		memzero_explicit(npu->bounce + (size_t)slot * NPU_DMA_SLOT_SIZE,
				 len);
}

static int airoha_crypto_transfer(void *context, unsigned int slot, size_t len)
{
	struct airoha_crypto_dev *npu = context;
	void *bounce;
	dma_addr_t dma;
	unsigned int queue = AIROHA_CRYPTO_NPU_QUEUE(slot);
	u32 ctrl, seq;
	bool profile = READ_ONCE(npu_profile);
	bool use_irq = READ_ONCE(npu_interrupt);
	u64 started = profile ? ktime_get_ns() : 0;
	u64 t1 = 0, t2 = 0, t3 = 0;
	int ret;

	if (READ_ONCE(npu->poisoned))
		return -ENODEV;
	if (slot >= AIROHA_CRYPTO_NPU_BATCH_SIZE)
		return -EINVAL;
	if (len > AIROHA_CRYPTO_MAX_REQUEST)
		return -EMSGSIZE;
	/* Large requests use the trailer space; collect no sample for them. */
	if (len > AIROHA_PROFILE_OFFSET)
		profile = false;
	bounce = npu->bounce + (size_t)slot * NPU_DMA_SLOT_SIZE;
	dma = npu->dma + (size_t)slot * NPU_DMA_SLOT_SIZE;
	if (profile)
		t1 = ktime_get_ns();
	dma_wmb();
	writel(lower_32_bits(dma), npu->regs + NPU_MBOX_CTRL0(queue));
	writel(len, npu->regs + NPU_MBOX_CTRL1(queue));
	writel(NPU_WAIT | (profile ? AIROHA_PROFILE_FLAG : 0) |
		       (use_irq ? AIROHA_INTERRUPT_FLAG : 0),
	       npu->regs + NPU_MBOX_CTRL3(queue));
	seq = readl(npu->regs + NPU_MBOX_CTRL2(queue));
	writel(seq + 1, npu->regs + NPU_MBOX_CTRL2(queue));
	if (profile)
		t2 = ktime_get_ns();
	if (use_irq) {
		ret = wait_event_timeout(
			      npu->completion_wait,
			      (readl(npu->regs + NPU_MBOX_CTRL3(queue)) &
			       NPU_DONE),
			      usecs_to_jiffies(NPU_TIMEOUT_US)) ?
			      0 :
			      -ETIMEDOUT;
		ctrl = readl(npu->regs + NPU_MBOX_CTRL3(queue));
	} else {
		ret = readl_poll_timeout(npu->regs + NPU_MBOX_CTRL3(queue),
					 ctrl, ctrl & NPU_DONE, 10,
					 NPU_TIMEOUT_US);
	}
	if (ret) {
		/* The hart can still access this buffer after a timeout. */
		WRITE_ONCE(npu->poisoned, true);
		dev_err(npu->dev,
			"crypto request timed out; DMA buffer quarantined\n");
		return ret;
	}
	if (profile)
		t3 = ktime_get_ns();
	dma_rmb();
	if (profile) {
		struct airoha_profile_sample sample;
		struct airoha_profile_aggregate *agg = &npu->profile[slot];
		u64 host_ns = ktime_get_ns() - started;
		unsigned long flags;

		memcpy(&sample, bounce + AIROHA_PROFILE_OFFSET, sizeof(sample));
		spin_lock_irqsave(&npu->profile_lock, flags);
		agg->count++;
		agg->host_ns_sum += host_ns;
		agg->host_ns_max = max(agg->host_ns_max, host_ns);
#define HOST_ACCUMULATE(name, value)                        \
	do {                                                \
		u64 ns = (value);                           \
		agg->host_##name##_ns_sum += ns;            \
		agg->host_##name##_ns_max =                 \
			max(agg->host_##name##_ns_max, ns); \
	} while (0)
		HOST_ACCUMULATE(copy_in, 0);
		HOST_ACCUMULATE(submit, t2 - t1);
		HOST_ACCUMULATE(poll, t3 - t2);
		HOST_ACCUMULATE(copy_out, 0);
		HOST_ACCUMULATE(clear, 0);
#undef HOST_ACCUMULATE
#define PROFILE_ACCUMULATE(name)                                            \
	do {                                                                \
		agg->name##_sum += sample.name;                             \
		agg->name##_max = max_t(u64, agg->name##_max, sample.name); \
	} while (0);
		AIROHA_PROFILE_FIELDS(PROFILE_ACCUMULATE)
#undef PROFILE_ACCUMULATE
		spin_unlock_irqrestore(&npu->profile_lock, flags);
	}
	return (int)((ctrl >> 2) & NPU_STATUS_MASK);
}

/* Exercise each firmware packet group through the same DMA/mailbox transport
 * as live requests, before publishing the algorithm to network users. */
static int airoha_crypto_selftest(struct airoha_crypto_dev *npu)
{
	enum { aad_len = 127, data_len = 1500 };
	const size_t len =
		sizeof(struct airoha_crypto_request) + aad_len + data_len;
	struct airoha_crypto_request *req;
	unsigned int slot, i;
	int status, ret = 0;

	for (slot = 0; slot < AIROHA_CRYPTO_NPU_BATCH_SIZE; slot++) {
		req = airoha_crypto_buffer(npu, slot);
		if (!req)
			return -ENODEV;
		memset(req, 0, len);
		req->version = cpu_to_le32(AIROHA_CRYPTO_VERSION);
		req->length = cpu_to_le32(data_len);
		req->aad_length = cpu_to_le32(aad_len);
		for (i = 0; i < sizeof(req->nonce); i++)
			req->nonce[i] = i + 8 * 29;
		for (i = 0; i < sizeof(req->key); i++)
			req->key[i] = i + 8 * 17;
		for (i = 0; i < aad_len; i++)
			req->data[i] = 255 - i;
		for (i = 0; i < data_len; i++)
			req->data[aad_len + i] = i;
		status = airoha_crypto_transfer(npu, slot, len);
		if (status != 1) {
			dev_err(npu->dev,
				"selftest slot %u encrypt status %d\n", slot,
				status);
			ret = -EIO;
			goto next;
		}
		for (i = 0; i < data_len; i++)
			if (req->data[aad_len + i] !=
			    airoha_test_ciphertext[i]) {
				dev_err(npu->dev,
					"selftest slot %u ciphertext mismatch at byte %u\n",
					slot, i);
				ret = -EIO;
				goto next;
			}
		if (memcmp(req->tag, airoha_test_ciphertext + data_len,
			   sizeof(req->tag)) != 0) {
			dev_err(npu->dev, "selftest slot %u tag mismatch\n",
				slot);
			ret = -EIO;
			goto next;
		}
		req->operation = cpu_to_le32(1);
		status = airoha_crypto_transfer(npu, slot, len);
		if (status != 1) {
			dev_err(npu->dev,
				"selftest slot %u decrypt status %d\n", slot,
				status);
			ret = -EIO;
			goto next;
		}
		for (i = 0; i < data_len; i++)
			if (req->data[aad_len + i] != (u8)i) {
				dev_err(npu->dev,
					"selftest slot %u plaintext mismatch at byte %u\n",
					slot, i);
				ret = -EIO;
				goto next;
			}
		dev_info(npu->dev, "selftest slot %u passed\n", slot);
next:
		airoha_crypto_release(npu, slot, len);
		if (READ_ONCE(npu->poisoned))
			break;
	}
	if (!ret && READ_ONCE(npu_interrupt) &&
	    !wait_event_timeout(npu->completion_wait,
				atomic_read(&npu->irq_count) >=
					2 * AIROHA_CRYPTO_NPU_BATCH_SIZE,
				usecs_to_jiffies(NPU_TIMEOUT_US))) {
		dev_err(npu->dev,
			"selftest did not receive all completion interrupts\n");
		WRITE_ONCE(npu->poisoned, true);
		ret = -ETIMEDOUT;
	}
	return ret;
}

static int airoha_crypto_boot(struct platform_device *pdev,
			      struct airoha_crypto_dev *npu)
{
	struct device *dev = &pdev->dev;
	const struct firmware *fw;
	struct resource res;
	void __iomem *code;
	u32 ready, i;
	int ret;

	ret = of_reserved_mem_region_to_resource(dev->of_node, 0, &res);
	if (ret)
		return dev_err_probe(dev, ret,
				     "missing firmware memory region\n");
	if (res.start != NPU_FW_ADDR || resource_size(&res) < NPU_FW_MAX_SIZE)
		return dev_err_probe(dev, -EINVAL,
				     "invalid firmware memory region\n");
	code = devm_ioremap_resource(dev, &res);
	if (IS_ERR(code))
		return (int)PTR_ERR(code);
	ret = request_firmware(&fw, NPU_FW_NAME, dev);
	if (ret)
		return dev_err_probe(dev, ret, "cannot load crypto firmware\n");
	if (!fw->size || fw->size > NPU_FW_MAX_SIZE) {
		release_firmware(fw);
		return -EINVAL;
	}
	mutex_lock(&airoha_boot_lock);
	if (airoha_boot_attempted) {
		mutex_unlock(&airoha_boot_lock);
		release_firmware(fw);
		return dev_err_probe(
			dev, -EBUSY,
			"NPU firmware already started; reboot required\n");
	}
	/* Keep this guard alive across failed probes and module removal. */
	if (!try_module_get(THIS_MODULE)) {
		mutex_unlock(&airoha_boot_lock);
		release_firmware(fw);
		return -ENODEV;
	}
	airoha_boot_attempted = true;
	mutex_unlock(&airoha_boot_lock);
	memcpy_toio(code, fw->data, fw->size);
	release_firmware(fw);
	writel(0, npu->regs + NPU_MIB30);
	writel(0, npu->regs + NPU_MIB31);
	for (i = 0; i < 8; i++)
		writel(lower_32_bits(res.start),
		       npu->regs + NPU_BOOT_BASE0 + (size_t)i * 4);
	writel(0xff, npu->regs + NPU_BOOT_CONFIG);
	writel(1, npu->regs + NPU_BOOT_TRIGGER);
	ret = readl_poll_timeout(npu->regs + NPU_MIB31, ready,
				 ready == NPU_READY, 100, NPU_TIMEOUT_US);
	if (ret)
		return dev_err_probe(dev, ret,
				     "crypto firmware did not start\n");
	return 0;
}

static int airoha_crypto_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct airoha_crypto_transport transport;
	struct airoha_crypto_dev *npu;
	int ret, irq;

	if (airoha_crypto_has_network_consumer(dev->of_node))
		return dev_err_probe(
			dev, -EBUSY,
			"NPU still referenced by a network device\n");
	npu = devm_kzalloc(dev, sizeof(*npu), GFP_KERNEL);
	if (!npu)
		return -ENOMEM;
	npu->dev = dev;
	spin_lock_init(&npu->profile_lock);
	init_waitqueue_head(&npu->completion_wait);
	npu->regs = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(npu->regs))
		return (int)PTR_ERR(npu->regs);
	irq = platform_get_irq(pdev, 0);
	if (irq < 0)
		return irq;
	ret = devm_request_irq(dev, irq, airoha_crypto_irq, IRQF_SHARED,
			       "airoha-npu-crypto", npu);
	if (ret)
		return ret;
	ret = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(32));
	if (ret)
		return ret;
	npu->bounce = dma_alloc_coherent(
		dev, NPU_DMA_SLOT_SIZE * AIROHA_CRYPTO_NPU_BATCH_SIZE,
		&npu->dma, GFP_KERNEL);
	if (!npu->bounce)
		return -ENOMEM;
	get_device(dev);
	if ((npu->dma & 3) || upper_32_bits(npu->dma) ||
	    NPU_DMA_SLOT_SIZE * AIROHA_CRYPTO_NPU_BATCH_SIZE >
		    0x40000000ULL - (npu->dma & 0x3fffffff)) {
		ret = -ERANGE;
		goto free_dma;
	}
	writel(NPU_MBOX_HOST_BIT, npu->regs + NPU_MBOX_INT_STATUS);
	writel(NPU_MBOX_HOST_BIT, npu->regs + NPU_MBOX_INT_MASK0);
	ret = airoha_crypto_boot(pdev, npu);
	if (ret)
		goto free_dma;
	ret = airoha_crypto_selftest(npu);
	if (ret)
		goto free_dma;
	transport.buffer = airoha_crypto_buffer;
	transport.transfer = airoha_crypto_transfer;
	transport.release = airoha_crypto_release;
	transport.ctx = npu;
	npu->engine = airoha_crypto_engine_register(dev, &transport);
	if (IS_ERR(npu->engine)) {
		ret = (int)PTR_ERR(npu->engine);
		goto free_dma;
	}
	platform_set_drvdata(pdev, npu);
	npu->profile_dir = debugfs_create_dir("airoha_npu_crypto", NULL);
	debugfs_create_file("profile", 0444, npu->profile_dir, npu,
			    &airoha_profile_fops);
	return 0;
free_dma:
	writel(0, npu->regs + NPU_MBOX_INT_MASK0);
	if (READ_ONCE(npu->poisoned)) {
		dev_err(dev,
			"retaining DMA buffer: firmware may still access it\n");
		return ret;
	}
	dma_free_coherent(dev, NPU_DMA_SLOT_SIZE * AIROHA_CRYPTO_NPU_BATCH_SIZE,
			  npu->bounce, npu->dma);
	put_device(dev);
	return ret;
}

static void airoha_crypto_remove(struct platform_device *pdev)
{
	struct airoha_crypto_dev *npu = platform_get_drvdata(pdev);

	debugfs_remove_recursive(npu->profile_dir);
	airoha_crypto_engine_unregister(npu->engine);
	writel(0, npu->regs + NPU_MBOX_INT_MASK0);
	if (READ_ONCE(npu->poisoned)) {
		dev_err(npu->dev,
			"retaining DMA buffer: firmware may still access it\n");
		return;
	}
	memzero_explicit(npu->bounce,
			 NPU_DMA_SLOT_SIZE * AIROHA_CRYPTO_NPU_BATCH_SIZE);
	dma_free_coherent(npu->dev,
			  NPU_DMA_SLOT_SIZE * AIROHA_CRYPTO_NPU_BATCH_SIZE,
			  npu->bounce, npu->dma);
	put_device(npu->dev);
}

static const struct of_device_id airoha_crypto_of_match[] = {
	{ .compatible = "airoha,an7581-crypto-npu" },
	{}
};
MODULE_DEVICE_TABLE(of, airoha_crypto_of_match);

static struct platform_driver airoha_crypto_driver = {
	.probe = airoha_crypto_probe,
	.remove = airoha_crypto_remove,
	.driver = {
		.name = "airoha-npu-crypto",
		.of_match_table = airoha_crypto_of_match,
		.suppress_bind_attrs = true,
	},
};
module_platform_driver(airoha_crypto_driver);
MODULE_FIRMWARE(NPU_FW_NAME);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Airoha AN7581 NPU crypto transport");
