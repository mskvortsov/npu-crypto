// SPDX-License-Identifier: GPL-2.0-only
/* AN7581 dedicated NPU crypto firmware transport. */
#include <linux/dma-mapping.h>
#include <linux/firmware.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_reserved_mem.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include "airoha_npu_crypto_proto.h"
#include "airoha_npu_engine.h"
#include "airoha_npu_test_vector.h"

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
#define NPU_MIB30 0x30c1b8
#define NPU_MIB31 0x30c1bc
#define NPU_READY 0x43525931
#define NPU_WAIT 1
#define NPU_DONE 2
#define NPU_STATUS_MASK 7
#define NPU_TIMEOUT_US 1000000
#define NPU_DMA_SLOT_SIZE ((AIROHA_CRYPTO_MAX_REQUEST + 3) & ~3)

struct airoha_crypto_dev {
	struct device *dev;
	void __iomem *regs;
	void *bounce;
	dma_addr_t dma;
	struct airoha_crypto_engine *engine;
	bool poisoned;
};

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

/* The engine serializes calls; the coherent bounce buffer belongs to us. */
static int airoha_crypto_transfer(void *context, unsigned int slot,
				  void *request, size_t len)
{
	struct airoha_crypto_dev *npu = context;
	void *bounce;
	dma_addr_t dma;
	unsigned int queue = AIROHA_CRYPTO_NPU_QUEUE(slot);
	u32 ctrl, seq;
	int ret;

	if (READ_ONCE(npu->poisoned))
		return -ENODEV;
	if (slot >= AIROHA_CRYPTO_NPU_BATCH_SIZE)
		return -EINVAL;
	if (len > AIROHA_CRYPTO_MAX_REQUEST)
		return -EMSGSIZE;
	bounce = npu->bounce + slot * NPU_DMA_SLOT_SIZE;
	dma = npu->dma + slot * NPU_DMA_SLOT_SIZE;
	memcpy(bounce, request, len);
	dma_wmb();
	writel(lower_32_bits(dma), npu->regs + NPU_MBOX_CTRL0(queue));
	writel(len, npu->regs + NPU_MBOX_CTRL1(queue));
	writel(NPU_WAIT, npu->regs + NPU_MBOX_CTRL3(queue));
	seq = readl(npu->regs + NPU_MBOX_CTRL2(queue));
	writel(seq + 1, npu->regs + NPU_MBOX_CTRL2(queue));
	ret = readl_poll_timeout(npu->regs + NPU_MBOX_CTRL3(queue), ctrl,
				 ctrl & NPU_DONE, 10, NPU_TIMEOUT_US);
	if (ret) {
		/* The hart can still access this buffer after a timeout. */
		WRITE_ONCE(npu->poisoned, true);
		dev_err(npu->dev, "crypto request timed out; DMA buffer quarantined\n");
		return ret;
	}
	dma_rmb();
	memcpy(request, bounce, len);
	memzero_explicit(bounce, len);
	return (ctrl >> 2) & NPU_STATUS_MASK;
}

/* Exercise each firmware packet group through the same DMA/mailbox transport
 * as live requests, before publishing the algorithm to network users. */
static int airoha_crypto_selftest(struct airoha_crypto_dev *npu)
{
	enum { aad_len = 127, data_len = 1500 };
	const size_t len = sizeof(struct airoha_crypto_request) + aad_len + data_len;
	struct airoha_crypto_request *req;
	unsigned int slot, i;
	int status, ret = 0;

	req = kzalloc(len, GFP_KERNEL);
	if (!req)
		return -ENOMEM;
	for (slot = 0; slot < AIROHA_CRYPTO_NPU_BATCH_SIZE; slot++) {
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
		status = airoha_crypto_transfer(npu, slot, req, len);
		if (status != 1) {
			dev_err(npu->dev, "selftest slot %u encrypt status %d\n", slot, status);
			ret = -EIO;
			goto next;
		}
		for (i = 0; i < data_len; i++)
			if (req->data[aad_len + i] != airoha_test_ciphertext[i]) {
				dev_err(npu->dev, "selftest slot %u ciphertext mismatch at byte %u\n", slot, i);
				ret = -EIO;
				goto next;
			}
		if (memcmp(req->tag, airoha_test_ciphertext + data_len, sizeof(req->tag))) {
			dev_err(npu->dev, "selftest slot %u tag mismatch\n", slot);
			ret = -EIO;
			goto next;
		}
		req->operation = cpu_to_le32(1);
		status = airoha_crypto_transfer(npu, slot, req, len);
		if (status != 1) {
			dev_err(npu->dev, "selftest slot %u decrypt status %d\n", slot, status);
			ret = -EIO;
			goto next;
		}
		for (i = 0; i < data_len; i++)
			if (req->data[aad_len + i] != (u8)i) {
				dev_err(npu->dev, "selftest slot %u plaintext mismatch at byte %u\n", slot, i);
				ret = -EIO;
				goto next;
			}
		dev_info(npu->dev, "selftest slot %u passed\n", slot);
next:
		if (READ_ONCE(npu->poisoned))
			break;
	}
	kfree_sensitive(req);
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
		return dev_err_probe(dev, ret, "missing firmware memory region\n");
	if (res.start != NPU_FW_ADDR || resource_size(&res) < NPU_FW_MAX_SIZE)
		return dev_err_probe(dev, -EINVAL, "invalid firmware memory region\n");
	code = devm_ioremap_resource(dev, &res);
	if (IS_ERR(code))
		return PTR_ERR(code);
	ret = request_firmware(&fw, NPU_FW_NAME, dev);
	if (ret)
		return dev_err_probe(dev, ret, "cannot load crypto firmware\n");
	if (!fw->size || fw->size > NPU_FW_MAX_SIZE) {
		release_firmware(fw);
		return -EINVAL;
	}
	memcpy_toio(code, fw->data, fw->size);
	release_firmware(fw);
	writel(0, npu->regs + NPU_MIB30);
	writel(0, npu->regs + NPU_MIB31);
	for (i = 0; i < 8; i++)
		writel(lower_32_bits(res.start), npu->regs + NPU_BOOT_BASE0 + i * 4);
	writel(0xff, npu->regs + NPU_BOOT_CONFIG);
	writel(1, npu->regs + NPU_BOOT_TRIGGER);
	ret = readl_poll_timeout(npu->regs + NPU_MIB31, ready,
				 ready == NPU_READY, 100, NPU_TIMEOUT_US);
	if (ret)
		return dev_err_probe(dev, ret, "crypto firmware did not start\n");
	return 0;
}

static int airoha_crypto_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct airoha_crypto_transport transport;
	struct airoha_crypto_dev *npu;
	int ret;

	if (airoha_crypto_has_network_consumer(dev->of_node))
		return dev_err_probe(dev, -EBUSY,
				     "NPU still referenced by a network device\n");
	npu = devm_kzalloc(dev, sizeof(*npu), GFP_KERNEL);
	if (!npu)
		return -ENOMEM;
	npu->dev = dev;
	npu->regs = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(npu->regs))
		return PTR_ERR(npu->regs);
	ret = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(32));
	if (ret)
		return ret;
	npu->bounce = dma_alloc_coherent(dev,
					 NPU_DMA_SLOT_SIZE *
					 AIROHA_CRYPTO_NPU_BATCH_SIZE,
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
	ret = airoha_crypto_boot(pdev, npu);
	if (ret)
		goto free_dma;
	ret = airoha_crypto_selftest(npu);
	if (ret)
		goto free_dma;
	transport.transfer = airoha_crypto_transfer;
	transport.ctx = npu;
	npu->engine = airoha_crypto_engine_register(dev, &transport);
	if (IS_ERR(npu->engine)) {
		ret = PTR_ERR(npu->engine);
		goto free_dma;
	}
	platform_set_drvdata(pdev, npu);
	return 0;
free_dma:
	if (READ_ONCE(npu->poisoned)) {
		dev_err(dev, "retaining DMA buffer: firmware may still access it\n");
		return ret;
	}
		dma_free_coherent(dev, NPU_DMA_SLOT_SIZE *
				  AIROHA_CRYPTO_NPU_BATCH_SIZE, npu->bounce,
				  npu->dma);
	put_device(dev);
	return ret;
}

static void airoha_crypto_remove(struct platform_device *pdev)
{
	struct airoha_crypto_dev *npu = platform_get_drvdata(pdev);

	airoha_crypto_engine_unregister(npu->engine);
	if (READ_ONCE(npu->poisoned)) {
		dev_err(npu->dev, "retaining DMA buffer: firmware may still access it\n");
		return;
	}
	memzero_explicit(npu->bounce, NPU_DMA_SLOT_SIZE *
			 AIROHA_CRYPTO_NPU_BATCH_SIZE);
	dma_free_coherent(npu->dev, NPU_DMA_SLOT_SIZE *
			  AIROHA_CRYPTO_NPU_BATCH_SIZE,
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
