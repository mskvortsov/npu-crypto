# Run from the repository root; linux/Makefile remains the Kbuild entry point.
OPENWRT_DIR ?= /w/openwrt-nokia
KERNEL_DIR ?= $(firstword $(wildcard $(OPENWRT_DIR)/build_dir/target-*/linux-airoha_an7581/linux-*.*))
CLANG_TIDY ?= clang-tidy-21
KERNEL_TIDY_FLAGS := --target=aarch64-linux-gnu -D__KERNEL__ -DMODULE \
	-std=gnu11 -ffreestanding -fno-builtin -Wno-unknown-warning-option \
	$(addprefix -I$(KERNEL_DIR)/,arch/arm64/include arch/arm64/include/generated \
	include arch/arm64/include/uapi arch/arm64/include/generated/uapi \
	include/uapi include/generated/uapi) \
	-include $(KERNEL_DIR)/include/linux/compiler-version.h \
	-include $(KERNEL_DIR)/include/linux/kconfig.h \
	-include $(KERNEL_DIR)/include/linux/compiler_types.h

.PHONY: tidy
tidy:
	@test -f "$(KERNEL_DIR)/include/generated/autoconf.h" || \
		{ echo 'Set KERNEL_DIR to a configured and built ARM64 kernel tree' >&2; exit 1; }
	@set -e; for batch in 1 2 4 8; do \
		$(CLANG_TIDY) linux/airoha_npu_crypto_proto.c linux/airoha_npu_engine.c \
			linux/airoha_npu_platform.c -- $(KERNEL_TIDY_FLAGS) \
			-DAIROHA_CRYPTO_NPU_BATCH_SIZE=$$batch; \
	done
