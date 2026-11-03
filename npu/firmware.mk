CROSS ?= riscv64-unknown-elf-
CLANG_TIDY ?= clang-tidy-21
CC := $(CROSS)gcc
LD := $(CROSS)ld
OBJCOPY := $(CROSS)objcopy
BUILD := build/AN7581_CRYPTO
ARCH := -march=rv32imc_zicsr_zifencei -mabi=ilp32
CFLAGS := $(ARCH) -Os -ffreestanding -fno-builtin -ffunction-sections \
	-fdata-sections -Wall -Wextra -DAN7581 -DNOWIFI -Inpu
LIBGCC := $(shell $(CC) $(ARCH) -print-libgcc-file-name)
OBJS := $(BUILD)/start.o $(BUILD)/service.o $(BUILD)/crypto.o $(BUILD)/chacha.o $(BUILD)/poly1305.o

.PHONY: all tidy
all: $(BUILD)/npu_rv32.bin $(BUILD)/npu_data.bin

# Check every supported packet/hart split using the production target flags.
tidy:
	@set -e; for batch in 1 2 4 8; do \
		$(CLANG_TIDY) npu/npu_crypto.c npu/npu_service.c -- \
			--target=riscv32-unknown-elf $(CFLAGS) \
			-DAIROHA_CRYPTO_NPU_BATCH_SIZE=$$batch; \
	done

$(BUILD):
	mkdir -p $@
$(BUILD)/start.o: npu/npu_start.S | $(BUILD)
	$(CC) $(ARCH) -c -o $@ $<
$(BUILD)/service.o: npu/npu_service.c npu/npu_crypto.h npu/npu_crypto_config.h npu/npu_crypto_profile.h npu/npu_regs.h | $(BUILD)
	$(CC) $(CFLAGS) -c -o $@ $<
$(BUILD)/crypto.o: npu/npu_crypto.c npu/npu_crypto.h npu/npu_crypto_config.h npu/npu_types.h | $(BUILD)
	$(CC) $(CFLAGS) -c -o $@ $<
$(BUILD)/chacha.S: npu/cryptogams/chacha-riscv.pl | $(BUILD)
	perl $< generic > $@
$(BUILD)/chacha.o: $(BUILD)/chacha.S
	$(CC) $(ARCH) -c -o $@ $<
$(BUILD)/poly1305.S: npu/cryptogams/poly1305-riscv.pl | $(BUILD)
	perl $< 32 $@
$(BUILD)/poly1305.o: $(BUILD)/poly1305.S
	$(CC) $(ARCH) -c -o $@ $<
$(BUILD)/firmware.elf: $(OBJS) npu/link.ld
	$(LD) -m elf32lriscv -T npu/link.ld --defsym=__ndbg_base=0x3e90f000 \
		--gc-sections -Map=$(BUILD)/firmware.map -o $@ $(OBJS) $(LIBGCC)
$(BUILD)/npu_rv32.bin: $(BUILD)/firmware.elf
	$(OBJCOPY) -O binary -j .text -j .rodata $< $@
$(BUILD)/npu_data.bin: $(BUILD)/firmware.elf
	$(OBJCOPY) -O binary -j .data $< $@
