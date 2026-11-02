CROSS ?= riscv64-unknown-elf-
CC := $(CROSS)gcc
LD := $(CROSS)ld
OBJCOPY := $(CROSS)objcopy
BUILD := build/AN7581_CRYPTO
ARCH := -march=rv32imc_zicsr_zifencei -mabi=ilp32
CFLAGS := $(ARCH) -Os -ffreestanding -fno-builtin -ffunction-sections \
	-fdata-sections -Wall -Wextra -DAN7581 -DNOWIFI -DNPU_CHACHA_ASM -I.
LIBGCC := $(shell $(CC) $(ARCH) -print-libgcc-file-name)
OBJS := $(BUILD)/start.o $(BUILD)/service.o $(BUILD)/crypto.o $(BUILD)/chacha.o

.PHONY: all
all: $(BUILD)/npu_rv32.bin $(BUILD)/npu_data.bin

$(BUILD):
	mkdir -p $@
$(BUILD)/start.o: crypto_standalone/start.S | $(BUILD)
	$(CC) $(ARCH) -c -o $@ $<
$(BUILD)/service.o: crypto_standalone/service.c npu_crypto.h npu_regs.h | $(BUILD)
	$(CC) $(CFLAGS) -c -o $@ $<
$(BUILD)/crypto.o: npu_crypto.c npu_crypto.h npu_types.h | $(BUILD)
	$(CC) $(CFLAGS) -c -o $@ $<
$(BUILD)/chacha.S: crypto_standalone/cryptogams/chacha-riscv.pl | $(BUILD)
	perl $< generic > $@
$(BUILD)/chacha.o: $(BUILD)/chacha.S
	$(CC) $(ARCH) -c -o $@ $<
$(BUILD)/firmware.elf: $(OBJS) link.ld
	$(LD) -m elf32lriscv -T link.ld --defsym=__ndbg_base=0x3e906800 \
		--gc-sections -Map=$(BUILD)/firmware.map -o $@ $(OBJS) $(LIBGCC)
$(BUILD)/npu_rv32.bin: $(BUILD)/firmware.elf
	$(OBJCOPY) -O binary -j .text -j .rodata $< $@
$(BUILD)/npu_data.bin: $(BUILD)/firmware.elf
	$(OBJCOPY) -O binary -j .data $< $@
