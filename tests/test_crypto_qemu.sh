#!/bin/sh
set -eu
out=$(mktemp /tmp/npu-crypto-qemu.XXXXXX)
asm=$(mktemp /tmp/npu-chacha.XXXXXX.S)
trap 'rm -f "$out" "$asm"' EXIT
perl crypto_standalone/cryptogams/chacha-riscv.pl generic > "$asm"
for batch in 1 2 3; do
	riscv64-unknown-elf-gcc -march=rv32imac_zicsr_zifencei -mabi=ilp32 \
		-Os -ffreestanding -fno-builtin -nostdlib -DAN7581 -DNOWIFI \
		-DNPU_CRYPTO_TEST -DNPU_CRYPTO_QEMU -DNPU_CHACHA_ASM \
		-DAIROHA_CRYPTO_NPU_BATCH_SIZE="$batch" -I. -T tests/qemu/link.ld \
		tests/qemu/start.S tests/qemu/main.c crypto_standalone/service.c \
		npu_crypto.c "$asm" -lgcc -o "$out"
	timeout 30 qemu-system-riscv32 -machine virt -smp 8 -m 128M -nographic \
		-bios none -kernel "$out" -no-reboot
	printf 'Batch size %s: 40 vectors passed for each packet group\n' "$batch"
	riscv64-unknown-elf-gcc -march=rv32imac_zicsr_zifencei -mabi=ilp32 \
		-Os -ffreestanding -fno-builtin -nostdlib -DAN7581 -DNOWIFI \
		-DNPU_CRYPTO_QEMU_MAILBOX -DNPU_CHACHA_ASM \
		-DAIROHA_CRYPTO_NPU_BATCH_SIZE="$batch" -I. -T tests/qemu/link.ld \
		tests/qemu/mailbox_start.S tests/qemu/mailbox.c \
		crypto_standalone/service.c npu_crypto.c "$asm" -lgcc -o "$out"
	timeout 60 qemu-system-riscv32 -machine virt -smp 8 -m 128M -nographic \
		-bios none -kernel "$out" -no-reboot
	printf 'Batch size %s: 100 concurrent mailbox encrypt/decrypt rounds passed\n' "$batch"
done
