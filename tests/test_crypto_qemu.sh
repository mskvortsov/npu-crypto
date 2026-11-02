#!/bin/sh
set -eu
out=$(mktemp /tmp/npu-crypto-qemu.XXXXXX)
asm=$(mktemp /tmp/npu-chacha.XXXXXX.S)
trap 'rm -f "$out" "$asm"' EXIT
perl crypto_standalone/cryptogams/chacha-riscv.pl generic > "$asm"
riscv64-unknown-elf-gcc -march=rv32imac_zicsr_zifencei -mabi=ilp32 \
	-Os -ffreestanding -fno-builtin -nostdlib -DAN7581 -DNOWIFI \
	-DNPU_CRYPTO_TEST -DNPU_CRYPTO_QEMU -DNPU_CHACHA_ASM -I. -T tests/qemu/link.ld \
	tests/qemu/start.S tests/qemu/main.c crypto_standalone/service.c \
	npu_crypto.c "$asm" -lgcc -o "$out"
timeout 30 qemu-system-riscv32 -machine virt -smp 8 -m 128M -nographic \
	-bios none -kernel "$out" -no-reboot
printf 'Eight-hart ChaCha20-Poly1305: 40 vectors passed\n'
