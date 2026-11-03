#!/bin/sh
set -eu
out=$(mktemp /tmp/npu-crypto-qemu.XXXXXX)
asm=$(mktemp /tmp/npu-chacha.XXXXXX.S)
poly=$(mktemp /tmp/npu-poly1305.XXXXXX.S)
trap 'rm -f "$out" "$asm" "$poly"' EXIT
run_qemu() {
	limit=$1
	harts=$2
	label=$3
	printf 'Running batch size %s: %s (timeout %ss)\n' "$batch" "$label" "$limit"
	if timeout "$limit" qemu-system-riscv32 -machine virt -smp "$harts" -m 128M -nographic \
		-bios none -kernel "$out" -no-reboot; then
		return 0
	else
		status=$?
		printf 'QEMU failed: batch size %s, %s, exit %s\n' "$batch" "$label" "$status" >&2
		if [ "$status" -eq 124 ]; then
			printf 'Timed out after %ss; firmware may be stalled or the host may be overloaded.\n' "$limit" >&2
		fi
		return "$status"
	fi
}
perl npu/cryptogams/chacha-riscv.pl generic > "$asm"
perl npu/cryptogams/poly1305-riscv.pl 32 "$poly"
for batch in 1 2 4 8; do
	riscv64-unknown-elf-gcc -march=rv32imac_zicsr_zifencei -mabi=ilp32 \
		-Os -ffreestanding -fno-builtin -nostdlib -DAN7581 -DNOWIFI \
		-DNPU_CRYPTO_TEST -DNPU_CRYPTO_QEMU \
		-DAIROHA_CRYPTO_NPU_BATCH_SIZE="$batch" -Inpu -T tests/qemu/link.ld \
		tests/qemu/start.S tests/qemu/main.c npu/npu_service.c \
		npu/npu_crypto.c "$asm" "$poly" -lgcc -o "$out"
	run_qemu "${QEMU_CRYPTO_TIMEOUT:-30}" 8 'crypto vectors'
	printf 'Batch size %s: 40 vectors passed for each packet group\n' "$batch"
	riscv64-unknown-elf-gcc -march=rv32imac_zicsr_zifencei -mabi=ilp32 \
		-Os -ffreestanding -fno-builtin -nostdlib -DAN7581 -DNOWIFI \
		-DNPU_CRYPTO_QEMU_MAILBOX \
		-DAIROHA_CRYPTO_NPU_BATCH_SIZE="$batch" -Inpu -T tests/qemu/link.ld \
		tests/qemu/mailbox_start.S tests/qemu/mailbox.c \
		npu/npu_service.c npu/npu_crypto.c "$asm" "$poly" -lgcc -o "$out"
	run_qemu "${QEMU_MAILBOX_TIMEOUT:-60}" 9 'mailbox rounds'
	printf 'Batch size %s: 100 concurrent mailbox encrypt/decrypt rounds passed\n' "$batch"
done
