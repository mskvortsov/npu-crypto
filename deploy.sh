#!/usr/bin/env bash
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OPENWRT_DIR=${OPENWRT_DIR:-/w/openwrt-nokia}
TARGET=${TARGET:-yasnogor}
JOBS=${JOBS:-1}
PACKAGE=package/kernel/airoha-npu-crypto

if [[ ! -f "$OPENWRT_DIR/rules.mk" ]]; then
	echo "OpenWrt tree not found: $OPENWRT_DIR (set OPENWRT_DIR to override)" >&2
	exit 1
fi

"$ROOT/openwrt/sync-package.sh" "$OPENWRT_DIR"
make -C "$OPENWRT_DIR" "$PACKAGE/compile" V=s "-j$JOBS"

mapfile -t firmware_files < <(find "$OPENWRT_DIR/build_dir" -type f \
	-path '*/airoha-npu-crypto/build/AN7581_CRYPTO/npu_rv32.bin' -print)
mapfile -t module_files < <(find "$OPENWRT_DIR/build_dir" -type f \
	-path '*/airoha-npu-crypto/linux/airoha_npu_crypto.ko' -print)

if [[ ${#firmware_files[@]} -ne 1 || ${#module_files[@]} -ne 1 ]]; then
	echo "Expected one built firmware and module; found ${#firmware_files[@]} firmware and ${#module_files[@]} modules" >&2
	exit 1
fi

firmware=${firmware_files[0]}
module=${module_files[0]}
remote_fw=/tmp/an7581_crypto.bin
remote_ko=/tmp/airoha_npu_crypto.ko

echo "Deploying to $TARGET"
scp -O "$firmware" "$TARGET:$remote_fw"
scp -O "$module" "$TARGET:$remote_ko"
ssh "$TARGET" "set -eu
  kernel_release=\$(uname -r)
  mkdir -p /lib/firmware/airoha \"/lib/modules/\$kernel_release\"
  cp '$remote_fw' /lib/firmware/airoha/an7581_crypto.bin
  cp '$remote_ko' \"/lib/modules/\$kernel_release/airoha_npu_crypto.ko\"
  chmod 0644 /lib/firmware/airoha/an7581_crypto.bin \"/lib/modules/\$kernel_release/airoha_npu_crypto.ko\"
  rm -f '$remote_fw' '$remote_ko'
  sync
  sha256sum /lib/firmware/airoha/an7581_crypto.bin \"/lib/modules/\$kernel_release/airoha_npu_crypto.ko\"
"

echo "Files installed. Reboot the target to activate the new firmware and module."
