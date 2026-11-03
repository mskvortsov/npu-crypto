#!/bin/sh
# Refresh the package snapshot in this project or in an existing OpenWrt tree.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if [ "$#" -gt 1 ]; then echo "Usage: $0 [openwrt-tree]" >&2; exit 2; fi
if [ "$#" -eq 1 ]; then
    [ -f "$1/rules.mk" ] || { echo "Not an OpenWrt tree: $1" >&2; exit 1; }
    dest=$1/package/kernel/airoha-npu-crypto
else
    dest=$root/openwrt/package/kernel/airoha-npu-crypto
fi
mkdir -p "$dest/src/npu/cryptogams" "$dest/src/linux"
cp "$root/openwrt/package.mk" "$dest/Makefile.tmp"
mv "$dest/Makefile.tmp" "$dest/Makefile"
cp "$root"/npu/npu_crypto.c "$root"/npu/npu_crypto.h "$root"/npu/npu_crypto_config.h "$root"/npu/npu_crypto_profile.h "$root"/npu/npu_regs.h "$root"/npu/npu_types.h "$root"/npu/link.ld "$dest/src/npu/"
cp "$root"/npu/firmware.mk "$root"/npu/npu_service.c "$root"/npu/npu_start.S "$dest/src/npu/"
cp "$root"/npu/cryptogams/LICENSE "$root"/npu/cryptogams/chacha-riscv.pl "$root"/npu/cryptogams/poly1305-riscv.pl "$dest/src/npu/cryptogams/"
cp "$root"/linux/Makefile "$root"/linux/airoha_npu_crypto_proto.c "$root"/linux/airoha_npu_crypto_proto.h "$root"/linux/airoha_npu_engine.c "$root"/linux/airoha_npu_engine.h "$root"/linux/airoha_npu_platform.c "$root"/linux/airoha_npu_test_vector.h "$dest/src/linux/"
echo "Updated $dest"
