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
mkdir -p "$dest/src/crypto_standalone/cryptogams" "$dest/src/linux"
cp "$root/openwrt/package/kernel/airoha-npu-crypto/Makefile" "$dest/Makefile.tmp"
mv "$dest/Makefile.tmp" "$dest/Makefile"
cp "$root"/npu_crypto.c "$root"/npu_crypto.h "$root"/npu_crypto_config.h "$root"/npu_crypto_profile.h "$root"/npu_regs.h "$root"/npu_types.h "$root"/link.ld "$dest/src/"
cp "$root"/crypto_standalone/Makefile "$root"/crypto_standalone/service.c "$root"/crypto_standalone/start.S "$dest/src/crypto_standalone/"
cp "$root"/crypto_standalone/cryptogams/LICENSE "$root"/crypto_standalone/cryptogams/README "$root"/crypto_standalone/cryptogams/chacha-riscv.pl "$dest/src/crypto_standalone/cryptogams/"
cp "$root"/linux/Makefile "$root"/linux/airoha_npu_crypto_proto.c "$root"/linux/airoha_npu_crypto_proto.h "$root"/linux/airoha_npu_engine.c "$root"/linux/airoha_npu_engine.h "$root"/linux/airoha_npu_platform.c "$root"/linux/airoha_npu_test_vector.h "$dest/src/linux/"
echo "Updated $dest"
