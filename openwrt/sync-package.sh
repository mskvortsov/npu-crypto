#!/bin/sh
# Refresh the package snapshot in this project or in an existing OpenWrt tree.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if [ "$#" -gt 1 ]; then echo "Usage: $0 [openwrt-tree]" >&2; exit 2; fi
if [ "$#" -eq 1 ]; then
    [ -f "$1/rules.mk" ] || { echo "Not an OpenWrt tree: $1" >&2; exit 1; }
    dest=$1/package/kernel/airoha-npu-crypto
    patch_dir=$1/target/linux/airoha/patches-6.18
else
    dest=$root/openwrt/package/kernel/airoha-npu-crypto
    patch_dir=$root/openwrt/target/linux/airoha/patches-6.18
fi

mkdir -p "$dest/src/"
cp "$root/openwrt/package.mk" "$dest/Makefile"
cp -r "$root/npu" "$dest/src/"
cp -r "$root/linux" "$dest/src/"
mkdir -p "$patch_dir"
cp "$root/linux/wireguard-offload.patch" "$patch_dir/932-wireguard-add-airoha-npu-offload.patch"

echo "Updated $dest"
echo "Updated $patch_dir/932-wireguard-add-airoha-npu-offload.patch"
