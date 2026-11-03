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
# Build from pristine sources: the configured kernel may still contain an older
# version of patch 932. Reuse its configuration and exported symbol versions.
kernel_parent=$(dirname -- "$(dirname -- "$(dirname -- "$module")")")
mapfile -t kernel_dirs < <(find "$kernel_parent" -mindepth 2 -maxdepth 2 \
	-path '*/include' -type d -print | while IFS= read -r include_dir; do
	candidate=${include_dir%/include}
	[[ -f "$candidate/include/config/kernel.release" && -f "$candidate/Module.symvers" ]] && printf '%s\n' "$candidate"
done)
if [[ ${#kernel_dirs[@]} -ne 1 ]]; then
	echo "Expected one configured kernel under $kernel_parent; found ${#kernel_dirs[@]}" >&2
	exit 1
fi
kernel_dir=${kernel_dirs[0]}
kernel_release=$(cat "$kernel_dir/include/config/kernel.release")
kernel_version=$(awk '$1 == "VERSION" {v=$3} $1 == "PATCHLEVEL" {p=$3} $1 == "SUBLEVEL" {s=$3} END {print v "." p "." s}' "$kernel_dir/Makefile")
archive="$OPENWRT_DIR/dl/linux-$kernel_version.tar.xz"
mapfile -t compilers < <(find "$OPENWRT_DIR/staging_dir" -path '*/toolchain-*/bin/*-linux-musl-gcc' -print)
if [[ ! -f "$archive" || ${#compilers[@]} -ne 1 ]]; then
	echo "Need $archive and exactly one OpenWrt musl toolchain (found ${#compilers[@]})" >&2
	exit 1
fi
cross_compile=${compilers[0]%-gcc}-
mkdir -p "$ROOT/build"
work_dir=$(mktemp -d "$ROOT/build/wireguard-deploy.XXXXXX")
trap 'rm -rf -- "$work_dir"' EXIT
tar -xJf "$archive" --strip-components=1 -C "$work_dir" \
	"linux-$kernel_version/drivers/net/wireguard"
patch --batch --forward --fuzz=0 -p1 -d "$work_dir" < "$ROOT/linux/wireguard-offload.patch"
make -C "$kernel_dir" M="$work_dir/drivers/net/wireguard" ARCH=arm64 \
	CROSS_COMPILE="$cross_compile" CONFIG_WIREGUARD=m "-j$JOBS" modules
wireguard="$work_dir/drivers/net/wireguard/wireguard.ko"
if grep -q '^CONFIG_MODULE_STRIPPED=y$' "$kernel_dir/include/config/auto.conf"; then
	"${cross_compile}strip" --strip-debug "$wireguard"
fi
# Check compatibility before uploading or replacing any files.
remote_release=$(ssh "$TARGET" uname -r)
if [[ "$remote_release" != "$kernel_release" ]]; then
	echo "Kernel release mismatch: built $kernel_release, target $remote_release" >&2
	exit 1
fi

remote_fw=/tmp/an7581_crypto.bin
remote_ko=/tmp/airoha_npu_crypto.ko
remote_wg=/tmp/wireguard.ko

echo "Deploying to $TARGET"
scp -O "$firmware" "$TARGET:$remote_fw"
scp -O "$module" "$TARGET:$remote_ko"
scp -O "$wireguard" "$TARGET:$remote_wg"
ssh "$TARGET" "set -eu
  kernel_release=\$(uname -r)
  mkdir -p /lib/firmware/airoha \"/lib/modules/\$kernel_release\"
  cp '$remote_fw' /lib/firmware/airoha/an7581_crypto.bin
  cp '$remote_ko' \"/lib/modules/\$kernel_release/airoha_npu_crypto.ko\"
  cp '$remote_wg' \"/lib/modules/\$kernel_release/wireguard.ko\"
  chmod 0644 /lib/firmware/airoha/an7581_crypto.bin \"/lib/modules/\$kernel_release/airoha_npu_crypto.ko\" \"/lib/modules/\$kernel_release/wireguard.ko\"
  rm -f '$remote_fw' '$remote_ko' '$remote_wg'
  sync
  sha256sum /lib/firmware/airoha/an7581_crypto.bin \"/lib/modules/\$kernel_release/airoha_npu_crypto.ko\" \"/lib/modules/\$kernel_release/wireguard.ko\"
"

echo "Files installed. Reboot the target to activate the new firmware and modules."
