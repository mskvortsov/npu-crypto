#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
cd "$(dirname "$0")/.."
OPENWRT_DIR=${OPENWRT_DIR:-/w/openwrt-nokia}
if [ -z "${BENCH_CC:-}" ]; then
	set -- "$OPENWRT_DIR"/staging_dir/toolchain-aarch64_cortex-a53_*/bin/aarch64-openwrt-linux-gcc
	if [ "$#" -ne 1 ] || [ ! -x "$1" ]; then
		echo 'Set OPENWRT_DIR or BENCH_CC to the device cross-compiler.' >&2
		exit 1
	fi
	BENCH_CC=$1
fi
export STAGING_DIR="$OPENWRT_DIR/staging_dir"
version=1.5.0
archive="build/benchmark/libkcapi-$version.tar.gz"
source_dir="$PWD/build/benchmark/libkcapi-$version"
mkdir -p build/benchmark
if [ ! -f "$archive" ]; then
	curl -fL "https://codeload.github.com/smuellerDD/libkcapi/tar.gz/refs/tags/v$version" -o "$archive.tmp"
	mv "$archive.tmp" "$archive"
fi
printf '%s  %s\n' f1d827738bda03065afd03315479b058f43493ab6e896821b947f391aa566ba0 "$archive" | sha256sum -c -
if [ ! -d "$source_dir" ]; then
	tar -xf "$archive" -C build/benchmark
fi
(
	cd "$source_dir"
	if [ ! -f configure ]; then
		autoreconf -fi
	fi
	if [ ! -f Makefile ] || [ ! -f .bench-cc ] || [ "$(cat .bench-cc)" != "$BENCH_CC" ]; then
		if [ -f Makefile ]; then
			make distclean
		fi
		./configure --host=aarch64-openwrt-linux --disable-shared --enable-static CC="$BENCH_CC"
		printf '%s\n' "$BENCH_CC" > .bench-cc
	fi
	# Upstream 1.5.0 has warnings with GCC 14's newer Linux headers.
	make -j"${JOBS:-4}" libkcapi.la CFLAGS='-O2 -Wno-error'
)
"$BENCH_CC" -O2 -Wall -Wextra -Werror -static -pthread \
	-I"$source_dir/lib" tools/kcapi-bench.c "$source_dir/.libs/libkcapi.a" \
	-o build/kcapi-bench
printf 'Built %s/build/kcapi-bench\n' "$PWD"
