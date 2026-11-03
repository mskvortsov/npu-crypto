# AN7581 NPU crypto offload

Standalone ChaCha20-Poly1305 firmware for the AN7581 NPU, a Linux crypto driver, and a WireGuard integration patch. The firmware splits eight RISC-V harts across 1, 2, 4, or 8 simultaneous requests; the default is four requests with two harts each. The Linux driver supports the same number of concurrent requests. WireGuard uses software for payloads of 1024 bytes or less, and when the NPU is unavailable. When all NPU slots are busy, the `npu_fallback` module parameter selects software fallback or waiting for a slot. This replaces the original NPU network firmware on the target.

## Layout

- `npu/`: firmware sources, build configuration, linker script, and Cryptogams RISC-V generators and license.
- `linux/`: platform driver, crypto engine, protocol, and WireGuard patch.
- `tests/`: host differential tests and QEMU tests for all supported batch sizes.
- `npu/docs/crypto.md`: protocol and implementation details.
- `openwrt/`: package snapshot, synchronization script, and target integration snapshots.

## Build and test

Run `make crypto-firmware` from this directory. It requires Perl and a `riscv64-unknown-elf-` toolchain supporting RV32. The firmware image is `build/AN7581_CRYPTO/npu_rv32.bin`.

Run `make tidy-firmware` to check both firmware C sources and their headers for all four batch sizes. It uses clang-tidy 21 by default; override with `CLANG_TIDY=clang-tidy` if needed. The checks and bare-metal exclusions are documented in `npu/.clang-tidy`; warnings fail the target.

Run `make format-check` to check formatting of firmware and Linux module C sources and headers, or `make format` to apply it. These use clang-format 22; override the executable with `CLANG_FORMAT=clang-format` if needed. Firmware rules live in `npu/.clang-format`; `linux/.clang-format` is copied from the target Linux 6.18 tree, with the include-sorting setting updated to clang-format 22 syntax. Use `format-firmware`, `format-linux`, `format-check-firmware`, or `format-check-linux` to limit the scope. Assembly, Cryptogams generators, and the WireGuard patch are outside the formatting scope.

Run `make tidy` for both components, or `make tidy-linux` for the Linux module alone. Linux checks use clang-tidy 21 against a configured and built ARM64 kernel for all four batch sizes. `linux/tooling.mk` discovers the kernel under `OPENWRT_DIR` (default `/w/openwrt-nokia`); set `KERNEL_DIR=/path/to/linux` to select it explicitly. The flags mirror `linux/.clangd`; `linux/.clang-tidy` documents kernel-specific exclusions. Only module sources and project headers produce diagnostics; upstream kernel headers are excluded. No module is installed or loaded by these targets.

Run `make test` for the host and QEMU tests. These need a C compiler, OpenSSL development headers and library, Python with `cryptography`, the RV32 toolchain, and `qemu-system-riscv32`. The QEMU crypto tests use eight emulated harts; mailbox tests use a ninth hart to simulate the host.

Run `./deploy.sh` to build the firmware and Linux module using the configured OpenWrt tree and install them on `yasnogor`. It does not reboot the target; see `openwrt/README.md` for configuration options.

The Linux module is built against the target kernel by the OpenWrt package. See `openwrt/README.md` for source synchronization and target integration. This directory is the source of truth; the OpenWrt package contains a separate snapshot that must be refreshed after edits.

Basic firmware and WireGuard traffic have been exercised on the Nokia XG-040G-MD UBI target. A safe way to stop the NPU and reload firmware while running has not been established; changes to the loaded firmware or driver require a reboot. The WireGuard patch does not cover AmneziaWG.
