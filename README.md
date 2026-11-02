# AN7581 NPU crypto offload

Standalone ChaCha20-Poly1305 firmware for the AN7581 NPU, a Linux crypto driver, and a WireGuard integration patch. The firmware uses eight RISC-V harts together on one request. The Linux driver handles one NPU request at a time; WireGuard falls back to software when the NPU is busy or unavailable. This replaces the original NPU network firmware on the target.

## Layout

- `npu_crypto.c`, `npu_crypto.h`: portable AEAD implementation and request format.
- `crypto_standalone/`: NPU startup, service, firmware build, and adapted Cryptogams RISC-V ChaCha generator and license.
- `npu_regs.h`, `npu_types.h`, `link.ld`: hardware definitions and linker script required by the firmware.
- `linux/`: platform driver, crypto engine, protocol, and WireGuard patch.
- `tests/`: host differential tests and an eight-hart QEMU test.
- `docs/crypto.md`: protocol and implementation details.
- `openwrt/`: package snapshot, synchronization script, and target integration snapshots.

## Build and test

Run `make crypto-firmware` from this directory. It requires Perl and a `riscv64-unknown-elf-` toolchain supporting RV32. The firmware image is `build/AN7581_CRYPTO/npu_rv32.bin`.

Run `make test` for the host tests and QEMU test. These need a C compiler, Python with `cryptography`, the RV32 toolchain, and `qemu-system-riscv32`.

The Linux module is built against the target kernel by the OpenWrt package. See `openwrt/README.md` for source synchronization and target integration. This directory is the source of truth; the OpenWrt package contains a separate snapshot that must be refreshed after edits.

Basic firmware and WireGuard traffic have been exercised on the Nokia XG-040G-MD UBI target. A safe way to stop the NPU and reload firmware while running has not been established; changes to the loaded firmware or driver require a reboot. The WireGuard patch does not cover AmneziaWG.
