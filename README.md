# AN7581 NPU crypto offload

Standalone ChaCha20-Poly1305 firmware for the AN7581 NPU, a Linux crypto driver, and a WireGuard integration patch. The firmware splits eight RISC-V harts across 1, 2, 4, or 8 simultaneous requests; the default is four requests with two harts each. The Linux driver supports the same number of concurrent requests. WireGuard submits larger packets asynchronously and uses software for payloads of 1024 bytes or less, or when the NPU is unavailable or busy. Crypto clients that allow backlog queue requests until a slot is available. This replaces the original NPU network firmware on the target.

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

Run `make test` for the host, WireGuard asynchronous ownership, and QEMU tests. These need a C compiler with AddressSanitizer and UndefinedBehaviorSanitizer, OpenSSL development headers and library, Python with `cryptography`, the RV32 toolchain, and `qemu-system-riscv32`. The QEMU crypto tests use eight emulated harts; mailbox tests use a ninth hart to simulate the host. Run `python3 tests/test_wireguard_async.py` for the WireGuard submission and callback tests alone; they exercise patched C code with a fake AEAD transport, including early and concurrent callbacks, failures, and transmit-list lifetime. They do not emulate kernel scheduling, DMA, or peer teardown.

Run `./deploy.sh` to build the firmware, NPU module, and patched `wireguard.ko` using the configured OpenWrt tree and install them on `yasnogor`. It does not reboot the target; see `openwrt/README.md` for configuration options.

The Linux module is built against the target kernel by the OpenWrt package. See `openwrt/README.md` for source synchronization and target integration. This directory is the source of truth; the OpenWrt package contains a separate snapshot that must be refreshed after edits.

Basic firmware and WireGuard traffic have been exercised on the Nokia XG-040G-MD UBI target. A safe way to stop the NPU and reload firmware while running has not been established; changes to the loaded firmware or driver require a reboot. The WireGuard patch does not cover AmneziaWG.

Build a standalone libkcapi throughput benchmark for the OpenWrt device with
`make benchmark`. See [benchmark instructions](tools/README.md) for kernel
prerequisites, concurrency options and software comparisons.

WireGuard caches separate keyed NPU transforms for each keypair's send and
receive directions. Crypto workers submit packets without waiting for hardware
and continue processing their queues. Completion callbacks publish packet state
through the existing ordered per-peer queues. A transmit list is published only
after all its outstanding requests finish, even if one packet fails. Peer
removal drains asynchronous callbacks before disabling receive NAPI or destroying
workqueues.

In normal mode, WireGuard does not request driver backlog, so a full NPU
falls back to software. This bounds hardware work to the configured slot
count and replaces the previous blocking integration. The driver packs and
unpacks directly in persistent DMA slots, avoiding an intermediate request
buffer and two full-request copies. Each slot has its own ordered worker queue,
allowing packing and unpacking across slots to run in parallel.
Submission and completion within a slot remain serialized, without sleeping
for the NPU.
Mailbox interrupts schedule completion processing only for submitted slots
whose mailbox reports completion; idle and unfinished slots stay asleep.
A shared watchdog detects timeouts and recovers missed interrupts. Hardware throughput and latency
must be measured on the target. The libkcapi benchmark selects the NPU algorithm
directly and bypasses WireGuard's packet processing.

## NPU-only testing

After rebuilding and installing both modules with `./deploy.sh`, reboot to
activate them. With benchmark traffic stopped, enable strict data crypto:

```sh
echo 1 > /sys/module/airoha_npu_crypto/parameters/npu_enable
echo 1 > /sys/module/wireguard/parameters/npu_only
```

`wireguard.npu_only` defaults to `0`. In test mode, all WireGuard data packets,
including small packets and keepalives, use the NPU. Requests allow driver
backlog, which queues up to 128 waiting requests in addition to active slots. Queue overflow, allocation failures, unavailable hardware/transforms,
and transport errors drop packets instead of using software crypto. Handshakes
still run in software. Stop benchmark traffic before changing modes; already
submitted requests retain their completion fallback policy. This mode does not
remove CPU routing, copies, allocation, or interrupt processing. With
`npu_enable=0` and `npu_only=1`, data packets are dropped. The former
`npu_fallback` parameter has been removed; remove it from module options.

Restore normal behavior with traffic stopped:

```sh
echo 0 > /sys/module/wireguard/parameters/npu_only
```

This patch covers mainline WireGuard only. Disable firewall hardware flow
offloading on the crypto-firmware setup before benchmarking to avoid repeated
attempts to load the network NPU driver.
