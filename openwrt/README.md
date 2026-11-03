# OpenWrt integration

`package/kernel/airoha-npu-crypto/` is the package snapshot. After changing firmware or driver sources, run `./openwrt/sync-package.sh` from the project root to refresh it. To also refresh the package directly in an existing OpenWrt tree, run:

```sh
./openwrt/sync-package.sh /w/openwrt-nokia
```

The script copies the tracked `openwrt/package.mk` recipe and its source files, and copies `linux/wireguard-offload.patch` to patch 932. It does not change kernel configuration, device trees, other patches, or build the image. The project sources are the authoritative copies. `target/linux/airoha/` contains snapshots of the target files currently used in `/w/openwrt-nokia`, provided for reference and migration. Review and apply changes to an OpenWrt tree deliberately: full target files can contain unrelated target-specific configuration.

The asynchronous WireGuard patch and updated NPU driver must be built together.
`deploy.sh` rebuilds both modules. A package-only build does not rebuild
WireGuard; for full images, apply patch 932 to a clean kernel build.
The driver honors requests without `CRYPTO_TFM_REQ_MAY_BACKLOG` by refusing busy
slots immediately. Requests with that flag queue automatically when slots are
busy; no separate driver fallback parameter is needed.

The Nokia XG-040G-MD UBI target uses a crypto-only device tree, selects the package, enables `CONFIG_CRYPTO_DEV_AIROHA_NPU` and `CONFIG_CRYPTO_ENGINE`, and includes patches 931 and 932. The device tree removes the Ethernet driver's NPU reference, so normal NPU network offload is unavailable. Patch 932 covers mainline WireGuard, not AmneziaWG.

To build the package in the configured tree, run `make package/kernel/airoha-npu-crypto/compile V=s -j1` there. The build host needs Perl and the `riscv64-unknown-elf-` toolchain. Installing a new firmware or module file does not replace the running instance; reboot to activate it. Do not reboot automatically on a remotely managed device.

From the project root, `./deploy.sh` synchronizes the package, builds the
firmware and NPU module in `/w/openwrt-nokia`, rebuilds patched `wireguard.ko`,
and deploys all three files to the SSH host
`yasnogor` using legacy SCP mode (`scp -O`). Set `OPENWRT_DIR`, `TARGET`, or
`JOBS` to override those defaults. The script installs files and prints their
hashes; it does not unload modules or reboot the target. WireGuard is built from
the matching cached `dl/linux-*.tar.xz` archive using the configured ARM64 kernel
and OpenWrt musl toolchain. The script checks that the target kernel release
matches before uploading files.

See the project README’s “NPU-only testing” section for strict test-mode parameters.
