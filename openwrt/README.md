# OpenWrt integration

`package/kernel/airoha-npu-crypto/` is the package snapshot. After changing firmware or driver sources, run `./openwrt/sync-package.sh` from the project root to refresh it. To also refresh the package directly in an existing OpenWrt tree, run:

```sh
./openwrt/sync-package.sh /w/openwrt-nokia
```

The script copies the package recipe and its source files; it does not change kernel configuration, device trees, patches, or build the image. The project sources are the authoritative copies. `target/linux/airoha/` contains snapshots of the target files currently used in `/w/openwrt-nokia`, provided for reference and migration. Review and apply changes to an OpenWrt tree deliberately: full target files can contain unrelated target-specific configuration.

The Nokia XG-040G-MD UBI target uses a crypto-only device tree, selects the package, enables `CONFIG_CRYPTO_DEV_AIROHA_NPU` and `CONFIG_CRYPTO_ENGINE`, and includes patches 931 and 932. The device tree removes the Ethernet driver's NPU reference, so normal NPU network offload is unavailable. Patch 932 must be kept consistent with `linux/wireguard-offload.patch`; it covers mainline WireGuard, not AmneziaWG.

To build the package in the configured tree, run `make package/kernel/airoha-npu-crypto/compile V=s -j1` there. The build host needs Perl and the `riscv64-unknown-elf-` toolchain. Installing a new firmware or module file does not replace the running instance; reboot to activate it. Do not reboot automatically on a remotely managed device.

From the project root, `./deploy.sh` synchronizes the package, builds the
firmware and module in `/w/openwrt-nokia`, and deploys them to the SSH host
`yasnogor` using legacy SCP mode (`scp -O`). Set `OPENWRT_DIR`, `TARGET`, or
`JOBS` to override those defaults. The script installs files and prints their
hashes; it does not unload the current module or reboot the target.
