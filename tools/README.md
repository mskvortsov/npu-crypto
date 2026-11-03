# libkcapi benchmark

Build for the Nokia XG-040G-MD (AN7581, AArch64 musl):

```sh
make benchmark
# Override as needed:
OPENWRT_DIR=/path/to/openwrt make benchmark
```

The build script downloads upstream libkcapi 1.5.0, verifies its SHA-256,
then builds `build/kcapi-bench` with the OpenWrt cross-compiler. Both libkcapi
and musl are linked statically; no userspace libraries need installing on the
device. Host prerequisites: curl, tar, autotools, libtool, make, and the
configured OpenWrt toolchain. `BENCH_CC` overrides the compiler; `JOBS` controls
library build parallelism. Downloaded sources and artifacts stay under `build/`.

The device needs `kmod-crypto-user` (including `af_alg` and `algif_aead`) and
the NPU crypto module/firmware. The current `/w/openwrt-nokia` kernel configuration
has `CONFIG_CRYPTO_USER_API_AEAD` disabled. Enable `CONFIG_PACKAGE_kmod-crypto-user`
in OpenWrt and rebuild the matching image/modules before running. A static
userspace binary cannot supply the missing kernel interface.

Copy and run manually once those prerequisites are installed:

```sh
scp -O build/kcapi-bench root@yasnogor:/tmp/
ssh root@yasnogor '/tmp/kcapi-bench -s 1420 -j 4 -t 5'
```

Defaults: NPU algorithm `airoha-npu-chacha20poly1305`, 1420-byte payload,
no associated data, one worker, three seconds **per direction**. Options:

| Option | Meaning |
| --- | --- |
| `-a name` | Exact kernel algorithm or driver name from `/proc/crypto` |
| `-s bytes` | Payload size, 1–60000 |
| `-A bytes` | Associated data size, 0–256 |
| `-j workers` | Concurrent synchronous requests, 1–64 |
| `-t seconds` | Duration per encryption/decryption phase, 1–3600 |
| `-h` | Help |

For a software comparison, use `-a 'rfc7539(chacha20,poly1305)'` or its exact
software driver name from `/proc/crypto`. Algorithms must accept 32-byte keys,
12-byte nonces and 16-byte tags. An unavailable requested algorithm fails;
the benchmark does not substitute another algorithm.

Try `-j 1`, `-j 2`, `-j 4`, and `-j 8` at payload sizes 64, 256, 1420,
and 8192. Each worker opens its own handle with a random key. Before timing,
every worker checks an encrypt/decrypt round trip and rejection of a damaged
tag. Encryption uses increasing nonces; decryption repeatedly processes the
last valid ciphertext. Each phase starts workers together and measures wall
time with `CLOCK_MONOTONIC`.

Output reports aggregate operations/s, payload MiB/s and Mbit/s (excluding
AAD/tag bytes). `mean-us/op` is elapsed time times worker count divided by
completed operations: an approximate per-worker service time, not a latency
percentile. Results include libkcapi, AF_ALG syscalls, scheduling and driver
overhead. The benchmark explicitly uses the sendmsg path. It does not measure
WireGuard throughput or isolate firmware execution time. Requests in flight
are allowed to finish at the end of a phase; a stalled kernel request can
therefore exceed the requested duration.
