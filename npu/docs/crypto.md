# ChaCha20-Poly1305

`npu/npu_crypto.c` contains an RFC 8439 ChaCha20-Poly1305 AEAD core. It accepts
32-byte keys, 12-byte nonces and associated data. Decryption checks the tag
before writing plaintext. Input and output must be identical or disjoint.

The dedicated AN7581 image accepts version 1 requests using a
four-byte-aligned, bidirectional DMA buffer. Its little-endian layout is:

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 4 | version, 1 |
| 4 | 4 | operation: 0 encrypt, 1 decrypt |
| 8 | 4 | data length, at most 16384 |
| 12 | 12 | RFC 8439 nonce |
| 24 | 32 | key |
| 56 | 16 | tag: output for encryption, input for decryption |
| 72 | length | input and output data, in place |

Mailbox status 1 is success, 2 is authentication failure, and 0 is an invalid
request. Authentication failure leaves the ciphertext unchanged. The host
must keep the DMA buffer alive and unmodified until completion; a timeout
alone does not stop the hart.

Run `python3 tests/test_crypto.py` from the repository root. The test needs
`cc`, OpenSSL development headers and library, and Python's `cryptography` package; it compares randomized inputs
against that implementation, tests in-place operation and checks that a bad
tag leaves the ciphertext unchanged. The core also compiles for RV32 as part of the dedicated firmware build.

## Dedicated image

`make crypto-firmware` builds `build/AN7581_CRYPTO/npu_rv32.bin`. This
experimental image uses all eight harts and does not initialize or provide the
normal NPU firmware services. `AIROHA_CRYPTO_NPU_BATCH_SIZE` selects 1, 2, 4,
or 8 simultaneous packets, with respectively 8, 4, 2, or 1 hart per packet.
Each group leader coordinates its packet and combines the Poly1305 portions
modulo 2^130-5. For decryption, authentication completes before
any plaintext is produced. Its data image is empty. The
image requires a dedicated host driver; it is not compatible with the existing
Airoha NPU driver. A prototype dedicated Linux driver and WireGuard patch
are in `linux/` and have been exercised on the selected OpenWrt target.

The host must clear MIB30 and MIB31 before starting all eight harts, then wait
for `0x43525931` in MIB31 before submitting a request. Hart 0 signals MIB30
after clearing shared state. Each group waits for every leader and worker to
start before publishing readiness. If a hart does not start, the driver times
out and WireGuard can use software crypto. Each group uses the mailbox queue
whose index equals its leader's hart ID, with the request layout above.
For each request, the host writes CTRL0 (DMA address), CTRL1 (buffer size), and
CTRL3 (bit 0 set, plus optional profiling bit 6 and interrupt bit 7), in
that order, then increments CTRL2 as the final doorbell write. It must serialize requests per queue and wait for CTRL3 bit 1 before
reading status and the DMA buffer. The firmware polls the doorbell and writes
status in CTRL3 bits 4:2. This ordering differs from the existing host
mailbox helper. Host DMA and MMIO ordering must be enforced by the driver.

Version 2 adds associated data for Linux AEAD requests. Its header is 76 bytes:
version, operation, data length and associated-data length are four
little-endian words at offsets 0, 4, 8 and 12; nonce, key and tag are at
16, 28 and 60. The associated data immediately follows the header and the
in-place data follows that. The mailbox length covers all three. Version 1
remains accepted. The dedicated service limits the whole request to 16460
bytes, including its header. For version 2, associated data plus payload must
therefore fit within 16384 bytes; the payload alone is also limited to 16384
bytes. The mailbox length field is 16 bits.

`python3 tests/test_crypto_request.py` exercises both associated-data and
payload boundaries through the version 2 request processor. It does not test
mailbox registers, DMA, or an NPU hart.

`linux/airoha_npu_crypto_proto.c` marshals Linux scatterlists into version 2
requests. `linux/airoha_npu_engine.c` registers an asynchronous AEAD algorithm
under the private name `airoha-npu-chacha20poly1305`. The platform driver in
`linux/airoha_npu_platform.c` loads `airoha/an7581_crypto.bin` and uses one
mailbox queue and one coherent bounce-buffer slot per packet group. Queue 8
provides shared host interrupt notification. A timeout poisons the device, so
subsequent transfers are refused, and the coherent buffer allocation is retained
because no hart stop sequence has been verified. It refuses to probe
if an enabled network device still references the same NPU. A crypto-only
device tree must remove those references and cannot use NPU PPE offload.

`linux/wireguard-offload.patch` routes mainline WireGuard transport encryption
and decryption through this private algorithm, falling back to software when
it is unavailable or the transport fails. It allocates an AEAD transform per
packet. The patch does not cover AmneziaWG.
The Nokia XG-040G-MD UBI OpenWrt target selects this package and uses a
crypto-only device tree. Basic firmware, DMA transport and WireGuard traffic have been exercised on hardware; reset and removal behavior remain unverified.

The dedicated firmware processes each request in place in its host DMA bounce
buffer through the NPU's uncached alias. Linux owns the slot until the NPU
completes and clears the buffer after copying the result. After a timeout the
whole allocation is retained because firmware may still access a slot. Requests larger than the
firmware request limit are rejected. Run `python3 tests/test_crypto_scratch.py`
to test boundary lengths and authentication failure without buffer modification;
hardware cache and DMA behavior are not covered by that test.

Run `tests/test_crypto_qemu.sh` to exercise the firmware's assembly crypto
and service on emulated RV32 harts for all four batch sizes. It tests 40 AEAD
vectors per packet group, including associated data, altered tags, unaligned
buffers, in-place operation and nonzero starting counters. It also runs 100
concurrent mailbox encrypt/decrypt rounds per batch size, with a ninth emulated
hart acting as the host. QEMU does not validate the AN7581 boot registers,
physical mailbox or mutex behavior, SRAM ordering, or hardware performance.

Run `python3 tests/test_poly_parallel.py` to compare 500 chunked Poly1305
requests with an independent ChaCha20-Poly1305 implementation. The tests do
not measure AN7581 hardware performance.

The dedicated image uses the scalar RV32 `ChaCha20_ctr32` generated from
`npu/cryptogams/chacha-riscv.pl`. Each hart passes its contiguous
block range and starting counter; the wrapper copies keys and nonce words into
aligned local arrays. The scalar epilogue clears its 64-byte state buffer, and
the wrapper clears its key and counter arrays. Native tests use a test-only
OpenSSL ChaCha20 adapter; QEMU tests execute the RISC-V assembly. The
Cryptogams license is in `npu/cryptogams/LICENSE` and is included in the
OpenWrt package.

By default, the Linux engine admits four NPU requests at a time. The writable
`npu_enable` module parameter controls NPU use at runtime. When enabled, only
requests with more than 1024 bytes of payload are submitted to the NPU; smaller
requests return `-EAGAIN` so the WireGuard patch uses its software
ChaCha20-Poly1305 path, which may use NEON. Set
`/sys/module/airoha_npu_crypto/parameters/npu_enable` to `0` to send all
requests through that software path, or `1` to enable the size threshold again.
If the NPU is already busy, `npu_fallback` selects software fallback when set
or queues the request for a free slot when cleared. When `npu_enable` is `0`,
`npu_fallback` has no effect. Both parameters default to `1`.
The read-only parameters `npu_submitted` and
`npu_busy` count accepted and busy-rejected requests respectively since the
module was loaded; requests skipped because they are small or NPU use is
disabled do not increment either counter. Busy counts are requests offered to
this private algorithm, not a direct measurement of NEON use. Authentication
failures do not fall back.

### Timing measurements

Timing collection is disabled by default. On a device running matching firmware
and module versions, enable it and read cumulative per-slot counters with:

```sh
echo 1 > /sys/module/airoha_npu_crypto/parameters/npu_profile
cat /sys/kernel/debug/airoha_npu_crypto/profile
```

Set the parameter to `0` to stop recording. Take snapshots before and after a
workload and subtract the counts and sums to isolate that workload. Maxima are
cumulative since driver probe and cannot be subtracted. Divide a sum difference
by the count difference for the mean per profiled request. Firmware values are
`mcycle` ticks, and Linux host values are nanoseconds; converting cycles to time
requires the NPU clock rate. The host measurement covers the transfer function,
including host copies and completion waiting. Firmware `total` covers request execution but
excludes mailbox detection and publishing the completion. The leader and wait
intervals are included in the corresponding ChaCha20 and Poly1305 totals.
The wait interval begins after the leader's work and ends after every worker
completes; it is not the sum of worker execution times. Input/output copy and
scratch clearing are retained as zero-valued counters for comparison with older firmware. Individual firmware intervals use
32-bit cycle differences, so each interval must be shorter than one counter
wrap. Profiling adds overhead and snapshots from different slots are not atomic.

Host timing fields break the transfer into `host_copy_in` (request to DMA),
`host_submit` (DMA write barrier and mailbox writes), `host_poll` (waiting for
completion), `host_copy_out` (DMA read barrier and result copy), and
`host_clear` (clearing the DMA request). Poll time includes firmware execution,
mailbox delivery, polling delays and scheduling; it is not host CPU time or
pure overhead. Each interval is wall time and may include preemption. Samples
cover completed transfers; timeouts are not included. The total also includes
validation and timing overhead, so it need not equal the sum of stage times.

The `npu_interrupt` module parameter selects completion handling: `1` uses the
queue 8 host interrupt (default), and `0` uses the previous polling path. Each
request keeps the mode selected when it was submitted. The startup self-test
checks that the expected completion interrupts are delivered when interrupt
mode is enabled. `host_poll` in the profile is the completion-wait interval in
either mode; in interrupt mode it includes interrupt delivery and scheduling.

The dedicated firmware uses the Cryptogams scalar RV32 Poly1305 block routine
for message segments. Its accumulator is converted for the existing parallel combiner;
unaligned input is copied in 16-byte chunks to avoid reads outside the input.
The QEMU suite tests the assembly for every batch size. QEMU validates
correctness but does not predict AN7581 performance.
