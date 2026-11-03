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
remains accepted. The whole request is limited to 65535 bytes, including its
header, and the payload is limited to 16384 bytes. Profiling reserves the final
256 bytes of the slot, limiting the request to 65280 bytes. The mailbox length
field is 16 bits.

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
completes and clears the buffer after unpacking the result into the destination
scatterlist. The driver packs directly from the source scatterlist into each
slot's persistent DMA buffer and unpacks directly from it, avoiding a temporary
request allocation and two full-request copies. After a timeout the
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
`npu_enable` module parameter (default `1`) controls NPU use at runtime.
When disabled, requests return `-EAGAIN` without being retained.
Requests without `CRYPTO_TFM_REQ_MAY_BACKLOG` use the NPU only above 1024 bytes
of payload and return `-EAGAIN` if all slots are busy. Requests with that flag
bypass the size threshold and queue when busy. Up to 128 requests may wait
for a slot; queue overflow returns `-EAGAIN` without retaining the request or
invoking its callback. Accepted requests return `-EINPROGRESS` and receive one
completion callback, including during teardown.

WireGuard's `npu_only` parameter (default `0`) controls its data-crypto policy.
Normal mode uses software for small packets, busy hardware, and transport
failures. Test mode requests backlog for all data packets and drops packets
on submission or completion failure, with no software crypto fallback.
Handshakes remain in software. Disabling `npu_enable` in test mode drops data
packets. The former `npu_fallback` parameter has been removed; remove it from
module options. Other crypto clients requesting backlog now queue automatically.
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
requires the NPU clock rate. The host measurement covers submission through completion processing,
including completion delivery and queue scheduling, but excluding packing and
unpacking. Firmware `total` covers request execution but
excludes mailbox detection and publishing the completion. The leader and wait
intervals are included in the corresponding ChaCha20 and Poly1305 totals.
The wait interval begins after the leader's work and ends after every worker
completes; it is not the sum of worker execution times. Input/output copy and
scratch clearing are retained as zero-valued counters for comparison with older firmware. Individual firmware intervals use
32-bit cycle differences, so each interval must be shorter than one counter
wrap. Profiling adds overhead and snapshots from different slots are not atomic.

Host timing fields measure `host_submit` (DMA write barrier and mailbox writes)
and `host_poll` (waiting for completion). The obsolete `host_copy_in`,
`host_copy_out`, and `host_clear` fields remain zero for output compatibility.
Packing, unpacking, and clearing now occur outside the measured transport;
`host_ns` therefore cannot be compared directly with older driver totals.
Poll time includes firmware execution, mailbox delivery, polling delays and
scheduling; it is not host CPU time or pure overhead. Each interval is wall time
and may include preemption. Samples cover completed transfers; timeouts are not
included. The total also includes validation and timing overhead, so it need not
equal the sum of stage times.

Live requests use separate nonblocking submit and result operations. An
ordered engine workqueue serializes slot bookkeeping, packing, and unpacking,
while the NPU processes all configured slots concurrently. Submission returns
without sleeping for hardware. The queue 8 host interrupt schedules one shared
completion worker, which checks the active slots, completes only finished
requests, and admits queued backlog requests. Repeated or coalesced interrupts
are safe. No per-request worker waits on a completion wait queue. During
removal, accepted requests drain before the IRQ handler and watchdog are
removed and the workqueue is destroyed.

The `npu_interrupt` module parameter selects notification: `1` requests the
queue 8 host interrupt (default). A shared delayed-work watchdog checks active
slots once per kernel tick, recovers missed interrupts and detects the
one-second timeout. A timeout quarantines the entire DMA allocation and fails
all outstanding requests without unpacking or clearing their buffers.
With `npu_interrupt=0`, live requests rely on that watchdog for polling, which
adds up to one tick of detection latency; use interrupt mode for throughput
tests. Each request keeps the notification mode selected at submission.
Only probe self-tests still use the synchronous interrupt/polling wrapper.
The startup self-test checks the expected completion interrupts when enabled.
`host_poll` is elapsed wall time from submission to completion processing,
including firmware execution, interrupt delivery and workqueue scheduling.

The dedicated firmware uses the Cryptogams scalar RV32 Poly1305 block routine
for message segments. Its accumulator is converted for the existing parallel combiner;
unaligned input is copied in 16-byte chunks to avoid reads outside the input.
The QEMU suite tests the assembly for every batch size. QEMU validates
correctness but does not predict AN7581 performance.
