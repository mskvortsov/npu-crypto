# ChaCha20-Poly1305

`npu_crypto.c` contains an RFC 8439 ChaCha20-Poly1305 AEAD core. It accepts
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
`cc` and Python's `cryptography` package; it compares randomized inputs
against that implementation, tests in-place operation and checks that a bad
tag leaves the ciphertext unchanged. The core also compiles for RV32 as part of the dedicated firmware build.

## Dedicated image

`make crypto-firmware` builds `build/AN7581_CRYPTO/npu_rv32.bin`. This
experimental image uses eight harts for one request at a time and does not
initialize or provide the normal NPU firmware services. Hart 0 coordinates the
request; all harts split both the ChaCha20 blocks and Poly1305 input blocks.
Each hart computes its partial accumulator and power of r, and hart 0 combines
the results modulo 2^130-5. For decryption, authentication completes before
any plaintext is produced. Its data image is empty. The
image requires a dedicated host driver; it is not compatible with the existing
Airoha NPU driver. A prototype dedicated Linux driver and WireGuard patch
are in `linux/` and have been exercised on the selected OpenWrt target.

The host must clear MIB30 and MIB31 before starting all eight harts, then wait
for `0x43525931` in MIB31 before submitting a request. Hart 0 signals MIB30
after clearing shared state, then waits for all seven workers to start before
publishing readiness. If a worker does not start, the driver times out and
WireGuard can use software crypto. Queue 0 uses the request layout above.
For each request, the host writes CTRL0 (DMA address), CTRL1 (buffer size), and
CTRL3 (1: slot 0, blocking), in that order, then increments CTRL2 as the final
doorbell write. It must serialize requests and wait for CTRL3 bit 1 before
reading status and the DMA buffer. The firmware polls the doorbell and writes
status in CTRL3 bits 4:2. This ordering differs from the existing host
mailbox helper. Host DMA and MMIO ordering must be enforced by the driver.

Version 2 adds associated data for Linux AEAD requests. Its header is 76 bytes:
version, operation, data length and associated-data length are four
little-endian words at offsets 0, 4, 8 and 12; nonce, key and tag are at
16, 28 and 60. The associated data immediately follows the header and the
in-place data follows that. The mailbox length covers all three. Version 1
remains accepted. The sum must fit in the mailbox's 16-bit length field and
the data portion remains limited to 16384 bytes.

`python3 tests/test_crypto_request.py` exercises both associated-data and
payload boundaries through the version 2 request processor. It does not test
mailbox registers, DMA, or an NPU hart.

`linux/airoha_npu_crypto_proto.c` marshals Linux scatterlists into version 2
requests. `linux/airoha_npu_engine.c` registers an asynchronous AEAD algorithm
under the private name `airoha-npu-chacha20poly1305`. The platform driver in
`linux/airoha_npu_platform.c` loads `airoha/an7581_crypto.bin` and owns queue 0.
It uses a coherent bounce buffer and permanently quarantines it after a
timeout, because no hart stop sequence has been verified. It refuses to probe
if an enabled network device still references the same NPU. A crypto-only
device tree must remove those references and cannot use NPU PPE offload.

`linux/wireguard-offload.patch` routes mainline WireGuard transport encryption
and decryption through this private algorithm, falling back to software when
it is unavailable or the transport fails. It allocates an AEAD transform per
packet. The patch does not cover AmneziaWG.
The Nokia XG-040G-MD UBI OpenWrt target selects this package and uses a
crypto-only device tree. Basic firmware, DMA transport and WireGuard traffic have been exercised on hardware; reset and removal behavior remain unverified.

The dedicated firmware stages each request in a 16,460-byte SRAM buffer. It
copies aligned words from uncached host memory, processes the request in SRAM,
then copies successful results back and clears the scratch buffer. Requests
whose header and payload exceed the buffer are rejected for software fallback.
Run `python3 tests/test_crypto_scratch.py` to test boundary lengths, failure
without host-buffer modification and scratch clearing; hardware timing and
DMA behavior are not covered by that test.

Run `tests/test_crypto_qemu.sh` to exercise the cooperative ChaCha20 path on
eight emulated RV32 harts with known authenticated ciphertexts, associated
data, and altered tags. This does not
validate the AN7581 boot registers, SRAM ordering, or hardware performance.

Run `python3 tests/test_poly_parallel.py` to compare 500 chunked Poly1305
requests with an independent ChaCha20-Poly1305 implementation. The tests do
not measure AN7581 hardware performance.

The dedicated image uses the scalar RV32 `ChaCha20_ctr32` generated from
`crypto_standalone/cryptogams/chacha-riscv.pl`. Each hart passes its contiguous
block range and starting counter; the wrapper copies keys and nonce words into
aligned local arrays. The scalar epilogue clears its 64-byte state buffer, and
the wrapper clears its key and counter arrays. The portable C implementation is also used by the host tests. The Cryptogams license is in
`crypto_standalone/cryptogams/LICENSE` and is included in the OpenWrt package.
The QEMU test exercises 40 AEAD vectors, bad tags, unaligned buffers and
in-place operation with nonzero starting counters.

By default, the Linux engine admits one request at a time. The writable
`npu_enable` module parameter controls NPU use at runtime. When enabled, only
requests with more than 1024 bytes of payload are submitted to the NPU; smaller
requests return `-EAGAIN` so the WireGuard patch uses its software
ChaCha20-Poly1305 path, which may use NEON. Set
`/sys/module/airoha_npu_crypto/parameters/npu_enable` to `0` to send all
requests through that software path, or `1` to enable the size threshold again.
If the NPU is already busy, larger requests also fall back to software.
The read-only parameters `npu_submitted` and
`npu_busy` count accepted and busy-rejected requests respectively since the
module was loaded; requests skipped because they are small or NPU use is
disabled do not increment either counter. Busy counts are requests offered to
this private algorithm, not a direct measurement of NEON use. Authentication
failures do not fall back.
