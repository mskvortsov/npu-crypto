#!/usr/bin/env python3
"""Exercise the in-place mailbox request without NPU MMIO."""
import ctypes
import os
import struct
import subprocess
import tempfile

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

with tempfile.TemporaryDirectory() as tmp:
    lib = os.path.join(tmp, 'crypto.so')
    subprocess.run(['cc', '-shared', '-fPIC', '-Wall', '-Wextra', '-Werror',
                    '-DAN7581', '-DNOWIFI', '-DNPU_CRYPTO_TEST', '-I.',
                    '-o', lib, 'npu/npu_crypto.c', 'npu/npu_service.c',
                    'tests/chacha_openssl.c', 'tests/poly1305_openssl.c', '-lcrypto'],
                   check=True)
    driver = ctypes.CDLL(lib)
    request = driver.npu_crypto_test_request
    request.argtypes = [ctypes.c_void_p, ctypes.c_uint]
    for size in (0, 1, 2, 3, 4, 15, 16, 17, 63, 64, 65, 1500, 16384):
        key, nonce, data = os.urandom(32), os.urandom(12), os.urandom(size)
        expected = ChaCha20Poly1305(key).encrypt(nonce, data, b'')
        raw = struct.pack('<IIII', 2, 0, size, 0) + nonce + key + bytes(16) + data
        padded = ctypes.create_string_buffer(raw + b'\xa5' * 4)
        assert request(padded, len(raw)) == 1
        assert padded.raw[76:76 + size] + padded.raw[60:76] == expected
        assert padded.raw[len(raw):len(raw) + 4] == b'\xa5' * 4
        struct.pack_into('<I', padded, 4, 1)
        assert request(padded, len(raw)) == 1
        assert padded.raw[76:76 + size] == data
        # A bad tag must not modify any host buffer byte.
        struct.pack_into('<I', padded, 4, 0)
        assert request(padded, len(raw)) == 1
        struct.pack_into('<I', padded, 4, 1)
        padded[60] = bytes([padded[60][0] ^ 1])
        before = padded.raw
        assert request(padded, len(raw)) == 2
        assert padded.raw == before
print('In-place crypto requests: 13 cases passed')
