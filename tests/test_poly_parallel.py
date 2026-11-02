#!/usr/bin/env python3
"""Differential tests for chunked Poly1305 through the firmware request path."""
import ctypes
import os
import random
import struct
import subprocess
import tempfile

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

rng = random.Random(7581)
with tempfile.TemporaryDirectory() as tmp:
    lib = os.path.join(tmp, 'crypto.so')
    subprocess.run(['cc', '-shared', '-fPIC', '-Wall', '-Wextra', '-Werror',
                    '-DAN7581', '-DNOWIFI', '-DNPU_CRYPTO_TEST', '-I.',
                    '-o', lib, 'npu_crypto.c', 'crypto_standalone/service.c'],
                   check=True)
    driver = ctypes.CDLL(lib)
    request = driver.npu_crypto_test_request
    request.argtypes = [ctypes.c_void_p, ctypes.c_uint]
    lengths = [0, 1, 15, 16, 17, 31, 32, 63, 64, 65, 127, 128, 129,
               255, 256, 511, 512, 513, 1500, 8192, 16000]
    for i in range(500):
        size = lengths[i % len(lengths)] if i < 210 else rng.randrange(8193)
        aad_len = rng.randrange(0, min(128, 16384 - size) + 1)
        key, nonce, data, aad = os.urandom(32), os.urandom(12), os.urandom(size), os.urandom(aad_len)
        expected = ChaCha20Poly1305(key).encrypt(nonce, data, aad)
        raw = struct.pack('<IIII', 2, 0, size, aad_len) + nonce + key + bytes(16) + aad + data
        buf = ctypes.create_string_buffer(raw, len(raw))
        assert request(buf, len(raw)) == 1, i
        assert buf.raw[76 + aad_len:] + buf.raw[60:76] == expected, i
        struct.pack_into('<I', buf, 4, 1)
        assert request(buf, len(raw)) == 1, i
        assert buf.raw[76 + aad_len:] == data, i
        assert driver.npu_crypto_test_scratch_clear() == 1, i
print('Parallel Poly1305: 500 differential cases passed')
