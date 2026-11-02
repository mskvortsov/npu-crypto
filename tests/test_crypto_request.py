#!/usr/bin/env python3
"""Test the versioned host request format without device hardware."""
import ctypes
import os
import struct
import subprocess
import tempfile

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

with tempfile.TemporaryDirectory() as tmp:
    path = os.path.join(tmp, 'crypto.so')
    subprocess.run(['cc', '-shared', '-fPIC', '-Wall', '-Wextra', '-Werror',
                    '-DAN7581', '-DNOWIFI', '-DNPU_CRYPTO_TEST',
                    '-o', path, 'npu_crypto.c'], check=True)
    process = ctypes.CDLL(path).npu_crypto_process
    process.argtypes = [ctypes.c_void_p, ctypes.c_uint]
    for size in (0, 1, 15, 16, 17, 64, 1500):
        for aad_len in (0, 1, 16, 31):
            key, nonce = os.urandom(32), os.urandom(12)
            aad, plain = os.urandom(aad_len), os.urandom(size)
            expected = ChaCha20Poly1305(key).encrypt(nonce, plain, aad)
            raw = (struct.pack('<IIII', 2, 0, size, aad_len) + nonce + key +
                   bytes(16) + aad + plain)
            request = ctypes.create_string_buffer(raw, len(raw))
            assert process(request, len(raw)) == 1
            result = request.raw
            assert result[76:76 + aad_len] == aad
            assert result[76 + aad_len:] + result[60:76] == expected
            struct.pack_into('<I', request, 4, 1)
            assert process(request, len(raw)) == 1
            assert request.raw[76 + aad_len:] == plain
            # A truncated payload must not be touched.
            before = request.raw
            assert process(request, len(raw) - 1) == 0
            assert request.raw == before
    invalid = ctypes.create_string_buffer(struct.pack('<IIII', 2, 0, 0, 0) + bytes(56))
    assert process(invalid, 72) == 0
print('Crypto request ABI: 28 cases passed')
