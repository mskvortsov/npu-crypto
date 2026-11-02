#!/usr/bin/env python3
"""Compare the firmware AEAD core against Python cryptography's implementation."""
import ctypes
import os
import subprocess
import tempfile

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def buf(data):
    return ctypes.create_string_buffer(data, max(1, len(data)))


with tempfile.TemporaryDirectory() as tmp:
    lib = os.path.join(tmp, 'crypto.so')
    subprocess.run(['cc', '-shared', '-fPIC', '-Wall', '-Wextra', '-Werror',
                    '-o', lib, 'npu_crypto.c'], check=True)
    crypt = ctypes.CDLL(lib).npu_chacha20poly1305
    for length in (0, 1, 15, 16, 17, 63, 64, 65, 127, 128, 129, 1500, 65535):
        for aad_len in (0, 1, 15, 16, 17, 65):
            key, nonce = os.urandom(32), os.urandom(12)
            plain, aad = os.urandom(length), os.urandom(aad_len)
            expected = ChaCha20Poly1305(key).encrypt(nonce, plain, aad)
            data, tag = buf(plain), ctypes.create_string_buffer(16)
            assert crypt(data, data, length, buf(aad), aad_len, buf(key),
                         buf(nonce), tag, 0) == 0
            assert data.raw[:length] + tag.raw == expected
            assert crypt(data, data, length, buf(aad), aad_len, buf(key),
                         buf(nonce), tag, 1) == 0
            assert data.raw[:length] == plain
            data = buf(expected[:-16])
            tag = buf(bytes([expected[-16] ^ 1]) + expected[-15:])
            assert crypt(data, data, length, buf(aad), aad_len, buf(key),
                         buf(nonce), tag, 1) == -1
            assert data.raw[:length] == expected[:-16]
print('ChaCha20-Poly1305: 78 cases passed')
