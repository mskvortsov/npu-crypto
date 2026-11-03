#!/usr/bin/env python3
"""Exercise actual patched callback/submission and TX batch code with fake hardware.

The fake AEAD can complete before submission returns or later, in arbitrary
order. ASan/UBSan check ownership; this does not emulate DMA or kernel teardown.
"""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
patch = (root / 'linux/wireguard-offload.patch').read_text()
def additions(name):
    section = next(s for s in patch.split('diff --git ') if s.startswith(f'a/drivers/net/wireguard/{name} '))
    return '\n'.join(line[1:] for line in section.splitlines() if line.startswith('+') and not line.startswith('+++'))

source = additions('npu_crypto.c')
source = '\n'.join(line for line in source.splitlines() if not line.startswith('#include'))
send = additions('send.c')
batch = send[send.index('struct encrypt_batch {'):send.index('static int encrypt_packet(')]
receive = additions('receive.c')
receive = receive[receive.index('static bool decrypt_finish('):receive.index('static int decrypt_packet(')]
with tempfile.TemporaryDirectory() as tmp:
    unit = Path(tmp) / 'async.c'
    unit.write_text((root / 'tests/wireguard_async_stubs.h').read_text() + '\n' + source + '\n' + batch + '\n' + receive + '\n' + (root / 'tests/wireguard_async_cases.c').read_text())
    binary = str(Path(tmp) / 'async')
    subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter', '-g', '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-pthread', '-o', binary, str(unit)], check=True)
    subprocess.run([binary], check=True)
