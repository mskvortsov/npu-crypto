#!/usr/bin/env python3
"""Run the actual asynchronous engine lifecycle with a simulated transport."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
engine = (root / 'linux/airoha_npu_engine.c').read_text()

def block(start):
    pos = engine.index(start)
    opening = engine.index('{', pos)
    depth = 1
    end = opening + 1
    while depth:
        depth += (engine[end] == '{') - (engine[end] == '}')
        end += 1
    return engine[pos:end]

source = (root / 'tests/engine_async_stubs.h').read_text()
for name in ('airoha_crypto_slot', 'airoha_crypto_engine', 'airoha_crypto_ctx', 'airoha_crypto_work'):
    source += block('struct ' + name + ' {') + ';\n'
source += '''
static atomic_t npu_submitted, npu_busy;
static bool npu_enable = true;
static void airoha_do_work(struct work_struct *work);
void airoha_crypto_engine_notify(struct airoha_crypto_engine *e, unsigned slots);
'''
for signature in (
    'static int airoha_reserve_slot(', 'static int airoha_enqueue(',
    'static void airoha_finish(',
    'static void airoha_do_work(struct work_struct *work)\n{',
    'static void airoha_completions(',
    'void airoha_crypto_engine_notify(', 'static void airoha_watchdog(',
):
    source += block(signature) + '\n'
source += (root / 'tests/engine_async_cases.c').read_text()
with tempfile.TemporaryDirectory() as tmp:
    path = Path(tmp)
    (path / 'test.c').write_text(source)
    subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-g', str(path / 'test.c'),
                    '-o', str(path / 'test')], check=True)
    subprocess.run([str(path / 'test')], check=True)
print('Async engine: nonblocking submission, early/coalesced/repeated IRQ, backlog, watchdog, errors and callback ownership passed')
