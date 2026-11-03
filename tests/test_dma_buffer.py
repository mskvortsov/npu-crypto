#!/usr/bin/env python3
"""Exercise real request packing/unpacking in persistent, isolated DMA slots."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
proto = (root / 'linux/airoha_npu_crypto_proto.c').read_text()
proto = proto[proto.index('int airoha_crypto_pack'):proto.index('MODULE_LICENSE')]
header = (root / 'linux/airoha_npu_crypto_proto.h').read_text()
header = header[header.index('struct airoha_crypto_request {'):header.index('int airoha_crypto_pack')]
platform = (root / 'linux/airoha_npu_platform.c').read_text()
slots = platform[platform.index('static void *airoha_crypto_buffer'):platform.index('static int airoha_crypto_transfer')]
source = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
typedef uint8_t u8;
typedef uint32_t __le32;
#define cpu_to_le32(x) (x)
#define le32_to_cpu(x) (x)
#define AIROHA_CRYPTO_VERSION 2
#define AIROHA_CRYPTO_TAG_SIZE 16
#define AIROHA_CRYPTO_MAX_DATA 16384
#define AIROHA_CRYPTO_MAX_REQUEST 65535
#define AIROHA_CRYPTO_NPU_BATCH_SIZE 4
#define NPU_DMA_SLOT_SIZE 65536
#define READ_ONCE(x) (x)
#define memzero_explicit(p, n) memset(p, 0, n)
struct airoha_crypto_dev { void *bounce; bool poisoned; };
struct scatterlist { u8 *data; size_t len; };
static int sg_nents_for_len(struct scatterlist *sg, size_t len)
{
    for (int i = 0; i < 3; i++) {
        if (len <= sg[i].len) return i + 1;
        len -= sg[i].len;
    }
    return -EINVAL;
}
static size_t sg_copy(struct scatterlist *sg, int n, void *buffer,
                      size_t len, size_t skip, bool to_buffer)
{
    size_t copied = 0;
    for (int i = 0; i < n && copied < len; i++) {
        if (skip >= sg[i].len) { skip -= sg[i].len; continue; }
        size_t part = sg[i].len - skip;
        if (part > len - copied) part = len - copied;
        if (to_buffer) memcpy((u8 *)buffer + copied, sg[i].data + skip, part);
        else memcpy(sg[i].data + skip, (u8 *)buffer + copied, part);
        copied += part;
        skip = 0;
    }
    return copied;
}
#define sg_pcopy_to_buffer(s,n,b,l,o) sg_copy(s,n,b,l,o,true)
#define sg_pcopy_from_buffer(s,n,b,l,o) sg_copy(s,n,b,l,o,false)
'''
source += header + proto + slots
source += r'''
int main(void)
{
    struct airoha_crypto_dev npu = { .bounce = malloc(4 * NPU_DMA_SLOT_SIZE) };
    assert(npu.bounce);
    memset(npu.bounce, 0xa5, 4 * NPU_DMA_SLOT_SIZE);
    u8 input[17000], output[17000], key[32] = {1}, nonce[12] = {2};
    for (size_t i = 0; i < sizeof(input); i++) input[i] = (u8)i;
    size_t sizes[] = {0, 1, 1420, AIROHA_CRYPTO_MAX_DATA};
    for (unsigned slot = 0; slot < 4; slot++) {
        struct airoha_crypto_request *req = airoha_crypto_buffer(&npu, slot);
        assert((void *)req == (u8 *)npu.bounce + slot * NPU_DMA_SLOT_SIZE);
        for (unsigned i = 0; i < sizeof(sizes)/sizeof(sizes[0]); i++) {
            size_t size = sizes[i], aad = 17, payload = size + aad;
            size_t capacity = sizeof(*req) + payload;
            struct scatterlist src[] = {{input, 7}, {input+7, 19},
                                        {input+26, sizeof(input)-26}};
            struct scatterlist dst[] = {{output, 11}, {output+11, 17},
                                        {output+28, sizeof(output)-28}};
            assert(airoha_crypto_pack(req, capacity, src, aad, size,
                                      key, nonce, false) == (int)capacity);
            assert(!memcmp(req->data, input, payload));
            assert(!memcmp(req->key, key, 32));
            memset(req->tag, 0x42, 16); /* Simulated firmware result. */
            assert(!airoha_crypto_unpack(req, capacity, dst, 1));
            assert(!memcmp(output, input, payload));
            for (unsigned j = 0; j < 16; j++) assert(output[payload+j] == 0x42);
            memcpy(input + payload, req->tag, 16);
            assert(airoha_crypto_pack(req, capacity, src, aad, size+16,
                                      key, nonce, true) == (int)capacity);
            memset(output, 0xcc, sizeof(output));
            assert(airoha_crypto_unpack(req, capacity, dst, 2) == -EBADMSG);
            for (unsigned j = 0; j < sizeof(output); j++) assert(output[j] == 0xcc);
            assert(!airoha_crypto_unpack(req, capacity, dst, 1));
            assert(!memcmp(output, input, payload));
            u8 guard = ((u8 *)req)[capacity];
            airoha_crypto_release(&npu, slot, capacity);
            for (unsigned j = 0; j < capacity; j++) assert(((u8 *)req)[j] == 0);
            assert(((u8 *)req)[capacity] == guard);
            /* A timeout must leave DMA memory untouched and reject new users. */
            memset(req, 0x5a, capacity);
            npu.poisoned = true;
            airoha_crypto_release(&npu, slot, capacity);
            for (unsigned j = 0; j < capacity; j++) assert(((u8 *)req)[j] == 0x5a);
            assert(!airoha_crypto_buffer(&npu, slot));
            npu.poisoned = false;
            airoha_crypto_release(&npu, slot, capacity);
        }
        if (slot < 3)
            for (unsigned j = 0; j < NPU_DMA_SLOT_SIZE; j++)
                assert(((u8 *)npu.bounce)[(slot+1)*NPU_DMA_SLOT_SIZE+j] == 0xa5);
    }
    assert(!airoha_crypto_buffer(&npu, 4));
    free(npu.bounce);
}
'''
with tempfile.TemporaryDirectory() as tmp:
    path = Path(tmp)
    (path / 'test.c').write_text(source)
    subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-g', str(path / 'test.c'),
                    '-o', str(path / 'test')], check=True)
    subprocess.run([str(path / 'test')], check=True)
print('Direct DMA buffers: fragmented SG, slot isolation, authentication failure, clearing and quarantine passed')
