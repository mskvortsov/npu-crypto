#!/usr/bin/env python3
"""Exercise actual mailbox submit/result/IRQ code with simulated registers."""
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
platform = (root / 'linux/airoha_npu_platform.c').read_text()

def block(start):
    pos = platform.index(start)
    opening = platform.index('{', pos)
    depth, end = 1, opening + 1
    while depth:
        depth += (platform[end] == '{') - (platform[end] == '}')
        end += 1
    return platform[pos:end]

source = r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
typedef uint32_t u32;
typedef uint64_t u64;
typedef u64 dma_addr_t;
typedef int spinlock_t;
typedef int wait_queue_head_t;
typedef int atomic_t;
typedef int irqreturn_t;
#define __iomem
#define IRQ_NONE 0
#define IRQ_HANDLED 1
#define BIT(n) (1U << (n))
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define smp_load_acquire(p) (*(p))
#define lower_32_bits(x) ((u32)(x))
#define usecs_to_jiffies(x) ((x)/1000)
#define time_after_eq(a,b) ((long)((a)-(b))>=0)
#define spin_lock_irqsave(l,f) do { (void)(l); (f)=0; } while(0)
#define spin_unlock_irqrestore(l,f) do { (void)(l); (void)(f); } while(0)
#define max(a,b) ((a)>(b)?(a):(b))
#define max_t(t,a,b) max((t)(a),(t)(b))
#define memzero_explicit(p,n) memset(p,0,n)
#define dev_err(...) (++error_logs)
static unsigned error_logs, notifications, wakeups, irq_freed, barriers;
static bool npu_profile, npu_interrupt=true;
static unsigned long jiffies;
static u64 clock_ns;
static u64 ktime_get_ns(void) { clock_ns+=10; return clock_ns; }
static void dma_wmb(void) { barriers++; }
static void dma_rmb(void) { barriers++; }
static u32 readl(void *p) { return *(u32 *)p; }
static void writel(u32 v,void *p) { *(u32 *)p=v; }
static void atomic_inc(int *a) { ++*a; }
static void wake_up(int *w) { (void)w; wakeups++; }
static void airoha_crypto_engine_notify(void *e) { assert(e); notifications++; }
static void devm_free_irq(void *d,int irq,void *npu) {
    (void)d; (void)npu; assert(irq==42); irq_freed++;
}
'''
source += (root / 'npu/npu_crypto_config.h').read_text()
source += (root / 'npu/npu_crypto_profile.h').read_text()
source += platform[platform.index('#define NPU_MBOX_CTRL0'):platform.index('/* There is no known safe way')]
for name in ('airoha_profile_aggregate', 'airoha_crypto_transfer_state', 'airoha_crypto_dev'):
    source += block('struct ' + name + ' {') + ';\n'
for signature in ('static irqreturn_t airoha_crypto_irq(',
                  'static void *airoha_crypto_buffer(', 'static void airoha_crypto_release(',
                  'static int airoha_crypto_submit(', 'static int airoha_crypto_timeout(',
                  'static int airoha_crypto_result(', 'static void airoha_crypto_stop('):
    source += block(signature) + '\n'
source += r'''
int main(void)
{
    struct airoha_crypto_dev npu={.regs=calloc(1,0x310000),
        .bounce=calloc(4,NPU_DMA_SLOT_SIZE),.dma=0x12340000,.irq=42};
    assert(npu.regs && npu.bounce);
    for (unsigned slot=0;slot<4;slot++) {
        unsigned q=AIROHA_CRYPTO_NPU_QUEUE(slot);
        void *p=airoha_crypto_buffer(&npu,slot); assert(p);
        memset(p,0x5a,1496);
        assert(!airoha_crypto_submit(&npu,slot,1496));
        assert(readl(npu.regs+NPU_MBOX_CTRL0(q))==0x12340000+slot*NPU_DMA_SLOT_SIZE);
        assert(readl(npu.regs+NPU_MBOX_CTRL1(q))==1496);
        assert(readl(npu.regs+NPU_MBOX_CTRL2(q))==1);
        assert(readl(npu.regs+NPU_MBOX_CTRL3(q))==(NPU_WAIT|AIROHA_INTERRUPT_FLAG));
        assert(airoha_crypto_result(&npu,slot)==-EINPROGRESS);
        assert(((u32 *)p)[0]==0x5a5a5a5a);
    }
    assert(airoha_crypto_irq(42,&npu)==IRQ_NONE);
    writel(NPU_MBOX_HOST_BIT,npu.regs+NPU_MBOX_INT_STATUS);
    assert(airoha_crypto_irq(42,&npu)==IRQ_HANDLED);
    assert(wakeups==1 && !notifications); /* Probe self-test only. */
    npu.engine=(void *)1;
    assert(airoha_crypto_irq(42,&npu)==IRQ_HANDLED);
    assert(wakeups==1 && notifications==1);
    writel(NPU_DONE|(1<<2),npu.regs+NPU_MBOX_CTRL3(0));
    assert(airoha_crypto_result(&npu,0)==1);
    airoha_crypto_release(&npu,0,1496);
    assert(!*(u32 *)npu.bounce);
    assert(*(u32 *)(npu.bounce+NPU_DMA_SLOT_SIZE)==0x5a5a5a5a);
    writel(NPU_DONE|(2<<2),npu.regs+NPU_MBOX_CTRL3(2));
    assert(airoha_crypto_result(&npu,1)==2); /* Authentication failure. */
    jiffies=npu.transfer[2].deadline;
    assert(airoha_crypto_result(&npu,2)==-ETIMEDOUT);
    assert(npu.poisoned && error_logs==1);
    assert(airoha_crypto_result(&npu,3)==-ENODEV);
    assert(airoha_crypto_submit(&npu,0,1496)==-ENODEV);
    assert(!airoha_crypto_buffer(&npu,0));
    airoha_crypto_release(&npu,3,1496);
    assert(*(u32 *)(npu.bounce+3*NPU_DMA_SLOT_SIZE)==0x5a5a5a5a);
    airoha_crypto_stop(&npu);
    assert(irq_freed==1 && !npu.engine && !readl(npu.regs+NPU_MBOX_INT_MASK0));

    npu.poisoned=false; npu_profile=true; npu_interrupt=false;
    /* Deadlines must also work across an unsigned jiffies wrap. */
    jiffies=(unsigned long)-500;
    assert(!airoha_crypto_submit(&npu,0,1496));
    assert(npu.transfer[0].profile && !npu.transfer[0].interrupt);
    assert(airoha_crypto_result(&npu,0)==-EINPROGRESS);
    struct airoha_profile_sample sample={.total=1234};
    memcpy(npu.bounce+AIROHA_PROFILE_OFFSET,&sample,sizeof(sample));
    writel(NPU_DONE|(1<<2),npu.regs+NPU_MBOX_CTRL3(0));
    assert(airoha_crypto_result(&npu,0)==1);
    assert(npu.profile[0].count==1 && npu.profile[0].total_sum==1234);
    assert(npu.profile[0].host_ns_sum==20);
    assert(npu.profile[0].host_submit_ns_sum==10);
    assert(npu.profile[0].host_poll_ns_sum==10);
    assert(airoha_crypto_submit(&npu,4,1496)==-EINVAL);
    assert(airoha_crypto_submit(&npu,0,65536)==-EMSGSIZE);
    assert(!airoha_crypto_submit(&npu,0,AIROHA_PROFILE_OFFSET+1));
    assert(!npu.transfer[0].profile);
    jiffies=npu.transfer[0].deadline;
    assert(airoha_crypto_result(&npu,0)==-ETIMEDOUT);
    assert(barriers>=8);
    free(npu.regs); free(npu.bounce);
}
'''
with tempfile.TemporaryDirectory() as tmp:
    path = Path(tmp)
    (path / 'test.c').write_text(source)
    subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                    '-Wno-unused-parameter', '-fsanitize=address,undefined',
                    '-g', str(path / 'test.c'), '-o', str(path / 'test')], check=True)
    subprocess.run([str(path / 'test')], check=True)
print('Async transport: mailbox submission, interrupt dispatch, timeout quarantine, profiling and IRQ teardown passed')
