/* Model the host mailbox registers in QEMU RAM. The firmware still runs its
 * real service loop on harts 0..7; hart 8 plays the role of the Linux host. */
#include "npu_crypto.h"
#include "npu_regs.h"
#include "npu_crypto_profile.h"

#define READY 0x43525931
#define ROUNDS 100
static volatile u32 registers[0x200 / 4];
volatile u32 npu_qemu_notify_lock;
static u32 notifications;
struct request { u32 version, op, length, aad_len; u8 nonce[12], key[32], tag[16], data[65536 - 76]; };
static struct request requests[AIROHA_CRYPTO_NPU_BATCH_SIZE];
static const u8 expected_tag[16] = { 0xc0,0xbc,0x73,0x67,0xf0,0x09,0xf0,0x2d,0x8e,0xd6,0x51,0x29,0xf5,0x23,0xc5,0x7f };

static void finish(u32 value) { *(volatile u32 *)0x100000 = value; for (;;) {} }
volatile u32 *npu_crypto_qemu_reg(u32 addr)
{
 if (addr < NPU_MBOX_BASE || addr >= NPU_MBOX_BASE + sizeof(registers) || (addr & 3))
  finish(0x13333);
 return &registers[(addr - NPU_MBOX_BASE) / 4];
}
static void fence(void) { __asm__ volatile("fence iorw, iorw" ::: "memory"); }
static void service_notification(void)
{
 u32 seq = REG32(MBQ_CTRL2(MBQ_NOTIFY));
 if (seq != notifications) {
  fence();
  if (seq != notifications + 1) finish(0x13333);
  notifications = seq;
  REG32(MBQ_CTRL3(MBQ_NOTIFY)) = 2;
 }
}
static void submit(u32 group)
{
 u32 q = AIROHA_CRYPTO_NPU_QUEUE(group), seq;
 REG32(MBQ_CTRL0(q)) = (u32)&requests[group];
 REG32(MBQ_CTRL1(q)) = 76 + requests[group].aad_len + requests[group].length;
 REG32(MBQ_CTRL3(q)) = 1 | AIROHA_PROFILE_FLAG | AIROHA_INTERRUPT_FLAG;
 fence();
 seq = REG32(MBQ_CTRL2(q));
 REG32(MBQ_CTRL2(q)) = seq + 1;
}
static void wait_done(u32 group)
{
 u32 q = AIROHA_CRYPTO_NPU_QUEUE(group), count, ctrl;
 for (count = 0; count < 200000000; count++) {
  service_notification();
  ctrl = REG32(MBQ_CTRL3(q));
  if (ctrl & 2) {
   fence();
   if (((ctrl >> 2) & 7) != 1) finish(0x13333);
   if (!((struct airoha_profile_sample *)((u8 *)&requests[group] + AIROHA_PROFILE_OFFSET))->total)
    finish(0x13333);
   return;
  }
 }
 finish(0x13333);
}
void mailbox_test_main(void)
{
 u32 count, g, i, round;
 for (count = 0; REG32(NPU_MIB31) != READY; count++)
  if (count == 200000000) finish(0x13333);
 fence();
 for (round = 0; round < ROUNDS; round++) {
  for (g = 0; g < AIROHA_CRYPTO_NPU_BATCH_SIZE; g++) {
   struct request *r = &requests[g];
   r->version = 2; r->length = 1500; r->aad_len = 127; r->op = 0;
   for (i = 0; i < 12; i++) r->nonce[i] = i + 8 * 29;
   for (i = 0; i < 32; i++) r->key[i] = i + 8 * 17;
   for (i = 0; i < r->aad_len; i++) r->data[i] = 255 - i;
   for (i = 0; i < r->length; i++) r->data[r->aad_len+i] = i;
   submit(g);
  }
  for (g = 0; g < AIROHA_CRYPTO_NPU_BATCH_SIZE; g++) {
   wait_done(g);
   for (i = 0; i < 16; i++)
    if (requests[g].tag[i] != expected_tag[i]) finish(0x13333);
   requests[g].op = 1;
   submit(g);
  }
  for (g = 0; g < AIROHA_CRYPTO_NPU_BATCH_SIZE; g++) {
   wait_done(g);
   for (i = 0; i < requests[g].length; i++)
    if (requests[g].data[requests[g].aad_len+i] != (u8)i) finish(0x13333);
  }
 }
 for (count = 0; notifications < 2 * ROUNDS * AIROHA_CRYPTO_NPU_BATCH_SIZE; count++) {
  if (count == 200000000) finish(0x13333);
  service_notification();
 }
 finish(0x5555);
}
