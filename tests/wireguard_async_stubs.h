/* SPDX-License-Identifier: GPL-2.0-only */
/* Minimal host substitutes for testing the patched code, not kernel behavior. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <pthread.h>
typedef uint8_t u8;
typedef uint64_t u64;
typedef atomic_int atomic_t;
typedef atomic_int refcount_t;
#define atomic_inc(p) ((void)atomic_fetch_add(p, 1))
#define atomic_dec_and_test(p) (atomic_fetch_sub(p, 1) == 1)
#define atomic_set(p, n) atomic_store(p, n)
#define atomic_read(p) atomic_load(p)
#define refcount_inc atomic_inc
#define refcount_dec_and_test atomic_dec_and_test
#define refcount_set atomic_set
#define READ_ONCE(x) (x)
#define module_param_named(...)
#define MODULE_PARM_DESC(...)
#define GFP_KERNEL 0
#define CRYPTO_TFM_REQ_MAY_SLEEP 1
#define CRYPTO_TFM_REQ_MAY_BACKLOG 2
#define IS_ERR(p) ((intptr_t)(p) < 0)
#define rcu_read_lock() ((void)0)
#define rcu_read_unlock() ((void)0)
#define struct_size(p, member, n) (sizeof(*(p)) + sizeof((p)->member[0]) * (n))
static int fail_alloc;
static void *test_alloc(size_t n) {
 if (fail_alloc && !--fail_alloc) return NULL;
 return calloc(1, n);
}
#define kzalloc(n, flags) test_alloc(n)
#define kfree free
#define kfree_sensitive free
struct scatterlist { void *buf; unsigned int length; };
struct crypto_aead { int dummy; };
struct wg_peer { atomic_t npu_inflight; atomic_t refs; atomic_t npu_wait; };
struct noise_keypair {
 struct crypto_aead *npu_sending, *npu_receiving;
 struct { struct wg_peer *peer; } entry;
 struct { u8 key[32]; } sending, receiving;
};
struct aead_request {
 struct scatterlist *sg;
 u8 *iv;
 size_t len;
 void (*complete)(void *, int);
 void *data;
};
static int alloc_tfm_fail, setkey_fail, auth_fail;
static struct crypto_aead *crypto_alloc_aead(const char *n, int a, int b) {
 return alloc_tfm_fail ? (void *)(intptr_t)-ENOENT : test_alloc(sizeof(struct crypto_aead));
}
static int crypto_aead_setkey(struct crypto_aead *t, const u8 *k, int n) { assert(n == 32); return setkey_fail; }
static int crypto_aead_setauthsize(struct crypto_aead *t, int n) { assert(n == 16); return auth_fail; }
#define crypto_free_aead free
static struct aead_request *aead_request_alloc(struct crypto_aead *t, int flags) { return test_alloc(sizeof(struct aead_request)); }
#define aead_request_free free
extern bool wg_npu_only;
static void aead_request_set_callback(struct aead_request *r, int flags, void (*cb)(void *, int), void *data) {
 assert(!!(flags & CRYPTO_TFM_REQ_MAY_BACKLOG) == wg_npu_only); r->complete = cb; r->data = data;
}
static void aead_request_set_ad(struct aead_request *r, int n) { assert(!n); }
static void aead_request_set_crypt(struct aead_request *r, struct scatterlist *s, struct scatterlist *d, size_t n, u8 *iv) {
 assert(s == d); r->sg = s; r->len = n; r->iv = iv;
}
static void put_unaligned_le64(u64 n, u8 *p) { for(int i=0;i<8;i++) p[i]=(u8)(n>>(8*i)); }
static struct wg_peer *wg_peer_get(struct wg_peer *p) { atomic_inc(&p->refs); return p; }
static void wg_peer_put(struct wg_peer *p) { assert(atomic_fetch_sub(&p->refs, 1) > 1); }
static void wake_up_all(atomic_t *p) { atomic_inc(p); }
static int software_calls;
static bool software_ok = true;
static bool software(struct scatterlist *s, size_t n, const void *a, int al, u64 counter, const u8 *key) {
 software_calls++; return software_ok;
}
#define chacha20poly1305_decrypt_sg_inplace software
#define chacha20poly1305_encrypt_sg_inplace software
/* Deferred, callback-before-return, or refused. */
static int submit_mode, early_status;
static struct aead_request *pending[32];
static unsigned int pending_count;
static int crypto_aead_encrypt(struct aead_request *r) {
 assert(!r->iv[0] && !r->iv[1] && !r->iv[2] && !r->iv[3]);
 if (submit_mode == 1) { r->complete(r->data, early_status); return -EINPROGRESS; }
 if (submit_mode == 2) return -EAGAIN;
 pending[pending_count++] = r; return -EINPROGRESS;
}
#define crypto_aead_decrypt crypto_aead_encrypt
struct sk_buff { int reset, data_offset, network_offset; unsigned int len; bool trim_fail; };
enum { PACKET_STATE_DEAD, PACKET_STATE_CRYPTED };
static int published, published_state;
static void wg_reset_packet(struct sk_buff *s, bool tx) { assert(tx); s->reset++; }
static void wg_queue_enqueue_per_peer_tx(struct sk_buff *s, int state) { published++; published_state=state; }
static int skb_network_offset(struct sk_buff *s) { return s->network_offset - s->data_offset; }
static void skb_push(struct sk_buff *s, unsigned int n) { s->data_offset -= n; s->len += n; }
static void skb_pull(struct sk_buff *s, unsigned int n) { s->data_offset += n; s->len -= n; }
static unsigned int noise_encrypted_len(unsigned int n) { return n + 16; }
static int pskb_trim(struct sk_buff *s, unsigned int n) { if(s->trim_fail) return -ENOMEM; s->len=n; return 0; }
static int rx_published, rx_state;
static void wg_queue_enqueue_per_peer_rx(struct sk_buff *s, int state) { rx_published++; rx_state=state; }
