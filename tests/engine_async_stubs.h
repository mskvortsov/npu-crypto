/* Minimal kernel model for exercising the production engine functions. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
typedef uint8_t u8;
typedef uint32_t u32;
typedef int atomic_t;
typedef int refcount_t;
typedef int spinlock_t;
struct aead_alg { int unused; };
struct completion { int unused; };
struct rcu_head { int unused; };
#define AIROHA_CRYPTO_NPU_BATCH_SIZE 4
#define AIROHA_CRYPTO_MIN_NPU_PAYLOAD_SIZE 1024
#define AIROHA_CRYPTO_MAX_PENDING 128
#define AIROHA_CRYPTO_MAX_DATA 16384
#define AIROHA_CRYPTO_MAX_REQUEST 65535
#define AIROHA_CRYPTO_TAG_SIZE 16
#define CRYPTO_TFM_REQ_MAY_BACKLOG 1
#define GFP_ATOMIC 0
#define READ_ONCE(x) (x)
#define BIT(x) (1U << (x))
#define unlikely(x) (x)
#define WARN_ON_ONCE(x) assert(!(x))
#define container_of(p,t,m) ((t *)((char *)(p) - offsetof(t,m)))
#define spin_lock_irqsave(l,f) do { (void)(l); (f)=0; } while (0)
#define spin_unlock_irqrestore(l,f) do { (void)(l); (void)(f); } while (0)
#define kzalloc(n,f) calloc(1,n)
#define kfree(p) free(p)
#define kfree_rcu(p,m) free(p)
static int atomic_read(atomic_t *a) { return *a; }
static int atomic_cmpxchg(atomic_t *a,int old,int next) {
    int prev=*a; if (prev==old) *a=next; return prev;
}
static void atomic_andnot(unsigned mask,atomic_t *a) { *a &= ~mask; }
#define atomic64_inc(a) (++*(a))
struct list_head { struct list_head *next,*prev; };
static void INIT_LIST_HEAD(struct list_head *l) { l->next=l->prev=l; }
static bool list_empty(struct list_head *l) { return l->next==l; }
static void list_add_tail(struct list_head *n,struct list_head *h) {
    n->next=h; n->prev=h->prev; h->prev->next=n; h->prev=n;
}
static void list_del_init(struct list_head *n) {
    n->prev->next=n->next; n->next->prev=n->prev; INIT_LIST_HEAD(n);
}
#define list_first_entry(h,t,m) container_of((h)->next,t,m)
struct work_struct { void (*fn)(struct work_struct *); bool pending; };
struct delayed_work { struct work_struct work; bool armed; };
struct workqueue_struct { struct work_struct *items[1024]; unsigned count; };
#define INIT_WORK(w,f) do { (w)->fn=f; (w)->pending=false; } while (0)
#define to_delayed_work(w) container_of(w,struct delayed_work,work)
static bool queue_work(struct workqueue_struct *q,struct work_struct *w) {
    if (w->pending) return false;
    assert(q->count<1024); w->pending=true; q->items[q->count++]=w; return true;
}
static bool queue_delayed_work(struct workqueue_struct *q,struct delayed_work *w,int delay) {
    (void)q; assert(delay==1);
    if (w->armed) return false;
    w->armed=true; return true;
}
static void run_queue(struct workqueue_struct *q) {
    unsigned guard=0;
    while (q->count) {
        assert(++guard<4096);
        struct work_struct *w=q->items[0];
        memmove(q->items,q->items+1,--q->count*sizeof(*q->items));
        w->pending=false; w->fn(w);
    }
}
struct airoha_crypto_engine;
struct airoha_crypto_transport {
    void *(*buffer)(void *,unsigned);
    int (*submit)(void *,unsigned,size_t);
    int (*result)(void *,unsigned);
    void (*stop)(void *);
    void (*release)(void *,unsigned,size_t);
    void *ctx;
};
struct crypto_aead { void *ctx; };
struct aead_request {
    struct { unsigned flags; } base;
    u32 cryptlen,assoclen;
    void *src,*dst;
    u8 *iv;
    struct crypto_aead *tfm;
    unsigned id;
};
#define crypto_aead_reqtfm(r) ((r)->tfm)
#define crypto_aead_ctx(t) ((t)->ctx)
struct airoha_crypto_request { u8 header[76]; u8 data[]; };
static int pack_error;
static unsigned unpack_count;
static int airoha_crypto_pack(void *buffer,size_t capacity,void *src,
                             unsigned aad,unsigned len,const u8 *key,
                             const u8 *iv,bool decrypt) {
    (void)src; (void)aad; (void)len; (void)key; (void)iv; (void)decrypt;
    memset(buffer,0x5a,capacity);
    return pack_error ? pack_error : (int)capacity;
}
static int airoha_crypto_unpack(void *buffer,size_t len,void *dst,unsigned status) {
    (void)buffer; (void)len; (void)dst;
    unpack_count++; return status==2 ? -EBADMSG : 0;
}
static void aead_request_complete(struct aead_request *,int);
