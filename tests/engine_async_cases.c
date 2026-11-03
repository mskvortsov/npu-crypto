static struct airoha_crypto_engine engine;
static struct workqueue_struct queues[4];
static void run_all(void) {
    bool pending;
    do {
        pending=false;
        for (unsigned i=0;i<4;i++) {
            run_queue(&queues[i]);
            pending |= queues[i].count != 0;
        }
        for (unsigned i=0;i<4;i++) pending |= queues[i].count != 0;
    } while (pending);
}
static struct airoha_crypto_ctx ctx;
static struct crypto_aead tfm;
static u8 buffers[4][17000];
static int statuses[4], submit_error;
static bool poisoned, early_irq;
static unsigned submitted[4], released[4], callbacks[256];
static int errors[256];
static void *buffer_get(void *unused,unsigned slot) {
    (void)unused; return poisoned ? NULL : buffers[slot];
}
static int submit(void *unused,unsigned slot,size_t len) {
    (void)unused; assert(len<=sizeof(buffers[slot]));
    assert(buffers[slot][0]==0x5a);
    if (submit_error) return submit_error;
    submitted[slot]++;
    statuses[slot]=early_irq ? 1 : -EINPROGRESS;
    if (early_irq) airoha_crypto_engine_notify(&engine, BIT(slot));
    return 0;
}
static int result(void *unused,unsigned slot) {
    (void)unused;
    if (poisoned) return -ENODEV;
    if (statuses[slot]==-ETIMEDOUT) poisoned=true;
    return statuses[slot];
}
static void release(void *unused,unsigned slot,size_t len) {
    (void)unused;
    released[slot]++;
    if (!poisoned) memset(buffers[slot],0,len);
}
static void aead_request_complete(struct aead_request *req,int err) {
    for (unsigned slot=0;slot<4;slot++)
        assert(!engine.active[slot] || engine.active[slot]->req!=req);
    /* The callback can immediately free its request. */
    assert(++callbacks[req->id]==1);
    errors[req->id]=err;
    free(req);
}
static void reset(void) {
    for (unsigned i=0;i<4;i++) assert(!queues[i].count);
    memset(&engine,0,sizeof(engine)); memset(queues,0,sizeof(queues));
    memset(callbacks,0,sizeof(callbacks)); memset(errors,0,sizeof(errors));
    memset(submitted,0,sizeof(submitted)); memset(released,0,sizeof(released));
    memset(buffers,0,sizeof(buffers));
    submit_error=pack_error=0; poisoned=early_irq=false; unpack_count=0;
    for (unsigned i=0;i<4;i++) {
        engine.slots[i].workqueue=&queues[i];
        engine.slots[i].engine=&engine;
        engine.slots[i].index=i;
        INIT_WORK(&engine.slots[i].completions,airoha_completions);
    }
    INIT_LIST_HEAD(&engine.pending);
    INIT_WORK(&engine.watchdog.work,airoha_watchdog);
    engine.transport=(struct airoha_crypto_transport){
        .buffer=buffer_get,.submit=submit,.result=result,.release=release};
    ctx.engine=&engine; tfm.ctx=&ctx;
}
static void enqueue(unsigned id,bool backlog,bool decrypt,unsigned len) {
    struct aead_request *r=calloc(1,sizeof(*r)); assert(r);
    r->id=id; r->tfm=&tfm; r->cryptlen=len;
    r->base.flags=backlog ? CRYPTO_TFM_REQ_MAY_BACKLOG : 0;
    int ret=airoha_enqueue(r,decrypt);
    if (ret!=-EINPROGRESS) free(r);
    assert(ret==-EINPROGRESS);
}
static void refuse(int expected,bool backlog) {
    struct aead_request r={.tfm=&tfm,.cryptlen=1420};
    r.base.flags=backlog ? CRYPTO_TFM_REQ_MAY_BACKLOG : 0;
    assert(airoha_enqueue(&r,false)==expected);
}
static void irq(void) { airoha_crypto_engine_notify(&engine, 15); run_all(); }
static void watchdog(void) {
    assert(engine.watchdog.armed); engine.watchdog.armed=false;
    engine.watchdog.work.fn(&engine.watchdog.work); run_all();
}
int main(void) {
    /* A single completion schedules only its slot; repeated IRQs coalesce. */
    reset();
    for (unsigned i=0;i<4;i++) enqueue(i,false,false,1420);
    run_all();
    statuses[2]=1;
    airoha_crypto_engine_notify(&engine, BIT(2));
    airoha_crypto_engine_notify(&engine, BIT(2));
    airoha_crypto_engine_notify(&engine, BIT(7));
    for (unsigned i=0;i<4;i++) assert(queues[i].count==(i==2));
    run_all();
    assert(callbacks[2] && !callbacks[0] && !callbacks[1] && !callbacks[3]);
    airoha_crypto_engine_notify(&engine, BIT(2));
    assert(!queues[2].count); /* Ignore a stale notification for an idle slot. */
    statuses[0]=statuses[1]=statuses[3]=1;
    airoha_crypto_engine_notify(&engine, BIT(0)|BIT(1)|BIT(3));
    run_all();
    for (unsigned i=0;i<4;i++) assert(callbacks[i]==1);

    /* Leave slot zero's submission queued: other slots must progress alone. */
    reset();
    for (unsigned i=0;i<4;i++) enqueue(i,false,false,1420);
    for (unsigned i=1;i<4;i++) run_queue(&queues[i]);
    assert(!submitted[0]);
    airoha_crypto_engine_notify(&engine, 15);
    for (unsigned i=1;i<4;i++) {
        statuses[i]=1;
        run_queue(&queues[i]);
        assert(callbacks[i]==1);
    }
    assert(!callbacks[0] && queues[0].count);
    early_irq=true;
    run_all();
    assert(callbacks[0]==1 && !engine.slots_in_use);

    reset();
    for (unsigned i=0;i<4;i++) enqueue(i,false,false,1420);
    run_all();
    for (unsigned i=0;i<4;i++) {
        assert(submitted[i]==1 && engine.active[i] && !callbacks[i]);
        assert(buffers[i][0]==0x5a);
    }
    refuse(-EAGAIN,false);
    enqueue(4,true,false,1420); assert(engine.pending_count==1);
    statuses[2]=1; irq();
    assert(callbacks[2]==1 && callbacks[4]==0);
    assert(engine.active[2] && engine.active[2]->req->id==4);
    assert(submitted[2]==2 && engine.pending_count==0);
    statuses[0]=statuses[1]=statuses[2]=1; statuses[3]=2;
    irq(); irq();
    for (unsigned i=0;i<5;i++) assert(callbacks[i]==1);
    assert(errors[3]==-EBADMSG && !engine.slots_in_use);
    for (unsigned i=0;i<4;i++) assert(!engine.active[i] && !buffers[i][0]);
    assert(unpack_count==5);

    reset(); early_irq=true;
    enqueue(0,false,false,1420); run_all();
    assert(callbacks[0]==1 && !engine.slots_in_use);

    reset(); enqueue(0,false,false,1420); engine.stopping=true; run_all();
    statuses[0]=1; watchdog(); /* Complete with no IRQ. */
    assert(callbacks[0]==1);

    reset();
    for (unsigned i=0;i<4;i++) enqueue(i,false,false,1420);
    for (unsigned i=4;i<132;i++) enqueue(i,true,false,1420);
    refuse(-EAGAIN,true); run_all();
    statuses[0]=-ETIMEDOUT; watchdog();
    for (unsigned i=0;i<132;i++) {
        assert(callbacks[i]==1);
        assert(errors[i]==(i ? -ENODEV : -ETIMEDOUT));
    }
    assert(!unpack_count && !engine.slots_in_use && !engine.pending_count);
    for (unsigned i=0;i<4;i++) assert(buffers[i][0]==0x5a);
    irq(); /* Late IRQ cannot unpack quarantined memory or complete twice. */

    reset();
    for (unsigned i=0;i<4;i++) enqueue(i,false,false,1420);
    run_all();
    statuses[2]=-ETIMEDOUT; irq();
    assert(!callbacks[0] && !callbacks[1] && callbacks[2] && callbacks[3]);
    watchdog();
    for (unsigned i=0;i<4;i++) assert(callbacks[i]==1);
    assert(!engine.slots_in_use && !unpack_count);

    reset(); pack_error=-EINVAL;
    enqueue(0,false,false,1420); run_all();
    assert(callbacks[0]==1 && errors[0]==-EINVAL && released[0]==1);
    assert(!submitted[0] && !buffers[0][0]);

    reset(); submit_error=-EIO;
    enqueue(0,false,false,1420); run_all();
    assert(callbacks[0]==1 && errors[0]==-EIO && released[0]==1);
    assert(!engine.active[0] && !buffers[0][0]);

    reset(); enqueue(0,true,true,8); run_all();
    assert(errors[0]==-EINVAL && !released[0]);
    enqueue(1,true,false,17000); run_all();
    assert(errors[1]==-EMSGSIZE && !released[0]);
    engine.stopping=true; refuse(-EAGAIN,true);
}
