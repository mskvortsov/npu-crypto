/* SPDX-License-Identifier: GPL-2.0-only */
static int completed;
static bool completion_ok;
static void done(void *data, bool ok) {
 assert(data == &completed); completed++; completion_ok = ok;
}
static void finish(unsigned int index, int status) {
 struct aead_request *r = pending[index]; pending[index] = NULL;
 r->complete(r->data, status);
}
static void *finish_thread(void *arg) { finish((uintptr_t)arg, 0); return NULL; }
int main(void) {
 struct crypto_aead tfm = {0};
 struct wg_peer peer = {0};
 atomic_set(&peer.refs, 1);
 struct noise_keypair kp = {.npu_sending=&tfm, .npu_receiving=&tfm, .entry.peer=&peer};
 char payload[1500] = {0};
 struct scatterlist sg = {.buf=payload, .length=sizeof(payload)};
 /* Optional hardware and transform initialization failures preserve software. */
 u8 key[32] = {0};
 alloc_tfm_fail=1; assert(!wg_npu_alloc(key)); alloc_tfm_fail=0;
 setkey_fail=-EINVAL; assert(!wg_npu_alloc(key)); setkey_fail=0;
 auth_fail=-EINVAL; assert(!wg_npu_alloc(key)); auth_fail=0;
 free(wg_npu_alloc(key));
 assert(wg_npu_submit(&sg, 1, 1024, &kp, 9, false, done, &completed) == -EAGAIN);
 assert(wg_npu_submit(&sg, 1, 1040, &kp, 9, true, done, &completed) == -EAGAIN);
 for (int failure=1; failure<=2; failure++) {
  fail_alloc=failure;
  assert(wg_npu_submit(&sg, 1, 1500, &kp, 9, false, done, &completed) == -ENOMEM);
 }
 assert(!completed && !atomic_read(&peer.npu_inflight) && atomic_read(&peer.refs)==1);
 /* Refusal leaves ownership with the worker. */
 submit_mode=2;
 assert(wg_npu_submit(&sg, 1, 1500, &kp, 9, false, done, &completed) == -EAGAIN);
 assert(!completed && !atomic_read(&peer.npu_inflight) && atomic_read(&peer.refs)==1);
 /* Callback may free the context and packet before submit returns. */
 submit_mode=1;
 assert(wg_npu_submit(&sg, 1, 1500, &kp, 9, false, done, &completed) == -EINPROGRESS);
 assert(completed==1 && completion_ok && !atomic_read(&peer.npu_inflight));
 /* Stack scatterlist and IV are replaced by owned request storage. */
 submit_mode=0;
 assert(wg_npu_submit(&sg, 1, 1500, &kp, 0x1020304050607080ULL, true, done, &completed) == -EINPROGRESS);
 assert(pending[0]->sg != &sg && pending[0]->sg->buf == payload);
 assert(pending[0]->iv[4]==0x80 && pending[0]->iv[11]==0x10);
 assert(atomic_read(&peer.npu_inflight)==1 && atomic_read(&peer.refs)==2);
 pending[0]->complete(pending[0]->data, -EINPROGRESS);
 assert(completed==1 && atomic_read(&peer.npu_inflight)==1);
 finish(0, -EBADMSG);
 assert(completed==2 && !completion_ok && !software_calls);
 assert(!atomic_read(&peer.npu_inflight) && atomic_read(&peer.refs)==1);
 assert(wg_npu_submit(&sg, 1, 1500, &kp, 9, true, done, &completed) == -EINPROGRESS);
 finish(1, -EIO);
 assert(completed==3 && completion_ok && software_calls==1);
 /* A batch cannot publish early, even if a callback arrives while its
  * worker is submitting the remaining list. One failure kills the list,
  * but it must still await all outstanding DMA users before publication.
  */
 struct sk_buff packets[3] = {0};
 struct encrypt_batch *batch = calloc(1, sizeof(*batch));
 batch->first=&packets[0]; refcount_set(&batch->pending, 1);
 for (int i=0;i<3;i++) {
  struct encrypt_completion *ctx=malloc(sizeof(*ctx));
  ctx->batch=batch; ctx->skb=&packets[i]; refcount_inc(&batch->pending);
  submit_mode = i==0 ? 1 : 0;
  assert(wg_npu_submit(&sg,1,1500,&kp,9,false,encrypt_done,ctx)==-EINPROGRESS);
  assert(!published);
 }
 encrypt_batch_put(batch); assert(!published);
 finish(3, -EBADMSG); assert(!published);
 finish(2, 0);
 assert(published==1 && published_state==PACKET_STATE_DEAD);
 assert(packets[0].reset==1 && packets[1].reset==1 && !packets[2].reset);
 /* Concurrent completions publish a successful list exactly once. */
 batch=calloc(1,sizeof(*batch)); batch->first=&packets[0]; refcount_set(&batch->pending,1);
 submit_mode=0;
 for (int i=0;i<3;i++) {
  struct encrypt_completion *ctx=malloc(sizeof(*ctx));
  ctx->batch=batch; ctx->skb=&packets[i]; refcount_inc(&batch->pending);
  assert(wg_npu_submit(&sg,1,1500,&kp,9,false,encrypt_done,ctx)==-EINPROGRESS);
 }
 encrypt_batch_put(batch);
 pthread_t threads[3];
 for (uintptr_t i=0;i<3;i++) assert(!pthread_create(&threads[i],NULL,finish_thread,(void *)(i+4)));
 for (int i=0;i<3;i++) assert(!pthread_join(threads[i],NULL));
 assert(published==2 && published_state==PACKET_STATE_CRYPTED);
 assert(!atomic_read(&peer.npu_inflight) && atomic_read(&peer.refs)==1);
 /* Strict mode submits short packets with backlog and never retries an
  * asynchronous transport error in software, even after mode is disabled.
  */
 wg_npu_only=true;
 submit_mode=0;
 int calls_before=software_calls;
 assert(wg_npu_submit(&sg,1,64,&kp,9,false,done,&completed)==-EINPROGRESS);
 wg_npu_only=false;
 finish(7,-EIO);
 assert(!completion_ok && software_calls==calls_before);
 wg_npu_only=true;
 submit_mode=2;
 assert(wg_npu_submit(&sg,1,64,&kp,9,true,done,&completed)==-EAGAIN);
 assert(software_calls==calls_before && !atomic_read(&peer.npu_inflight));
 wg_npu_only=false;
 /* RX restores the endpoint header and trims the tag only on success. */
 struct sk_buff rx = {.data_offset=52, .len=1516};
 decrypt_done(&rx, true);
 assert(rx_published==1 && rx_state==PACKET_STATE_CRYPTED);
 assert(rx.data_offset==52 && rx.len==1500 && !rx.network_offset);
 rx.len=1516;
 decrypt_done(&rx, false);
 assert(rx_published==2 && rx_state==PACKET_STATE_DEAD && rx.len==1516);
 rx.trim_fail=true;
 decrypt_done(&rx, true);
 assert(rx_published==3 && rx_state==PACKET_STATE_DEAD && rx.data_offset==52);
 puts("WireGuard async: allocation/refusal, early/deferred/concurrent completion, authentication failure, fallback, TX list ownership and RX finalization passed");
}
