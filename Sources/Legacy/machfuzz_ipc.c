#include "exploit.h"
#include "nk_diag.h"
#include <mach/message.h>
#include <mach/mach_time.h>
#include <dlfcn.h>

typedef mach_msg_return_t (*msg_overwrite_fn)(
    mach_msg_header_t *msg, mach_msg_option_t options,
    mach_msg_size_t send_size, mach_msg_size_t rcv_size,
    mach_port_t rcv_name, mach_msg_timeout_t timeout,
    mach_port_t notify, mach_msg_header_t *rcv,
    mach_msg_size_t rcv_scatter_size);

static msg_overwrite_fn s_overwrite = NULL;
static int s_overwrite_resolved = 0;

static msg_overwrite_fn get_overwrite(void) {
    if (s_overwrite_resolved) return s_overwrite;
    s_overwrite_resolved = 1;
    void *h = dlopen("/usr/lib/system/libsystem_kernel.dylib", RTLD_LAZY);
    if (h) s_overwrite = (msg_overwrite_fn)dlsym(h, "mach_msg_overwrite_trap");
    return s_overwrite;
}

#define IPC_MAX_PORTS      64
#define IPC_DEADLINE_SEC   8
#define IPC_MINIMIZE_TRIES 3

typedef struct {
    mach_port_t   rx;
    int           in_pset;
    int           dead;
} ipc_pair_t;

typedef struct {
    ipc_pair_t    pool[IPC_MAX_PORTS];
    int           count;
    int           use_pset;
    mach_port_t   pset;
    mach_port_t   notify_port;
    uint64_t      seed;
    int           corrupt_kind;
    const uint32_t *sizes;
    int           n_sizes;
    int           tid;
} ipc_ctx_t;

static volatile int g_ipc_stop = 0;
static volatile uint64_t g_ipc_ops = 0;
static volatile uint64_t g_ipc_events = 0;
static volatile int g_anomaly_flag = 0;

static const uint32_t ipc_all_sizes[] = {
    16, 32, 48, 64, 96, 128, 160, 192, 224, 256, 320, 384, 512, 768, 1024, 2048
};
static const uint32_t ipc_min_sizes[] = { 160, 192, 224, 256 };

static uint64_t ipc_rand(ipc_ctx_t *c) {
    c->seed = c->seed * 6364136223846793005ULL + 1442695040888963407ULL;
    return c->seed >> 17;
}

static void *ipc_alloc_pair(ipc_ctx_t *c) {
    if (c->count >= IPC_MAX_PORTS) return NULL;
    ipc_pair_t *p = &c->pool[c->count];
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &p->rx) != KERN_SUCCESS)
        return NULL;
    if (mach_port_insert_right(mach_task_self(), p->rx, p->rx,
            MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS) {
        p->dead = 1;
        return NULL;
    }
    p->in_pset = 0;
    if (c->use_pset && c->pset != MACH_PORT_NULL &&
        mach_port_insert_member(mach_task_self(), p->rx, c->pset) == KERN_SUCCESS)
        p->in_pset = 1;
    c->count++;
    return p;
}

static void ipc_drop_pair(ipc_ctx_t *c, int idx) {
    ipc_pair_t *p = &c->pool[idx];
    if (p->dead) return;
    p->dead = 1;
    if (p->in_pset && c->pset != MACH_PORT_NULL)
        mach_port_move_member(mach_task_self(), p->rx, c->pset);
    mach_port_mod_refs(mach_task_self(), p->rx, MACH_PORT_RIGHT_RECEIVE, -1);
    p->rx = MACH_PORT_NULL;
    int last = c->count - 1;
    c->pool[idx] = c->pool[last];
    c->count = last;
}

static void ipc_build_complex(
    uint8_t *msg, size_t msg_cap,
    void **ool_ptrs, uint32_t *ool_szs, int ndesc,
    int corrupt_kind, uint64_t body_seq)
{
    memset(msg, 0, msg_cap);
    mach_msg_header_t *h = (mach_msg_header_t *)msg;
    mach_msg_body_t *body = (mach_msg_body_t *)(h + 1);
    mach_msg_ool_descriptor_t *d = (mach_msg_ool_descriptor_t *)(body + 1);

    h->msgh_remote_port = 0;
    h->msgh_local_port = 0;
    h->msgh_voucher_port = 0;
    h->msgh_id = 0x4141;

    if (ndesc <= 0) {
        h->msgh_bits = MACH_MSGH_BITS(0, 0);
        h->msgh_size = (mach_msg_size_t)sizeof(mach_msg_header_t);
        return;
    }

    h->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0) | MACH_MSGH_BITS_COMPLEX;
    body->msgh_descriptor_count = (mach_msg_size_t)ndesc;

    size_t used = sizeof(mach_msg_header_t) + sizeof(mach_msg_body_t);
    for (int i = 0; i < ndesc; i++) {
        if (used + sizeof(*d) > msg_cap) break;
        d[i].address = ool_ptrs[i];
        d[i].size = ool_szs[i];
        d[i].deallocate = 0;
        d[i].copy = MACH_MSG_PHYSICAL_COPY;
        d[i].pad1 = 0;
        d[i].type = MACH_MSG_OOL_DESCRIPTOR;
        used += sizeof(*d);
    }

    switch (corrupt_kind) {
    case 1:
        body->msgh_descriptor_count = (mach_msg_size_t)(ndesc + 4);
        break;
    case 2:
        d[ndesc - 1].size = (mach_msg_size_t)0x10000;
        d[ndesc - 1].address = (void *)0xdeadbeefdeadbeefULL;
        break;
    case 3:
        d[ndesc - 1].type = (mach_msg_descriptor_type_t)0x7f;
        break;
    case 4:
        body->msgh_descriptor_count = 0;
        h->msgh_bits &= ~MACH_MSGH_BITS_COMPLEX;
        break;
    case 5:
        d[0].size = (mach_msg_size_t)(ool_szs[0] + 8);
        break;
    default:
        break;
    }

    h->msgh_size = (mach_msg_size_t)used;
    (void)body_seq;
}

static void *ipc_sender_thread(void *arg) {
    ipc_ctx_t *c = (ipc_ctx_t *)arg;
    static uint8_t smsg[8192];
    void *ptrs[3];
    uint32_t szs[3];
    static uint8_t *ool[3];

    for (int i = 0; i < 3; i++) {
        ool[i] = (uint8_t *)malloc(16384);
        memset(ool[i], 0, 16384);
    }

    while (!g_ipc_stop) {
        if (c->count < 4) ipc_alloc_pair(c);
        if (c->count == 0) break;

        int idx = (int)(ipc_rand(c) % (uint64_t)c->count);
        if (c->pool[idx].dead) { ipc_drop_pair(c, idx); continue; }

        int ndesc = (int)(1 + ipc_rand(c) % 3);
        int ck = c->corrupt_kind >= 0 ? c->corrupt_kind
            : (int)(ipc_rand(c) % 6);
        char ool_list[96];
        int ool_len = 0;
        for (int i = 0; i < ndesc; i++) {
            uint32_t sz = c->sizes[ipc_rand(c) % (uint64_t)c->n_sizes];
            nk_canary_stamp(ool[i], sz);
            ptrs[i] = ool[i];
            szs[i] = sz;
            ool_len += snprintf(ool_list + ool_len, sizeof(ool_list) - ool_len,
                "%s%u", i ? "," : "", sz);
        }

        ipc_build_complex(smsg, sizeof(smsg), ptrs, szs, ndesc, ck,
            nk_diag_seq_next());

        mach_port_t dest = c->pool[idx].rx;
        time_t now_t = time(NULL);

        mach_msg_return_t mr = mach_msg((mach_msg_header_t *)smsg,
            MACH_SEND_MSG | ((ipc_rand(c) & 1) ? MACH_SEND_TIMEOUT : 0),
            ((mach_msg_header_t *)smsg)->msgh_size, 0, dest,
            (mach_msg_timeout_t)(ipc_rand(c) % 3), MACH_PORT_NULL);

        g_ipc_ops++;
        g_ipc_events++;
        nk_diag_event("ipc", "SND",
            "t=%ld tid=%d port=%u ck=%d ndesc=%d ool=[%s] mr=%d",
            (long)now_t, c->tid, dest, ck, ndesc,
            ool_list, mr);

        if (mr == MACH_SEND_INVALID_MEMORY || mr == MACH_MSG_VM_KERNEL ||
            mr == MACH_SEND_INVALID_RIGHT || mr == MACH_SEND_INVALID_TYPE) {
            g_anomaly_flag = 1;
            nk_diag_anomaly(NK_P1_DEFECT_NO_CONTROL, "ipc",
                "send mr=%d port=%u ck=%d ndesc=%d ool=[%s]",
                mr, dest, ck, ndesc, ool_list);
        }

        if ((g_ipc_ops & 4095) == 0 && c->count >= 8) {
            int victim = (int)(ipc_rand(c) % (uint64_t)c->count);
            ipc_drop_pair(c, victim);
        }
    }

    for (int i = 0; i < 3; i++) free(ool[i]);
    return NULL;
}

static void *ipc_destroyer_thread(void *arg) {
    ipc_ctx_t *c = (ipc_ctx_t *)arg;
    uint64_t spins = 0;
    while (!g_ipc_stop) {
        if (c->count > 2 && (spins++ & 1)) {
            int victim = (int)(ipc_rand(c) % (uint64_t)c->count);
            mach_port_t tx = c->pool[victim].rx;
            kern_return_t kr = mach_port_request_notification(
                mach_task_self(), tx, MACH_NOTIFY_DEAD_NAME,
                0, c->notify_port, MACH_MSG_TYPE_MAKE_SEND_ONCE, 0);
            if (kr != KERN_SUCCESS)
                nk_diag_event("ipc", "NOTIFY", "DEAD kr=%d port=%u", kr, tx);
            mach_port_request_notification(
                mach_task_self(), tx, MACH_NOTIFY_PORT_DESTROYED,
                0, c->notify_port, MACH_MSG_TYPE_MAKE_SEND_ONCE, 0);
            mach_port_request_notification(
                mach_task_self(), tx, MACH_NOTIFY_NO_SENDERS,
                0, c->notify_port, MACH_MSG_TYPE_MAKE_SEND_ONCE, 0);
            nk_diag_event("ipc", "DST", "tid=%d port=%u", c->tid, tx);
            ipc_drop_pair(c, victim);
        } else {
            mach_msg_header_t nmsg;
            memset(&nmsg, 0, sizeof(nmsg));
            nmsg.msgh_size = sizeof(nmsg);
            nmsg.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND,
                MACH_MSG_TYPE_MAKE_SEND_ONCE);
            mach_msg(&nmsg, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
                sizeof(nmsg), c->notify_port, 1, MACH_PORT_NULL);
        }
        usleep(50);
    }
    return NULL;
}

static void ipc_inspect_rcv(const uint8_t *rmsg) {
    const mach_msg_header_t *h = (const mach_msg_header_t *)rmsg;
    if (!(h->msgh_bits & MACH_MSGH_BITS_COMPLEX)) return;

    const mach_msg_body_t *body = (const mach_msg_body_t *)(h + 1);
    if (body->msgh_descriptor_count > 64) {
        nk_diag_anomaly(NK_P1_DEFECT_NO_CONTROL, "ipc",
            "rcv dsc_wild count=%u size=%u", body->msgh_descriptor_count,
            h->msgh_size);
        return;
    }

    for (uint32_t i = 0; i < body->msgh_descriptor_count; i++) {
        const mach_msg_ool_descriptor_t *d =
            (const mach_msg_ool_descriptor_t *)(body + 1) + i;
        if (d->type != MACH_MSG_OOL_DESCRIPTOR) continue;
        if (!d->address || d->size < sizeof(nk_canary_t) + 16) continue;

        uint32_t fep = 0, ftid = 0;
        uint64_t fseq = 0;
        nk_canary_result_t r = nk_canary_check((const void *)d->address,
            (size_t)d->size, &fep, &fseq, &ftid);
        if (r == NK_CAN_FOREIGN || r == NK_CAN_STALE) {
            g_anomaly_flag = 1;
            nk_diag_event("ipc", "CANARY",
                "dsc=%u addr=0x%llx size=%u r=%d fep=%u fseq=%llu ftid=%u",
                i, (unsigned long long)d->address, d->size, (int)r,
                fep, (unsigned long long)fseq, ftid);
            nk_diag_anomaly(NK_P1_DEFECT_NO_CONTROL, "ipc",
                "recv OOL stale/foreign canary r=%d fep=%u fseq=%llu size=%u",
                (int)r, fep, (unsigned long long)fseq, d->size);
        }
    }
}

static void *ipc_receiver_thread(void *arg) {
    ipc_ctx_t *c = (ipc_ctx_t *)arg;
    static uint8_t rmsg[32768];
    msg_overwrite_fn ow = get_overwrite();

    while (!g_ipc_stop) {
        mach_port_t from = c->pset != MACH_PORT_NULL ? c->pset
            : (c->count ? c->pool[0].rx : MACH_PORT_NULL);
        if (from == MACH_PORT_NULL) { usleep(100); continue; }

        mach_msg_option_t opt = MACH_RCV_MSG;
        uint32_t r = (uint32_t)ipc_rand(c);
        if (r & 1) opt |= MACH_RCV_TIMEOUT;
        if (r & 2) opt |= MACH_RCV_LARGE;
        if (r & 4) opt |= MACH_RCV_GUARDED_DESC;
        if (r & 8) opt |= MACH_RCV_VOUCHER;

        memset(rmsg, 0, sizeof(rmsg));
        mach_msg_return_t mr;
        if (ow && (ipc_rand(c) & 3) == 0) {
            mr = ow((mach_msg_header_t *)rmsg, opt, 0, sizeof(rmsg),
                from, (mach_msg_timeout_t)(ipc_rand(c) % 2), MACH_PORT_NULL,
                (mach_msg_header_t *)rmsg, sizeof(rmsg));
        } else {
            mr = mach_msg((mach_msg_header_t *)rmsg, opt, 0, sizeof(rmsg),
                from, (mach_msg_timeout_t)(ipc_rand(c) % 2), MACH_PORT_NULL);
        }

        if (mr == MACH_MSG_SUCCESS) {
            mach_msg_header_t *h = (mach_msg_header_t *)rmsg;
            int kptr = 0;
            for (size_t off = 0; off + 8 <= h->msgh_size; off += 8) {
                uint64_t v;
                memcpy(&v, rmsg + off, 8);
                uint32_t hi = (uint32_t)(v >> 32);
                if ((hi & 0xfffff000u) == 0xfffff000u ||
                    (hi & 0xffff0000u) == 0xffff0000u) kptr++;
            }
            if (kptr) {
                g_anomaly_flag = 1;
                nk_diag_event("ipc", "KPTR", "size=%u count=%d",
                    h->msgh_size, kptr);
                nk_diag_anomaly(NK_P1_DEFECT_NO_CONTROL, "ipc",
                    "rcv kptr_leak count=%d size=%u", kptr, h->msgh_size);
            }
            ipc_inspect_rcv(rmsg);
            nk_diag_event("ipc", "RCV", "port=%u size=%u complex=%d",
                (unsigned)h->msgh_local_port, h->msgh_size,
                (h->msgh_bits & MACH_MSGH_BITS_COMPLEX) ? 1 : 0);
        } else if (mr != MACH_RCV_TIMED_OUT && mr != MACH_RCV_TOO_LARGE &&
            mr != MACH_RCV_INVALID_NAME && mr != MACH_RCV_INVALID_NOTIFY) {
            if (mr == MACH_RCV_INVALID_DATA)
                nk_diag_anomaly(NK_P2_RARE_PANIC, "ipc",
                    "rcv MACH_RCV_INVALID_DATA");
            nk_diag_event("ipc", "RCVE", "mr=%d", mr);
        }
    }
    return NULL;
}

static uint64_t ipc_run_epoch(int nthreads, ipc_ctx_t *base, int seconds) {
    pthread_t th[3];
    ipc_ctx_t *ctx = (ipc_ctx_t *)calloc(1, sizeof(ipc_ctx_t));
    if (!ctx) return 0;
    memcpy(ctx, base, sizeof(ipc_ctx_t));
    ctx->seed = base->seed;
    ctx->tid = 0;
    ctx->count = 0;
    if (ctx->use_pset && ctx->pset == MACH_PORT_NULL)
        mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_PORT_SET,
            &ctx->pset);

    g_anomaly_flag = 0;
    g_ipc_stop = 0;
    if (nthreads >= 3)
        pthread_create(&th[2], NULL, ipc_receiver_thread, ctx);
    pthread_create(&th[1], NULL, ipc_destroyer_thread, ctx);
    pthread_create(&th[0], NULL, ipc_sender_thread, ctx);

    for (int i = 0; i < seconds; i++) {
        sleep(1);
        if (g_anomaly_flag) break;
    }
    g_ipc_stop = 1;
    pthread_join(th[0], NULL);
    pthread_join(th[1], NULL);
    if (nthreads >= 3) pthread_join(th[2], NULL);
    free(ctx);
    return g_ipc_ops;
}

static void ipc_minimize(ipc_ctx_t *base, const char *anomaly_desc) {
    nk_log("[ipc] minimizer: %s", anomaly_desc);
    for (int t = 0; t < IPC_MINIMIZE_TRIES; t++) {
        ipc_ctx_t m;
        memcpy(&m, base, sizeof(ipc_ctx_t));
        m.seed = base->seed + (uint64_t)t * 7919u;
        m.sizes = ipc_min_sizes;
        m.n_sizes = sizeof(ipc_min_sizes) / sizeof(ipc_min_sizes[0]);
        m.corrupt_kind = base->corrupt_kind >= 0 ? base->corrupt_kind : t % 6;
        m.use_pset = 0;
        m.pset = MACH_PORT_NULL;
        m.count = 0;
        m.tid = 0;
        for (int i = 0; i < IPC_MAX_PORTS; i++) m.pool[i].dead = 1;

        uint64_t pre = g_ipc_ops;
        ipc_run_epoch(3, &m, 2);
        int reproduced = (g_anomaly_flag != 0);
        g_anomaly_flag = 0;

        nk_diag_event("ipc", "MIN",
            "try=%d seed=%llx ops=%llu reproduced=%d ck=%d",
            t, (unsigned long long)m.seed,
            (unsigned long long)(g_ipc_ops - pre), reproduced, m.corrupt_kind);

        if (reproduced) {
            nk_diag_anomaly(NK_P0_REPRO_CONTROLLED, "ipc",
                "MIN repro try=%d seed=%llx ck=%d sizes=192-range single-epoch",
                t, (unsigned long long)m.seed, m.corrupt_kind);
            return;
        }
    }
    nk_diag_anomaly(NK_P3_NOISE, "ipc", "MIN failed after %d tries",
        IPC_MINIMIZE_TRIES);
}

void nk_ipc_fuzz(void) {
    nk_log("[ipc] harness boot: canary + JSONL + minimizer + panic correlation");
    nk_diag_crash_pending(NULL);
    nk_diag_panic_correlate();
    nk_diag_epoch_start("ipc");

    uint32_t boot0 = nk_diag_boot_epoch();
    nk_diag_event("ipc", "RUN", "boot=%u budget=%ds", boot0, IPC_DEADLINE_SEC);

    ipc_ctx_t base;
    memset(&base, 0, sizeof(base));
    base.seed = ((uint64_t)mach_absolute_time() << 16) ^
        (uint64_t)nk_diag_epoch() ^ (uint64_t)getpid();
    base.pset = MACH_PORT_NULL;
    base.use_pset = 1;
    base.sizes = ipc_all_sizes;
    base.n_sizes = sizeof(ipc_all_sizes) / sizeof(ipc_all_sizes[0]);
    base.corrupt_kind = -1;
    base.count = 0;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_PORT_SET, &base.pset);
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &base.notify_port);
    mach_port_insert_right(mach_task_self(), base.notify_port,
        base.notify_port, MACH_MSG_TYPE_MAKE_SEND);

    char anomaly_desc[256] = { 0 };
    int watchdog = IPC_DEADLINE_SEC;

    ipc_ctx_t shared = base;
    shared.use_pset = 1;
    shared.count = 0;

    g_ipc_stop = 0;
    pthread_t th[3];
    ipc_ctx_t *ctxs[3];
    int nctx = 3;
    for (int i = 0; i < nctx; i++) {
        ctxs[i] = (ipc_ctx_t *)calloc(1, sizeof(ipc_ctx_t));
        if (!ctxs[i]) { nctx = i; break; }
        memcpy(ctxs[i], &shared, sizeof(ipc_ctx_t));
        ctxs[i]->seed = base.seed + 0x9E3779B9u * (uint64_t)(i + 1);
        ctxs[i]->tid = i;
    }
    pthread_create(&th[0], NULL, ipc_sender_thread, ctxs[0]);
    pthread_create(&th[1], NULL, ipc_destroyer_thread, ctxs[1]);
    pthread_create(&th[2], NULL, ipc_receiver_thread, ctxs[2]);

    while (watchdog-- > 0) {
        sleep(1);
        uint32_t e = nk_diag_boot_epoch();
        if (e != boot0) {
            nk_diag_event("ipc", "PANICWATCH", "boot %u -> %u", boot0, e);
            snprintf(anomaly_desc, sizeof(anomaly_desc),
                "reboot during race window (boot %u -> %u)", boot0, e);
            nk_diag_anomaly(NK_P2_RARE_PANIC, "ipc", "%s", anomaly_desc);
            g_ipc_stop = 1;
            break;
        }
    }
    g_ipc_stop = 1;
    for (int i = 0; i < 3; i++) pthread_join(th[i], NULL);
    for (int i = 0; i < nctx; i++) if (ctxs[i]) free(ctxs[i]);

    uint32_t e = nk_diag_boot_epoch();
    nk_diag_event("ipc", "RUNEND", "boot=%u ops=%llu events=%llu",
        e, (unsigned long long)g_ipc_ops,
        (unsigned long long)g_ipc_events);

    if (anomaly_desc[0]) {
        ipc_minimize(&base, anomaly_desc);
    }

    nk_diag_ring_dump();
    nk_log("[ipc] harness done ops=%llu events=%llu log=%s",
        (unsigned long long)g_ipc_ops, (unsigned long long)g_ipc_events,
        nk_diag_log_path());
}
