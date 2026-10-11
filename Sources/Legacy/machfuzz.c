#include "exploit.h"
#include <sys/sysctl.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>

#define PROC_PIDLISTFDS        1
#define PROC_PIDTASKALLINFO    2
#define PROC_PIDTBSDINFO       3
#define PROC_PIDTASKINFO       4
#define PROC_PIDTHREADINFO     5
#define PROC_PIDLISTTHREADS    6
#define PROC_PIDRUSAGE         7
#define PROC_PIDLISTUPTRS      8
#define PROC_PIDLISTCOALITIONS 9
#define PROC_PIDCOALITIONINFO 10
#define PROC_PIDNOTEEXIT      11
#define PROC_PIDREGIONPATHINFO 12
#define PROC_PIDREGIONPATHINFO2 13
#define PROC_PIDREGIONPATHINFO3 14
#define PROC_PIDT_SHORTBSDINFO 16
#define PROC_PIDPATHINFO       17

typedef int (*proc_pidinfo_fn)(int pid, int flavor, uint64_t arg,
    void *buffer, int buffersize);

static int scan_ptr(const uint8_t *buf, size_t n, const char *tag) {
    int found = 0;
    for (size_t off = 0; off + 8 <= n; off += 8) {
        uint64_t v;
        memcpy(&v, buf + off, 8);
        uint32_t hi = (uint32_t)(v >> 32);
        if (hi == 0xfffffff0 || hi == 0xfffffe00) {
            nk_log("[sys LEAK] %s off=%zu ptr=0x%016llx%s",
                tag, off, (unsigned long long)v,
                ((v & 0xFFFFULL) == 0) ? " (round)" : "");
            found++;
        }
    }
    return found;
}

static proc_pidinfo_fn s_pinfo = NULL;
static int pinfo_resolved = 0;

static proc_pidinfo_fn get_pinfo(void) {
    if (pinfo_resolved) return s_pinfo;
    pinfo_resolved = 1;
    void *h = dlopen("/usr/lib/libproc.dylib", RTLD_LAZY);
    if (h) s_pinfo = (proc_pidinfo_fn)dlsym(h, "proc_pidinfo");
    return s_pinfo;
}

void nk_sys_fuzz(void) {
    struct timeval boot0;
    size_t bl = sizeof(boot0);
    int have_boot = (sysctlbyname("kern.boottime", &boot0, &bl, NULL, 0) == 0);
    if (have_boot)
        nk_log("[sys] boot epoch before: %ld", (long)boot0.tv_sec);

    nk_log("[sys] stage 1: sysctl OID walk kern/hw/security/vfs (read-only)");
    static const int    roots[4] = { 1, 6, 7, 3 };
    static const char  *rname[4] = { "kern", "hw", "security", "vfs" };
    int oids = 0, leaks = 0;
    for (int ri = 0; ri < 4; ri++) {
        for (int k = 0; k < 2048; k++) {
            int mib[2] = { roots[ri], k };
            uint8_t buf[512];
            size_t len = sizeof(buf);
            memset(buf, 0, sizeof(buf));
            if (sysctl(mib, 2, buf, &len, NULL, 0) != 0) continue;
            if (len == 0 || len > sizeof(buf)) continue;
            oids++;
            leaks += scan_ptr(buf, len, rname[ri]);
        }
    }
    nk_log("[sys] stage 1 done readable_oids=%d leaks=%d", oids, leaks);

    nk_log("[sys] stage 2: proc_info flavor sweep (read-only)");
    proc_pidinfo_fn pinfo = get_pinfo();
    if (!pinfo) {
        nk_log("[sys] stage 2 skipped: proc_pidinfo not available");
    } else {
        static const int flavors[] = {
            PROC_PIDLISTFDS, PROC_PIDTASKINFO, PROC_PIDTBSDINFO,
            PROC_PIDT_SHORTBSDINFO, PROC_PIDLISTUPTRS, PROC_PIDPATHINFO
        };
        static const char *fname[] = {
            "LISTFDS", "TASKINFO", "BSDINFO",
            "SHORTBSD", "LISTUPTRS", "PATH"
        };
        pid_t targets[3];
        targets[0] = getpid();
        targets[1] = getppid();
        targets[2] = 1;
        int pleaks = 0;
        for (int ti = 0; ti < 3; ti++) {
            for (size_t fi = 0; fi < sizeof(flavors)/sizeof(flavors[0]); fi++) {
                static uint8_t pbuf[4096];
                memset(pbuf, 0, sizeof(pbuf));
                errno = 0;
                int r = pinfo(targets[ti], flavors[fi], 0, pbuf, sizeof(pbuf));
                if (r <= 0) {
                    nk_log("[sys] pid=%d %s r=%d errno=%d",
                        (int)targets[ti], fname[fi], r, errno);
                    continue;
                }
                nk_log("[sys] pid=%d %s r=%d", (int)targets[ti], fname[fi], r);
                pleaks += scan_ptr(pbuf, (size_t)r, fname[fi]);
            }
        }
        nk_log("[sys] stage 2 done leaks=%d", pleaks);
        leaks += pleaks;
    }

    nk_log("[sys] stage 3: deprecated syscall probe (user buffers only)");
    static const int nums[] = {
        444, 446, 448, 450, 464, 470, 474, 482, 490, 494,
        506, 510, 520, 524, 526, 527, 530, 532, 534
    };
    int alive = 0;
    for (size_t i = 0; i < sizeof(nums)/sizeof(nums[0]); i++) {
        uint8_t a[64], b2[64];
        memset(a, 0xBB, sizeof(a));
        memset(b2, 0xBB, sizeof(b2));
        errno = 0;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        long r = syscall(nums[i], a, 64, b2, 64);
#pragma GCC diagnostic pop
        int e = errno;
        int wa = 0, wb = 0;
        for (int j = 0; j < 64; j++) {
            if (a[j] != 0xBB) wa++;
            if (b2[j] != 0xBB) wb++;
        }
        if (r >= 0 || wa || wb) {
            nk_log("[sys ALIVE] num=%d r=%ld errno=%d wa=%d wb=%d",
                nums[i], r, e, wa, wb);
            alive++;
            if (wa) scan_ptr(a, 64, "numA");
            if (wb) scan_ptr(b2, 64, "numB");
        }
    }
    nk_log("[sys] stage 3 done alive=%d", alive);

    if (have_boot) {
        struct timeval boot1;
        size_t bl2 = sizeof(boot1);
        if (sysctlbyname("kern.boottime", &boot1, &bl2, NULL, 0) == 0) {
            if (boot1.tv_sec != boot0.tv_sec)
                nk_log("[sys PANIC-WATCH] boot epoch CHANGED mid-run: kernel rebooted");
            else
                nk_log("[sys PANIC-WATCH] boot epoch stable: no panic during run");
        }
    }
    nk_log("[sys] sweep done total_leaks=%d", leaks);
}
