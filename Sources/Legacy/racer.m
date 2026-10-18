/* racer.m — IOKit race-condition harness (post-fuzz2).            *
 * (iOS 26.2 23C55, iPhone14,5, app sandbox, no extra priv needed)  *
 * Targets: AppleKeyStore UC (s0/1/16 live, s17/s35 2f0-gate,       *
 * type 0..15 open) + AGXAcceleratorG14P (type1). Threads run the  *
 * same UC / same service in parallel: open/close cycling vs sel   *
 * dispatch vs struct hammer — lifetime races, switch race, ref    *
 * races.                                                          */
#import <IOKit/IOKitLib.h>
#import <Foundation/Foundation.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <mach/mach.h>
#include "exploit.h"

#define rl(fmt_, ...) nk_log(fmt_, ##__VA_ARGS__)

static volatile int _stop = 0;
static pthread_barrier_t _barrier;

static io_connect_t rk_open(const char *name, uint32_t type) {
    CFMutableDictionaryRef d = IOServiceMatching(name);
    if (!d) return 0;
    io_iterator_t it = 0;
    if (IOServiceGetMatchingServices(kIOMasterPortDefault, d, &it) != KERN_SUCCESS) return 0;
    io_object_t s = IOIteratorNext(it);
    io_connect_t c = 0;
    if (s) {
        IOServiceOpen(s, mach_task_self(), type, &c);
        IOObjectRelease(s);
    }
    IOObjectRelease(it);
    return c;
}

/* T1: open/close cycler — UC lifetime race */
static void *race_open_cycle(void *arg) {
    (void)arg;
    uint32_t ty = 0;
    int opened = 0, closed = 0;
    for (int i = 0; i < 2000 && !_stop; i++) {
        io_connect_t c = rk_open("AppleKeyStore", ty & 15);
        if (c) { opened++; IOServiceClose(c); closed++; }
        ty++;
        if ((i & 63) == 63) usleep(2000);
    }
    rl("[rc] openCycle done opened=%d", opened);
    return NULL;
}

/* T2/T3: s17/s35 hammer with alternating struct sizes */
static void *race_ks_ab(void *arg) {
    int sel = (int)(intptr_t)arg;
    io_connect_t c = rk_open("AppleKeyStore", 0);
    if (!c) { rl("[rc] ab%02d no conn", sel); return NULL; }
    static const size_t SZS[4] = { 8, 24, 48, 96 };
    kern_return_t prev = 0; int changes = 0, n = 0;
    for (int i = 0; i < 3000 && !_stop; i++) {
        size_t sz = SZS[i & 3];
        uint8_t stb[96], outb[256];
        memset(stb, 0xAA, sizeof(stb));
        size_t osz = sizeof(outb);
        kern_return_t kr = IOConnectCallStructMethod(c, sel, stb, sz, outb, &osz);
        if (prev && kr != prev) {
            changes++;
            rl("[rc] s%02d flip %d:%d -> %d (i=%d)", sel, prev, kr, i, osz);
        }
        prev = kr;
        n = i;
        if ((i & 31) == 31) usleep(2000);
    }
    rl("[rc] ab%02d done n=%d flips=%d last=0x%x", sel, n, changes, prev);
    IOServiceClose(c);
    return NULL;
}

/* T4: wide sel sweep hammer — s0/1/16 + rest, records out quad */
static void *race_ks_wide(void *arg) {
    (void)arg;
    io_connect_t c = rk_open("AppleKeyStore", 0);
    if (!c) return NULL;
    static const uint32_t WS[6] = { 0, 1, 16, 5, 33, 63 };
    uint64_t out[8]; uint32_t oc;
    kern_return_t prev[6] = {0, 0, 0, 0, 0, 0};
    int succ = 0;
    for (int i = 0; i < 3000 && !_stop; i++) {
        for (int j = 0; j < 6; j++) {
            uint64_t in2[2] = { WS[j], 0 };
            uint8_t stb[64];
            memset(stb, 0xAA, sizeof(stb));
            size_t sz = 16; uint8_t o[16]; size_t osz = sizeof(o);
            kern_return_t kr;
            if (j < 3)
                kr = IOConnectCallMethod(c, WS[j], in2, 2, NULL, 0, out, &oc, NULL, NULL);
            else
                kr = IOConnectCallStructMethod(c, WS[j], stb, sz, o, &osz);
            if (prev[j] && kr != prev[j]) rl("[rc] wide%02d flip %d->%d (i=%d)", WS[j], prev[j], kr, i);
            prev[j] = kr;
            if (kr == KERN_SUCCESS && j < 3) succ++;
        }
        if ((i & 63) == 63) usleep(2000);
    }
    rl("[rc] wide done succ=%d", succ);
    IOServiceClose(c);
    return NULL;
}

/* T5: AGXAcceleratorG14P hammer on live type1 */
static void *race_agx(void *arg) {
    (void)arg;
    io_connect_t c = rk_open("AGXAcceleratorG14P", 1);
    if (!c) { rl("[rc] agx no conn"); return NULL; }
    kern_return_t prev = -1; int flips = 0, n = 0;
    for (int i = 0; i < 2000 && !_stop; i++) {
        uint64_t in2[2] = { (uint64_t)(i & 63), 0 };
        uint8_t stb[64];
        memset(stb, 0xAA, sizeof(stb));
        size_t osz1 = 16; uint64_t out[4]; uint32_t oc = 4; memset(out, 0, sizeof(out));
        uint8_t o[16]; size_t osz = sizeof(o);
        kern_return_t kr;
        if (i & 1) kr = IOConnectCallMethod(c, in2[0], in2, 2, NULL, 0, out, &oc, NULL, NULL);
        else kr = IOConnectCallStructMethod(c, in2[0], stb, 8 + (i & 15) * 8, o, &osz);
        if (prev != (kern_return_t)-1 && kr != prev) {
            flips++;
            rl("[rc] agx flip %d->%d (i=%d)", prev, kr, i);
        }
        prev = kr;
        n = i;
        if ((i & 31) == 31) usleep(2000);
    }
    rl("[rc] agx done n=%d flips=%d last=0x%x", n, flips, prev);
    IOServiceClose(c);
    return NULL;
}

void nk_racer_run(void) {
    nk_filelog_open("racer");
    rl("[rc] racer session start");
    _stop = 0;
    if (pthread_barrier_init(&_barrier, NULL, 5) != 0) {
        rl("[rc] barrier init fail");
        nk_filelog_close();
        return;
    }
    pthread_t th[5];
    int cnt = 0;
    if (pthread_create(&th[cnt++], NULL, race_open_cycle, NULL) != 0) cnt--;
    if (pthread_create(&th[cnt++], NULL, race_ks_ab, (void *)(intptr_t)17) != 0) cnt--;
    if (pthread_create(&th[cnt++], NULL, race_ks_ab, (void *)(intptr_t)35) != 0) cnt--;
    if (pthread_create(&th[cnt++], NULL, race_ks_wide, NULL) != 0) cnt--;
    if (pthread_create(&th[cnt++], NULL, race_agx, NULL) != 0) cnt--;
    rl("[rc] threads=%d", cnt);
    for (int i = 0; i < cnt; i++) pthread_join(th[i], NULL);
    rl("[rc] racer session end threads=%d", cnt);
    pthread_barrier_destroy(&_barrier);
    nk_filelog_close();
}
