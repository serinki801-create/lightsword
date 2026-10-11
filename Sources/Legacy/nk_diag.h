#ifndef NK_DIAG_H
#define NK_DIAG_H

#include "exploit.h"
#include <stdint.h>
#include <stddef.h>

/*
 * Diagnostics foundation for the exploitability harness.
 * Log-only by default. No memory access outside caller-owned buffers.
 */

#define NK_CANARY_MAGIC    0xC0FFEE01u
#define NK_EVENT_RING      1024
#define NK_MAX_OOL_SIZES   16

typedef struct {
    uint32_t magic;
    uint32_t epoch;
    uint32_t tid;
    uint32_t pad;
    uint64_t seq;
    uint64_t size;
    uint64_t pattern;
    uint64_t crc;
} nk_canary_t;

typedef enum {
    NK_CAN_OK        = 0,
    NK_CAN_MISS      = 1,
    NK_CAN_BADCRC    = 2,
    NK_CAN_FOREIGN   = 3,
    NK_CAN_STALE     = 4
} nk_canary_result_t;

typedef enum {
    NK_P0_REPRO_CONTROLLED = 0,
    NK_P1_DEFECT_NO_CONTROL = 1,
    NK_P2_RARE_PANIC        = 2,
    NK_P3_NOISE             = 3
} nk_triage_t;

uint32_t nk_crc32(const void *data, size_t len);

uint32_t nk_diag_epoch(void);
uint32_t nk_diag_boot_epoch(void);
uint64_t nk_diag_seq_next(void);
void     nk_diag_epoch_start(const char *module);
int      nk_diag_crash_pending(const char **reason);
int      nk_diag_panic_correlate(void);

void     nk_canary_stamp(void *buf, size_t size);
nk_canary_result_t nk_canary_check(const void *buf, size_t size,
    uint32_t *foreign_epoch, uint64_t *foreign_seq, uint32_t *foreign_tid);

void     nk_diag_event(const char *module, const char *kind,
    const char *fmt, ...);
void     nk_diag_ring_dump(void);
const char *nk_diag_log_path(void);
const char *nk_diag_report_path(void);

void     nk_diag_anomaly(nk_triage_t cls, const char *module,
    const char *detail_fmt, ...);
void     nk_diag_counts(nk_triage_t cls);
int      nk_diag_stop_after_same_crash(const char *tag);

#endif
