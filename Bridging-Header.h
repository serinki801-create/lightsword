#pragma once
#include "exploit.h"
#include "nk_home.h"
#include "nk_state_machine.h"
#include "nk_trace.h"

void nk_async_main(void (^block)(void));
void nk_async_background(void (^block)(void));
void nk_async_main_after(double seconds, void (^block)(void));
void nk_crash_guard_install(const char *path);
int  nk_state_last_breadcrumb(char *out, int cap);
void nk_state_load(void);
void nk_jsbridge_log(const char *tag, const char *msg);
void nk_jsbridge_status(const char *kv);
int  nk_run_begin(const char *label);
int  nk_run_current(void);
/* W-T3 hunt convergence: dead probe candidates (page died mid-walk) */
void nk_probe_mark_dead(void);
int  nk_probe_dead_list(char *out, int cap);
void nk_probe_dead_clear(void);
int  nk_selftest_claim(int run);
void nk_fatal_webcontent(void);

void nk_iokit_fuzz(void);



void nk_iogpu_oob_run(void);
void nk_iogpu_oob64_run(void);
void nk_oob_hunt_run(void);
int  nk_aio_uaf_run(int attempts);
