#pragma once
/* nk_state_machine.c — crash-driven probe state machine.
 * R7: a call that kills the LC guest uncatchably (SIGKILL from sandbox/jetsam,
 * or a Mach exception the sigaction guard never sees) cannot be caught. The
 * state machine detects the interruption on the NEXT launch — the previous run
 * left the probe marked RUNNING with no verdict — marks it DEAD, and the runner
 * skips it until the body is fixed. Verdicts persist in
 * Documents/nk_probe_state.json; the last-before-death line is the tail of
 * Documents/trace.log. */

#define NK_ST_RUNNING   (-1)
#define NK_ST_OK        0
#define NK_ST_RECOVERED 11
#define NK_ST_DEAD      9

void nk_state_load(void);                          /* call at launch         */
int  nk_state_should_skip(int probe_id);           /* DEAD probes are skipped */
void nk_state_begin(int probe_id);                 /* mark RUNNING pre-probe  */
void nk_state_end(int probe_id, int verdict);      /* verdict post-probe      */
int  nk_state_last_breadcrumb(char *out, int cap); /* >0 len, -1 no file, -2 empty */
void nk_state_reset(void);                         /* clear state file, re-enable all probes */
