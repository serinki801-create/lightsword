#pragma once
/* nk_home.c — home/Documents resolution for the LiveContainer guest.
 * LC does not export HOME to its in-process guest, so AppMain.onAppear
 * passes NSHomeDirectory() at launch. Every C-side path (guard file, stage
 * breadcrumbs, trace.log, state file) resolves through here. */

#include <stddef.h>

void        nk_set_home(const char *home);
const char *nk_home_dir(void);
void        nk_home_documents(char *out, size_t cap);          /* fs-ready dir */
void        nk_home_path(const char *name, char *out, size_t cap);
