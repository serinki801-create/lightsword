// language: C, file: nk_home.c, target: iOS 26.2 / 23C55 / arm64e, LiveContainer guest
// Home + Documents resolution. AppMain.onAppear calls nk_set_home() with
// NSHomeDirectory(); setenv mirrors it for legacy getenv callers (trace.log).
// Load-bearing post-mortem evidence lives only under Documents/ — never /tmp,
// which the sandbox silently rejects for LC guests.

#include "nk_home.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

static char g_home[512];

void nk_set_home(const char *home)
{
    if (!home || !home[0]) return;
    size_t i = 0;
    for (; home[i] && i < sizeof(g_home) - 1; i++) g_home[i] = home[i];
    g_home[i] = 0;
    setenv("HOME", g_home, 1);
}

const char *nk_home_dir(void)
{
    return g_home[0] ? g_home : "/var/mobile";
}

/* The Documents directory of the app, resolved so that the file ends up
 * where the user actually looks. NSHomeDirectory() in the LiveContainer
 * guest already points AT a Documents directory (in the guest it is
 * nested: .../Application/<A>/Documents/Data/Application/<B>), so blindly
 * appending "/Documents" put every log one level too deep, where it was
 * invisible in the Files app. If the home path already ends in
 * /Documents it is used as-is; otherwise /Documents is appended. */
void nk_home_documents(char *out, size_t cap)
{
    const char *h = nk_home_dir();
    size_t n = strlen(h);
    if (n >= 9 && !strcmp(h + n - 9, "/Documents")) {
        snprintf(out, cap, "%s", h);
    } else {
        snprintf(out, cap, "%s/Documents", h);
    }
    mkdir(out, 0755);
}

void nk_home_path(const char *name, char *out, size_t cap)
{
    char docs[512];
    nk_home_documents(docs, sizeof(docs));
    snprintf(out, cap, "%s/%s", docs, name);
}
