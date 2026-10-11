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

void nk_home_documents(char *out, size_t cap)
{
    snprintf(out, cap, "%s/Documents", nk_home_dir());
    mkdir(out, 0755);
}

void nk_home_path(const char *name, char *out, size_t cap)
{
    char docs[512];
    nk_home_documents(docs, sizeof(docs));
    snprintf(out, cap, "%s/%s", docs, name);
}
