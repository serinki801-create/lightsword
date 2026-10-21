#include "nk_trace.h"
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include "nk_home.h"
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <time.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include "nk_home.h"

static int g_fd = -1;
static char g_path[512] = {0};

// Создаём папку если её нет
static void ensure_dir(const char *dir) {
    struct stat st;
    if (stat(dir, &st) == 0) return;
    /* mkdir -p: create each component */
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s", dir);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    mkdir(tmp, 0755);
}

static const char *trace_path(void) {
    if (g_path[0] != 0) return g_path;
    
    const char *home = getenv("HOME");
    if (!home || home[0] == 0) {
        // Fallback если нет HOME
        home = "/var/mobile/Containers/Data/Application";
    }
    
    // Пробуем создать папку Documents
    char docs_path[512];
    snprintf(docs_path, sizeof(docs_path), "%s/Documents", home);
    ensure_dir(docs_path);
    
    snprintf(g_path, sizeof(g_path), "%s/trace.log", docs_path);
    return g_path;
}

void trace_open(void) {
    if (g_fd >= 0) return;
    
    const char *path = trace_path();
    g_fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    
    if (g_fd < 0) {
        // Fallback в /tmp
        g_fd = open("/tmp/trace.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    }
    
    if (g_fd >= 0) {
        fcntl(g_fd, F_NOCACHE, 1);
    }
}

void trace_log(const char *fmt, ...) {
    if (g_fd < 0) trace_open();
    if (g_fd < 0) return;
    
    char buf[1024];
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm t;
    localtime_r(&tv.tv_sec, &t);
    
    int off = snprintf(buf, sizeof(buf), "[%02d:%02d:%02d.%03d] ",
                       t.tm_hour, t.tm_min, t.tm_sec, tv.tv_usec / 1000);
    
    va_list ap;
    va_start(ap, fmt);
    off += vsnprintf(buf + off, sizeof(buf) - off, fmt, ap);
    va_end(ap);
    
    if (off < (int)sizeof(buf) - 1) buf[off++] = '\n';
    
    write(g_fd, buf, off);
    fsync(g_fd);
}

void trace_close(void) {
    if (g_fd >= 0) {
        close(g_fd);
        g_fd = -1;
    }
}

/* ------------------------------------------------------------------ */
/* Per-probe durable logs under Documents/ (next to trace.log)          */
/* ------------------------------------------------------------------ */
#define DOCLOG_MAX 8

typedef struct {
    char name[64];
    char path[512];
    int  fd;
} doclog_t;

static doclog_t g_doclogs[DOCLOG_MAX];
static pthread_mutex_t g_doclog_lock = PTHREAD_MUTEX_INITIALIZER;

/* fd must start at -1: a static array zero-initialises fd to 0, and 0 is a
   VALID fd (stdin). With fd==0 every slot looked "open" and the open loop
   never reached the open() call, so no log file was ever created. */
static void doclogs_init(void)
{
    for (int i = 0; i < DOCLOG_MAX; i++) g_doclogs[i].fd = -1;
}

static const char *docs_dir(void)
{
    static char dir[512];
    if (!dir[0]) {
        /* Try several candidate homes in order; pick the first one whose
           Documents/ can actually be created and written to. */
        const char *cands[3];
        int n = 0;
        if (nk_home_dir() && nk_home_dir()[0]) cands[n++] = nk_home_dir();
        const char *env = getenv("HOME");
        if (env && env[0]) cands[n++] = env;
        cands[n++] = "/var/mobile";
        /* NOTE: /tmp is deliberately NOT a candidate — the LiveContainer guest
           sandbox rejects it silently, so a log written there is invisible. */
        for (int ci = 0; ci < n; ci++) {
            char tmp[512];
            /* a candidate that already ends in /Documents IS the documents
             * dir - do not append another one */
            size_t cl = strlen(cands[ci]);
            if (cl >= 9 && !strcmp(cands[ci] + cl - 9, "/Documents"))
                snprintf(tmp, sizeof(tmp), "%s", cands[ci]);
            else
                snprintf(tmp, sizeof(tmp), "%s/Documents", cands[ci]);
            ensure_dir(tmp);
            /* probe: try to create a test file */
            char test[600];
            snprintf(test, sizeof(test), "%s/.probe", tmp);
            int fd = open(test, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd >= 0) {
                (void)write(fd, "ok", 2);
                close(fd);
                unlink(test);
                snprintf(dir, sizeof(dir), "%s", tmp);
                return dir;
            }
        }
        /* fallback */
        {
            size_t hl = strlen(nk_home_dir());
            if (hl >= 9 && !strcmp(nk_home_dir() + hl - 9, "/Documents"))
                snprintf(dir, sizeof(dir), "%s", nk_home_dir());
            else
                snprintf(dir, sizeof(dir), "%s/Documents", nk_home_dir());
            ensure_dir(dir);
        }
    }
    return dir;
}

void nk_doc_log_open(const char *name)
{
    if (!name || !name[0]) return;
    static int inited = 0;
    if (!inited) { doclogs_init(); inited = 1; }

    pthread_mutex_lock(&g_doclog_lock);
    for (int i = 0; i < DOCLOG_MAX; i++) {
        if (g_doclogs[i].fd >= 0 && !strncmp(g_doclogs[i].name, name, sizeof(g_doclogs[0].name) - 1)) {
            pthread_mutex_unlock(&g_doclog_lock);
            return;
        }
    }
    for (int i = 0; i < DOCLOG_MAX; i++) {
        if (g_doclogs[i].fd >= 0) continue;
        snprintf(g_doclogs[i].name, sizeof(g_doclogs[i].name), "%s", name);

        /* Try multiple candidate homes */
        const char *homes[3];
        int nh = 0;
        if (nk_home_dir() && nk_home_dir()[0]) homes[nh++] = nk_home_dir();
        const char *env = getenv("HOME");
        if (env && env[0]) homes[nh++] = env;
        homes[nh++] = "/var/mobile";
        /* /tmp excluded: the LC guest sandbox rejects it silently. */
        for (int hi = 0; hi < nh; hi++) {
            char docs[512];
            /* a home that already ends in /Documents IS the documents dir */
            size_t hl2 = strlen(homes[hi]);
            if (hl2 >= 9 && !strcmp(homes[hi] + hl2 - 9, "/Documents"))
                snprintf(docs, sizeof(docs), "%s", homes[hi]);
            else
                snprintf(docs, sizeof(docs), "%s/Documents", homes[hi]);
            /* mkdir -p */
            char tmp[512];
            snprintf(tmp, sizeof(tmp), "%s", docs);
            for (char *pp = tmp + 1; *pp; pp++) {
                if (*pp == '/') { *pp = '\0'; mkdir(tmp, 0755); *pp = '/'; }
            }
            mkdir(tmp, 0755);

            snprintf(g_doclogs[i].path, sizeof(g_doclogs[i].path), "%s/%s", docs, name);
            g_doclogs[i].fd = open(g_doclogs[i].path, O_WRONLY | O_CREAT | O_APPEND, 0644);
            if (g_doclogs[i].fd >= 0) {
                fcntl(g_doclogs[i].fd, F_NOCACHE, 1);
                char hdr[128];
                struct timeval tv;
                gettimeofday(&tv, NULL);
                struct tm t;
                localtime_r(&tv.tv_sec, &t);
                int n = snprintf(hdr, sizeof(hdr),
                                  "=== %s session %02d:%02d:%02d ===\n",
                                  name, t.tm_hour, t.tm_min, t.tm_sec);
                if (n > 0) { (void)write(g_doclogs[i].fd, hdr, (size_t)n); fsync(g_doclogs[i].fd); }
                /* Also log to trace.log */
                char msg[600];
                snprintf(msg, sizeof(msg), "[DOCLOG] %s -> %s (fd %d)\n",
                         name, g_doclogs[i].path, g_doclogs[i].fd);
                /* Show the absolute path in the UI log too: after a kernel
                 * panic the device reboots and the only way back to the
                 * evidence is knowing exactly which file to open. */
                trace_log("[DOCLOG] %s -> %s", name, g_doclogs[i].path);
                /* write to trace.log directly */
                if (g_fd < 0) trace_open();
                /* keep an index of the durable logs in Documents/ so that
                 * after a reboot one file tells the whole story */
                {
                    char idx[512];
                    snprintf(idx, sizeof(idx), "%s/Documents/LOGS.txt", homes[hi]);
                    int ifd = open(idx, O_WRONLY | O_CREAT | O_APPEND, 0644);
                    if (ifd >= 0) {
                        char line[700];
                        int n = snprintf(line, sizeof(line),
                                         "[%02d:%02d:%02d] %s -> %s\n",
                                         t.tm_hour, t.tm_min, t.tm_sec, name,
                                         g_doclogs[i].path);
                        if (n > 0) { (void)write(ifd, line, (size_t)n); fsync(ifd); }
                        close(ifd);
                    }
                }
                if (g_fd >= 0) { write(g_fd, msg, strlen(msg)); fsync(g_fd); }
                break;
            }
        }
        if (g_doclogs[i].fd < 0) {
            char msg[600];
            snprintf(msg, sizeof(msg), "[DOCLOG] %s OPEN FAILED errno=%d home=%s\n",
                     name, errno, nk_home_dir());
            if (g_fd < 0) trace_open();
            if (g_fd >= 0) { write(g_fd, msg, strlen(msg)); fsync(g_fd); }
        }
        break;
    }
    pthread_mutex_unlock(&g_doclog_lock);
}

void nk_doc_log(const char *name, const char *fmt, ...)
{
    if (!name || !name[0]) return;
    /* lazy open: nk_log() may fire before nk_doc_log_open() and the first
       lines must not be lost (session header included). */
    int have = 0;
    pthread_mutex_lock(&g_doclog_lock);
    for (int i = 0; i < DOCLOG_MAX; i++)
        if (g_doclogs[i].fd >= 0 && !strncmp(g_doclogs[i].name, name, sizeof(g_doclogs[0].name) - 1)) { have = 1; break; }
    pthread_mutex_unlock(&g_doclog_lock);
    if (!have) nk_doc_log_open(name);

    pthread_mutex_lock(&g_doclog_lock);
    int target_fd = -1;
    for (int i = 0; i < DOCLOG_MAX; i++) {
        if (g_doclogs[i].fd < 0) continue;
        if (strncmp(g_doclogs[i].name, name, sizeof(g_doclogs[0].name) - 1)) continue;
        target_fd = g_doclogs[i].fd;
        break;
    }
    /* Fallback: if the named doc log could not be opened, append to
       trace.log (which we know exists) with a [DOC:<name>] prefix. */
    if (target_fd < 0) {
        if (g_fd < 0) trace_open();
        target_fd = g_fd;
    }

    if (target_fd >= 0) {
        char buf[1024];
        struct timeval tv;
        gettimeofday(&tv, NULL);
        struct tm t;
        localtime_r(&tv.tv_sec, &t);
        int off = snprintf(buf, sizeof(buf), "[%02d:%02d:%02d.%03d] ",
                           t.tm_hour, t.tm_min, t.tm_sec, (int)(tv.tv_usec / 1000));
        if (off < 0) off = 0;
        if (off > (int)sizeof(buf) - 2) off = (int)sizeof(buf) - 2;
        va_list ap;
        va_start(ap, fmt);
        int w = vsnprintf(buf + off, sizeof(buf) - (size_t)off - 1, fmt, ap);
        va_end(ap);
        if (w > 0) off += w;
        if (off > (int)sizeof(buf) - 2) off = (int)sizeof(buf) - 2;
        buf[off++] = '\n';
        (void)write(target_fd, buf, (size_t)off);
        fsync(target_fd);
    }
    pthread_mutex_unlock(&g_doclog_lock);
}

/* Absolute path of a doc log (for UI / path file). */
int nk_doc_log_path(const char *name, char *out, size_t out_sz)
{
    if (!name || !out || out_sz == 0) return -1;
    snprintf(out, out_sz, "%s/%s", docs_dir(), name);
    return 0;
}

void nk_doc_log_close_all(void)
{
    pthread_mutex_lock(&g_doclog_lock);
    for (int i = 0; i < DOCLOG_MAX; i++) {
        if (g_doclogs[i].fd >= 0) {
            close(g_doclogs[i].fd);
            g_doclogs[i].fd = -1;
        }
    }
    pthread_mutex_unlock(&g_doclog_lock);
}
