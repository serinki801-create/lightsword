#include "nk_trace.h"
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <time.h>

static int g_fd = -1;
static char g_path[512] = {0};

// Создаём папку если её нет
static void ensure_dir(const char *dir) {
    struct stat st;
    if (stat(dir, &st) != 0) {
        mkdir(dir, 0755);
    }
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
