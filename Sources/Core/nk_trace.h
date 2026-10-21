#ifndef TRACE_LOG_H
#define TRACE_LOG_H

#include <stddef.h>

void trace_open(void);
void trace_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void trace_close(void);

/* Per-probe durable log under Documents/<name>, next to trace.log.
   Each line is written(2)+fsync(2), so the file on disk ends exactly at the
   line that killed the process — the only evidence that survives a kernel
   panic / fly-away. nk_doc_log_open() is idempotent per name; the fd stays
   open until nk_doc_log_close_all(). */
void nk_doc_log_open(const char *name);
void nk_doc_log(const char *name, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
int  nk_doc_log_path(const char *name, char *out, size_t out_sz);
void nk_doc_log_close_all(void);
int  nk_doc_log_export(const char *dest_dir);
void nk_doc_log_set_visible_dir(const char *dir);  /* where the Swift side wants them */  /* copy the durable logs elsewhere */

#endif
