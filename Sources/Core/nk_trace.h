#ifndef TRACE_LOG_H
#define TRACE_LOG_H

void trace_open(void);
void trace_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void trace_close(void);

#endif
