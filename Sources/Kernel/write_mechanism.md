# write_mechanism.md — B12 write-channel proof (T1 / 3B)

## 6. A15 panic 69EDA62B (2026-10-09) register validation

Target: iPhone14,5 / A15 / 23C55 / xnu-12377.62.10 / LiveContainer. Full
detail in panic_symbolization.md; this section is the load-bearing subset.

- esr 0x96000006 decodes EC=0x25 = INSTRUCTION ABORT, far=0: the CPU fetched
  at NULL. Saved PC 0x8478a58 is `ret`+4; LR is PAC-signed
  (0x4ae68bf035ea1e78). The panic label "Kernel data abort" is generic and
  covered the earlier far=0x58 panic too — the old "aio_proc_lock on
  procp=0" reading of panic1 is RETRACTED; it was a fetch-of-0x58.
- x23 = 0xffffffffffffffff in the faulting frame: TRASHIT poison from the
  blind TAILQ_REMOVE (queue.h:163 writes (void*)-1 to elm->tqe_next/tqe_prev)
  is the coherent source. [VP register]
- x2 = 0x100 (AIO_COMPLETED) in the faulting context: the re-arm gate value
  [VP register].
- Backtrace: syscall 0x7fb418c -> AIO/kevent region 0x8479bd8 -> 0x8479e78 ->
  fault frame 0x8478a58; kevent64 frames 0x814b02c/0x814c790; the AIO code
  window is 0x8477xxx-0x847a000 (aiocb-copyin pattern at 0x8477e00, kdebug
  bl 0x8080655ec sites).
- Consequence for the channel: the fire sequence has now twice run on real
  A15 hardware and both times ended through TRASHIT-poisoned control flow,
  not through a write-check or an accounting panic. The write frame is live.
  Survivability (C4) is unchanged as the open problem: the fire itself must
  not poison anything the caller returns through.
- p_aio_total_count offset: **[VB-DISASM — CLOSED] proc+0x47C** (dec instruction
  + accounting-mismatch panic quote: Docs/panic_symbolization.md §6). p_aio_doneq @
  proc+0x5E0 derived from the same function.


Target: iOS 26.2 / 23C55 / iPhone14,5 / xnu-12377.62.10.
Device KC: UUID 6F9AD32F-3BEC-41D3-9B75-D8566AAAE7BF (identical to both panic logs).
Anchors: xnu-12377.61.12 (local `/home/abzal/xnu`), xnu-12377.81.4 (iOS 26.3,
`/tmp/opencode/xnu-xnu-12377.81.4`). 62.10 source is unpublished; all citations are
61.12 with the 81.4 twin confirmed identical unless noted.

## 1. The frame: a blind TAILQ_REMOVE on a stale pointer — PROVEN

`filt_aioprocess`, 61.12:2550-2579:

```c
entryp = knote_kn_hook_get_raw(kn);        // :2557 — stale after aio_return()
assert(entryp);                            // :2558
p = entryp->procp;                         // :2559 — read at +0x40
lck_mtx_lock(&aio_klist_lock);
if (kn->kn_fflags) {                       // :2562 — armed by filt_aioevent
    kn->kn_ext[0] = entryp->errorval;      // :2564 — +0x28 -> userspace
    kn->kn_ext[1] = entryp->returnval;     // :2565 — +0x20 -> userspace
    knote_fill_kevent(kn, kev, 0);         // :2566
    knote_kn_hook_set_raw(kn, NULL);       // :2567 (removed in 81.4 patch)
    aio_proc_lock(p);                      // :2569 — &p->p_mlock = procp+0x58
    aio_proc_remove_done_locked(p, entryp);// :2570 <== THE WRITE
    aio_proc_unlock(p);
    aio_entry_unref(entryp);               // :2572 — conditional second free
    res = FILTER_ACTIVE;
}
```

`aio_proc_remove_done_locked`, 61.12:470-480 — **there is no list search**:

```c
static void
aio_proc_remove_done_locked(proc_t procp, aio_workq_entry *entryp)
{
    TAILQ_REMOVE(&procp->p_aio_doneq, entryp, aio_proc_link);  // :473 — blind
    entryp->aio_proc_link.tqe_prev = NULL;                     // :474
    if (os_atomic_dec_orig(&aio_anchor.aio_total_count, relaxed) <= 0)
        panic("Negative total AIO count!");                    // :475-476
    ...
}
```

`TAILQ_REMOVE` (bsd/sys/queue.h), on this build (`QUEUEDEBUG` OFF → the
`TAILQ_CHECK_NEXT/PREV` guards at queue.h:635-650 compile out):

```c
if ((TAILQ_NEXT((elm), field)) != NULL)
        TAILQ_NEXT((elm), field)->field.tqe_prev = (elm)->field.tqe_prev;  /* write A */
*(elm)->field.tqe_prev = TAILQ_NEXT((elm), field);                          /* write B */
TRASHIT((elm)->field.tqe_next);   /* elm->tqe_next  = (void*)-1 */
TRASHIT((elm)->field.tqe_prev);   /* elm->tqe_prev  = (void*)-1 */
```

With `elm` = the reclaimed slot:

- write A = `*(slot+0x10 value + 0x10) = (slot+0x18 value)` (only when +0x10 != 0)
- write B = `*(slot+0x18 value) = (slot+0x10 value)` — an 8-byte write of a chosen
  value to a chosen kernel address, if +0x10/+0x18 are controlled
- TRASHIT then poisons the slot's own +0x10/+0x18 to -1
- 81.4 identical: `aio_proc_remove_done_locked` at :472-474, body unchanged.

Device-side proof of presence: the KC string set carries
`"proc %p: p_aio_total_count accounting mismatch @%s:%d"` (that exact function's
panic), plus `"aio_workq_entry %p being freed while still enqueued @%s:%d"`
(aio_free_request), `"Negative total AIO count! @%s:%d"`,
`"Trying to remove an entry from a work queue, but it is not on a queue @%s:%d"`,
`"AIO on a proc list that does not belong to that proc. @%s:%d"`. The struct is
byte-identical between 61.12 and 81.4. Sandwich complete: the blind remove runs
on 23C55.

## 2. The re-arm trigger — PROVEN

`do_aio_completion_and_unlock` tail (61.12; 81.4:2216-2218 same):

```c
} else if (do_kevent) {
    lck_mtx_lock(&aio_klist_lock);
    KNOTE(&aio_klist, 1);                 // walks EVERY AIO knote
    lck_mtx_unlock(&aio_klist_lock);
}
```

`filt_aioevent`, 61.12:2517-2542:

```c
entryp = knote_kn_hook_get_raw(kn);            // :2529 — the STALE slot pointer
if (__improbable(entryp == NULL)) goto out;    // :2530
if (entryp->flags & AIO_COMPLETED) {           // :2535 — reads slot+0x30
    kn->kn_fflags |= hint;                     // :2536 — arms the knote
    activate = FILTER_ACTIVE;                  // :2537
}
```

Consequence: completion of **any** SIGEV_KEVENT entry inspects the stale slot.
A zeroed slot (`flags == 0`) is SILENT (no arm, no crash). A reclaimed slot
showing `AIO_COMPLETED (0x100)` at +0x30 arms the knote and the next reap fires
the write. This is why panic1's far=0x58 (zeroed slot, arm-from-a-completed-
before-free ordering) and panic2's marker qwords (reclaimed slot) are both on
the same path.

## 3. Candidate sequences (1)-(4) against the source

**(1) DOUBLE-STALE — REFUTED for value control.**
Two knotes on one slot still converge on `aio_proc_remove_done_locked`, whose
remove consumes `+0x10/+0x18` of whatever occupies the slot. A reclaimed
same-subsystem entry's links are written by the kernel at insertion
(`aio_try_proc_insert_active_locked` 61.12:458 `TAILQ_INSERT_TAIL`, and
`aio_proc_move_done_locked` :466-467). Both are real list pointers into
`p->p_aio_activeq/p_aio_doneq`, never userspace data. Provides list-surgery,
not what-where. Panic2's marker qwords were at the aiocb-copy offsets, not at
+0x10/+0x18 — consistent with this.

**(2) LIO LEADER/PENDING CONFUSION — REFUTED.**
`do_aio_completion_and_unlock` (61.12:~800-880) touches only
`--leader->lio_pending` (+0x34) and `entryp->lio_leader = NULL` (+0x38).
`lio_leader` is a kernel entry pointer assigned in `lio_listio` (61.12:1466
context), not a user value. Nothing writes +0x10/+0x18 from lio state.

**(3) REFHANG — REFUTED.**
The premature `aio_entry_unref` at :2572 on a reclaimed entry drives its
refcount (+0x2C) to zero → `aio_free_request` (61.12:1973-1990):

```c
if (entryp->aio_proc_link.tqe_prev || entryp->aio_workq_link.tqe_prev)
    panic("aio_workq_entry %p being freed while still enqueued", entryp);
```

A live in-queue entry has non-NULL links → this path PANICS (that exact string
is in the device KC). With links NULL it just zfrees. No userspace value
reaches +0x10/+0x18 through the refcount path.

**(4) PROC RUNDOWN — REFUTED.**
`_aio_exit` (61.12:923+) and `do_aio_cancel_locked` (61.12:~1020-1090) walk with
`TAILQ_FOREACH_SAFE` over real list members; entry removal for cancels goes
through `aio_proc_remove_done_locked` on genuine members. No blind remove of
attacker-shaped links.

## 4. VERDICT

The **frame** for the write channel is proven: a blind `*(tqe_prev)=tqe_next`
on a stale slot, armed by any other entry's completion, fires a leaked-heap read
back to userspace plus an unlink with kernel-written link values.

The **value control** at +0x10/+0x18 is NOT reachable from any aio-subsystem
sequence: every writer of those fields in `bsd/kern/kern_aio.c` (61.12:
402/415/414-415, 458, 466-467, 473) writes kernel list pointers. No (1)-(4)
candidate supplies the two values.

Therefore the write channel is **CROSS-TYPE RECLAIM** (former W-C):
reclaim the freed 192-byte slot with a different `kalloc.type.192` object that
carries user-controlled bytes at +0x10/+0x18. It removes the value-control
problem by construction. This is T3 (bucket map).

**Per instructions: 3B is NOT settled from (1)-(4). Go to T3.** A neighbour
with a directly user-controlled +0x10/+0x18 is worth more than any unproven
sequence in this file.

## 5. What T2 must confirm on device for this to work

1. The read channel: `ext[1]`/`ext[0]` from the reclaimed slot (+0x20/+0x28),
   and `kev.data` = the original entry's kernel VA (61.12:1520 / 81.4:1534
   `kev.data = (intptr_t)entryp;` — the kalloc.type.192 heap leak).
2. That a spray object can occupy a freed aio slot at all — panic2's marker
   qwords are evidence *something* landed, but they were the buffer fill byte
   (0x41 = g_buf fill), not a placed marker. Per-field markers (T2 Gate 1) are
   the only acceptable evidence.
3. The outcome distribution {far 0x58 zeroed : reclaimed-with-marker :
   reclaimed-buffer-content : other} — that ratio is the A15 answer to
   upstream's A13 70% and pins the migration rate estimate.
