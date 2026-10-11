# fire_log.md — fire path, validation gates, T4 propagation (2026-10-10, static)

Target: iOS 26.2 / 23C55 / iPhone14,5 / A15. Carve `Artifacts/carve/kernel.carve.macho`
(VMA == carve file offset; container offsets +0x8000). Hand-decoded adrp/add
(llvm display invalid on the rebased image).

## Fire path — find-walk (function @ carve 0x146e9c0, call it aio_find_aiocb)

    146e9e8: ldr x21, [x0, #1504]   ; entryp = proc-><list1>.tqh_first
    146e9f0: ldr x8,  [x21, #64]    ; entryp->procp         (slot+0x40)
    146e9f4: cmp  x8, x0
    146e9f8: b.ne 0x146eb34         ; -> panic kern_aio.c:858
    146e9fc: ldr x8,  [x21, #72]    ; entryp->uaiocbp       (slot+0x48)
    146ea00: ldr x9,  [x1]          ; user aiocb pointer
    146ea04: cmp  x8, x9
    146ea08: b.eq  0x146ea50        ; FOUND -> remove path
    146ea0c: ldr x21, [x21, #16]    ; entryp->aio_proc_link.tqe_next (+0x10)
    146ea10: cbnz x21, 0x146e9f0    ; walk (BLIND follow of tqe_next)
    146ea14: ldr x8,  [x0, #1488]   ; proc-><list2>.tqh_first
    146ea1c: ldr x9,  [x8, #64]
    146ea20: cmp  x9, x0
    146ea24: b.ne 0x146eb44         ; -> panic kern_aio.c:877
    146ea28: ldr x9,  [x8, #72]
    146ea2c: ldr x10, [x1]
    146ea30: cmp  x9, x10
    146ea34: b.eq  0x146ea98        ; FOUND in list2 (w0=36)
    146ea38: ldr x8,  [x8, #16]
    146ea3c: cbnz x8,  0x146ea1c    ; walk list2

Batch drain (function @ 0x146ec00): same two checks, mismatch -> panic
`"AIO on a proc list that does not belong to that proc. @%s:%d"` kern_aio.c:971 @
0x146ed6c.

### Derived offsets
    p_aio_doneq   @ proc+0x5E0  (list1, THREE independent sites: 0x146c080 str
                               tqh_last +0x5E8, 0x146e9e8 ldr tqh_first,
                               0x146ec38 ldr tqh_first)
    <list2>       @ proc+0x5D0  (0x146ea14 / 0x146ec30 ldr #1488; second walk,
                               panics at kern_aio.c:877/971)

## The remove (aio_proc_remove_done_locked @ 0x146c028) — settled [VB-DISASM]

    TAILQ_REMOVE slot+0x10/+0x18 from p_aio_doneq; TRASHIT -1 into links
    (mov w9,#-1 @0x146c09c); per-proc counter dec @ proc+0x47C (panic mismatch
    line 479); global atomic counter @ vm 0x7a65128 (panic "Negative total AIO
    count!" line 476) [R16].

## Post-remove at the single-entry call site (0x146ea50)

    146ea58: bl  0x146c028          ; remove(procp=x0, entryp=x1)
    146ea5c: ldr x8, [x21, #32]     ; entryp->returnval (+0x20)
    146ea60: str x8, [x23]          ; READ CHANNEL: slot+0x20 -> user out ptr
    146ea78: add x0, x21, #44       ; &entryp->aio_refcount (+0x2C)
    146ea7c: mov w8, #-1            ; TRASHIT #2
    146ea80: <atomic store>         ; refcount = -1  (second poison site)

## T4 precondition #8 — poison propagation, settled this session

Two-phase death, matches all device panics:

    Phase 1 (the fire): the kevent64 reap path (filt_aioprocess on stale
      kn_hook, component (iv) — the SETTLED active component) does NOT run the
      find-walk. It takes entryp from the knote, dereferences entryp->procp
      (+0x40) to aio_proc_lock(&p->p_mlock) (lock word @ p+0x58) and enters the
      remove above. That is why a foreign +0x40 is survivable LONG ENOUGH to
      run the WWW and the TRASHIT stores — the aio_proc_lock/dec craft budget
      (mbuf+0x58 zero, mbuf+0x47C > 0, packet >= 0x480 B) applies exactly here.
    Phase 2 (the kill): the TRASHIT -1 lands in slot+0x10/+0x18 and the slot
      stays linked in p_aio_doneq from the reclaimer's perspective. The NEXT
      find-walk on that proc follows tqe_next blindly (0x146ea0c):
        tqe_next = -1  ->  x21 = 0xffffffffffffffff
        next iteration ldr x8,[x21,#64] = read at 0xffff...ffc0 (non-canonical)
      and/or the earlier WWW write `*(slot+0x18) = slot+0x10` lands a wild
      pointer into a saved frame; the leaf flag-search helper at 0x146ca58
      (`mov w0,#13; ret`) returns through it -> PAC auth fails -> retaa fetch
      at NULL -> ESR EC=0x25, far=0. That is the 2026-10-09 panic (x23=-1
      TRASHIT register [VP] now sourced to 0x146c09c).

Target-selection rule that follows (T4 #8): a SCRATCH target must be chosen so
that (a) the write value at *(scratch) cannot be a code pointer, (b) nothing
the corrupted chain returns through can be a saved LR — i.e. the target qword
lives in a data-only scratch kernel object whose VA was leaked via the read
channel, never a list head, never a thread/stack frame.

Also note the deterministic gates: if the SAME slot is reached through the
find-walk (not the knote path), a foreign +0x40 panics immediately at
kern_aio.c:858/877/971. The exploit path must therefore be the knote-fire
path (component (iv)) and must fire before any find-walk runs on that proc.

## No fires logged yet (T4 budget intact: 0 used of <=2 benign, <=5 live)
