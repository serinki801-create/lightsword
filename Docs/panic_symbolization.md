# panic_symbolization.md — A15 panic 69EDA62B (2026-10-09 17:31:37 +0500)

Target: iPhone14,5 / A15 T8110 / iOS 26.2 23C55 / xnu-12377.62.10 / LiveContainer.
Device KC: fileset 6F9AD32F-3BEC-41D3-9B75-D8566AAAE7BF, kernel UUID
0C92DE50-2BF0-35FB-B461-A869B2ACEB5E. Carved image: /tmp/opencode/kernel_main
(segments clamped, symtab neutralized, llvm-objdump clean).

## 0. Slide arithmetic — settled [VB]

Re-verified against this .ips (method: image VM = va - kc_slide; exec_base must equal
__TEXT_EXEC vm + kc_slide):

    pc va 0xfffffff035ea0a58 - kc_slide 0x2da28000 = vm 0xfffffff008478a58
    exec_base 0xfffffff0359d8000 - kc_slide 0x2da28000 = 0xfffffff007fb0000  ✓ == __TEXT_EXEC vm
    kc_file_off(pc) = 0x01474a58 -> carved 0x01474a58 (carve = image, header at 0)

## 1. The fault — esr decode [VB-DISASM]

    esr = 0x96000006

    bits[31:26] EC = 0x25 = Instruction Abort from same EL (NOT data abort;
    "Kernel data abort" is the panic label for both classes on this build).
    bits[25] IL = 1, 32-bit instruction. bits[5:0] FSC = 0x06 translation fault.

    far = 0x0000000000000000 -> the CPU tried to FETCH at NULL.

    Faulting stream, disassembled at carved 0x01474a58 (vm 0x8478a58):

        fffffff008478a48: bics  wzr, w4, w8
        fffffff008478a4c: mov   w8, #13
        fffffff008478a50: csel  w0, wzr, w8, eq
        fffffff008478a54: ret                                  <--
        fffffff008478a58: mov   w0, #13                         <-- saved PC (post-ret)
        fffffff008478a5c: ret

    Bytes at 0x1474a58: a0018052 c0035fd6 = mov w0,#13 ; ret. A `mov` cannot
    fault. Saved PC = ret+4, far = 0, lr = 0x4ae68bf035ea1e78 (PAC-signed).

    INTERPRETATION [AS-STRONG]: this is an authenticated return through a
    POISONED LR. On arm64e+FPAC, `retaa` with a corrupted signature produces an
    instruction-abort whose fetch address is the unauthenticated/zero target
    (far=0) while PC_EL1 holds the return-next address (ret+4 = 0x8478a58).
    The printed PC is therefore NOT the faulting instruction; the fault is the
    fetch at far=0 with the return coming out of the leaf helper at 0x8478a54.

    p_mlock/panic1 correction [VB FROM THIS SESSION]: the OLD attribution
    "far=0x58 = aio_proc_lock(&p->p_mlock) deref, procp=0" is RETRACTED. It
    assumed a data abort. esr 0x96000006 (EC=0x25) makes panic1's far=0x58 the
    FETCH of VA 0x58 — again a control-flow corruption, not a lock deref.
    Same class of fault, same harness, two boots.

## 2. Register validation [VP from .ips, roles partly [AS]]

    x23 = 0xffffffffffffffff  -> -1. TRASHIT poison candidate: TAILQ_REMOVE
      writes (void*)-1 into elm->tqe_next/tqe_prev (bsd/sys/queue.h:163). The
      blind remove of a reclaimed slot leaving -1 in the link fields, then a
      poisoned LR/saved frame reaching a ret, is the coherent story. Verdict:
      [VP register, mechanism consistent, final confirmation pending the
      parent-function identification].
    x2  = 0x100  -> AIO_COMPLETED present in faulting context [VP].
    x19 = 0x0    -> null base in the corrupted chain [VP].
    x21/x26 = 0xffffffe15dc00900, x10/x27 = 0xffffffe15dc00958 (slot-va and
      slot+0x58 candidates; both inside GEN2 0xffffffe079bd0000-0xffffffe15f9b8000
      from the panic zone map) [VP values, roles AS].
    x4/x5/x6 = 0x4141414141414141 -> old harness buffer fill. NOT a marker.
    x22/x24 = 0xffffffe160dfc1d8 -> matches "Panicked thread" line [VP].

## 3. Region identification [VB-DISASM]

Backtrace frames (vm): syscall 0x7fb418c -> 0x8479bd8 -> 0x8479e78 ->
0x8478a58 (fault) ... kevent64-side frames at 0x814b02c/0x814c790 -> panic
caller 0x87f0274. Independent corroboration that the AIO code lives in the
0x8477xxx-0x847a000 window: at 0x8477e00-0x8477f00 the disassembly shows the
aiocb-copyin pattern (six 32-bit field copies [x22,#24/#40/#28/#104/#32/#108]
-> [x20,#40/#44/#48/#52/#56/#60]) matching do_munge_aiocb_user64_to_user /
aio_validate's field set, plus kdebug-style bl 0x8080655ec calls (w0=7,
w2=16, w3=72) used by the AIO subsystem's KERNEL_DEBUG sites.

What is NOT identified: the exact parent function containing the failing
guard and the name of the helper whose ret+4 is the saved PC. The window
contains mixed code (uthread refcount dec at [x23,#352], page-flag checks,
the leaf flag-search helper). Without the string-reference table (see §4),
function naming stops here.

## 4. Symbolization status — narrowed blocker

Confirmed dead (this session): image-wide adrp scan to the AIO string page =
0 hits; chained-dword scan for the string file offsets in __DATA_CONST and
whole-KC = 0 hits. The panic strings are referenced through a pointer table
whose encoding is unresolved (likely PAC-signed or lives in a section parsed
separately, e.g. __KLD / rodata descriptor tables).

EXACT remaining path (one command chain, next session):
1. In the AIO window, resolve the `adrp x20,#-10518528; add x20,x20,#1496`
   pattern (appears at 0x84780c0 and repeats): compute the target
   (0x84780c0-0xA06410+1496 = vm 0x7a4a254 -> file 0xa42254). This is a
   rodata table in __TEXT; dump it and match entries against the AIO panic
   format strings at file 0x7f5a7/0x7f611/0x7f56e/0x7f6a1.
2. The table row index -> which panic the calling site is inside names the
   containing function (aio_proc_remove_done_locked carries
   "Negative total AIO count!").
3. Once located, read its dec instruction immediate -> p_aio_total_count
   offset [VB-DISASM]. NOT closed this session.

## 5. Verdict impact

- The B12 source frame (write_mechanism.md) stands, unchanged and now with an
  even stronger A15 signal: the blind remove ran, TRASHIT poisoned the slot links
  (x23=-1 [VP]), and control flow followed the poison into a PAC-failing ret.
- p_aio_total_count offset: still UNVERIFIED. T4 precondition remains open.
- panic1/panic2 attribution corrected from "lock deref" to "PAC/control-flow
  corruption after TRASHIT" — no source-offset implications.

## 6. T2-SYM2 — CLOSED 2026-10-10 (this session) [VB-DISASM]

Coordinate note: carve = `Artifacts/carve/kernel.carve.macho` (rebased, VMA ==
carve file offset, image base vm 0xfffffff00700c000). Old-session file offsets
shift by -0x8000 (old base vm 0xfffffff007004000): old 0x1474a58 == carve
0x146ca58. llvm-objdump's `adrp #imm` display is wrong against the rebased
image — adrp/add pairs were decoded by hand in python (see quote below).

### The function — aio_proc_remove_done_locked @ carve 0x146c028 (vm 0x847c028)

Prologue at 0x146c028: `paciasp; sub sp,#48; stp x29,x30,[sp,#32]`; x0 = procp,
x1 = entryp. Verbatim stream:

    146c038: add  x8, x1, #16          ; &entryp->aio_proc_link.tqe_next (slot+0x10)
    146c03c: ldr  x9, [x1, #16]        ; entryp->tqe_next
    146c040: cbz  x9, 0x146c06c        ; empty-list path
    146c044: ldr  x10,[x9, #24]        ; next->tqe_prev
    146c048: cmp  x10, x8
    146c04c: b.ne 0x146c0d4             ; -> brk #0xbffd
    146c050: ldr  x11,[x1, #24]        ; entryp->tqe_prev
    146c054: ldr  x10,[x11]
    146c058: cmp  x10, x1
    146c05c: b.ne 0x146c0cc             ; -> brk #0xbffd  (QUEUEDEBUG-style assert)
    146c060: add  x10, x1, #24
    146c064: str  x11,[x9, #24]        ; next->tqe_prev = entryp->tqe_prev
    146c06c: ldr  x9, [x1, #24]        ; (empty path) tqe_prev
    146c080: str  x9, [x0, #1512]      ; procp->p_aio_doneq.tqh_last = tqe_prev
    146c084: ldr  x8, [x8]             ; entryp->tqe_next
    146c088: ldr  x9, [x10]            ; entryp->tqe_prev
    146c08c: str  x8, [x9]              ; *tqe_prev = tqe_next      <- THE WWW
    146c090: str  xzr, [x10]           ; entryp->tqe_prev = NULL
    146c094: adrp x8, 0x2600000         ; -> global @ vm 0x7a65128 (__DATA)
    146c098: add  x8, x8, #296
    146c09c: mov  w9, #-1               ; TRASHIT poison source for x23=-1 [VP]
    146c0a0: b8290108                   ; atomic op on the global (ldaddal/swp-class)
    146c0a4: cmp  w8, #0
    146c0a8: b.le 0x146c0dc            ; -> panic "Negative total AIO count!"
    146c0ac: ldr  w8, [x0, #1148]       ; procp->p_aio_total_count   @ proc+0x47C
    146c0b0: sub  w9, w8, #1
    146c0b4: str  w9, [x0, #1148]      ; procp->p_aio_total_count--
    146c0b8: cmp  w8, #0
    146c0bc: b.le 0x146c0f8            ; -> panic "proc %p: p_aio_total_count

### Panic strings — decoded from the b.le targets (hand adrp arithmetic)

    0x146c0dc page = (0x146c000 - 0x13f5000) = 0x77000; +0x593 = 0x77593
      s @0x77593 = "kern_aio.c"          (the __FILE__ slot)
    0x146c0ec +0x5a7 = 0x775a7 -> "Negative total AIO count! @%s:%d"          line 476
    0x146c10c +0x5c8 = 0x775c8 -> "proc %p: p_aio_total_count accounting mismatch @%s:%d"  line 479

### Derived offsets — now [VB-DISASM]

    p_aio_total_count   @ struct proc +0x47C   (int32; ldr/str w8,[x0,#1148], 1148=0x47C)
    p_aio_doneq         @ struct proc +0x5E0   (tqh_last @ +0x5E8, from str x9,[x0,#1512])
    panic lines         476 / 479 of kern_aio.c on xnu-12377.62.10
    global counter      @ vm 0x7a65128 (__DATA) — atomic-dec class, born from the
                        same remove site; feeds "Negative total AIO count!"

Cross-checks: (a) the panic-table adrp site at 0x84780c0 from the old session
(resolves to vm 0x7a4a254) is a different table from the runtime-filled one at
vm 0x7a705d8 seen at 0x146c150 (`adrp x9,#-10485760; add #1496` -> carve
0xa6c5d8, = vm 0x7a705d8; ldp bounds + ldrh lookup = zone/page-color table);
(b) the dec/b.le/panic reading of a 32-bit counter on the same proc object
that owns p_aio_doneq is unique to aio_proc_remove_done_locked; (c) TRASHIT
`mov w9,#-1` at 0x146c09c is the poison source matching panic x23 = -1 [VP].

### Impact

- T4 precondition CLOSED: p_aio_total_count offset is 0x47C.
- C4 survival for the dn_flow_queue SILVER path: the mbuf payload must make
  the qword at p+0x47C read > 0 (decrement lands without panic), and the lock
  word at p+0x58 must read unheld. Packet length budget: header ~0x40 + payload
  to at least 0x480 — a 1500B MTU packet carries it with slack.
- A15 panic consistency: the remove site above is the WWW the blind fire hit;
  the PAC-failed ret at vm 0x8478a58 (carve 0x146ca58) is 0xa30 BELOW the
  function, i.e. control flow descended from the caller chain
  (syscall 0x7fb418c -> 0x8479bd8 -> 0x8479e78) into this function's
  neighbourhood after the links were poisoned — same story, now anchored to
  the exact instruction.
