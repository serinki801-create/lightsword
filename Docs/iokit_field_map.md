# iokit_field_map.md — T3 field-RE, session 2026-10-10 (static)

Target: iOS 26.2 / 23C55 / iPhone14,5 / A15. Carve `Artifacts/carve/kernel.carve.macho`
(rebased; VMA == carve file offset). All addresses below are carve coordinates.

## 0. Method — the decisive one

Instead of reconstructing ctors by hand (vtable pointers are chain-encoded, see §2),
the field map of each 192-class IOKit object is established by a **complete store
census over the whole class cluster**: disassemble the cluster bounds, collect every
`str/strb/strh` whose destination is the object register, and tabulate the byte
offsets written. An offset that is never written by the class stays at its Z_ZERO
allocation value. For the B12 slot this is exactly the question: what lands at
+0x10/+0x18/+0x30/+0x40 when the class reclaims the slot.

## 1. Cluster bounds (from the kalloc_type_view site scan, last session)

    IOCPU                    view @ carve 0xb1aed0  (rec 1086, kt_size 184)
    IOCPUInterruptController view @ carve 0xb1af10  (rec 1087, kt_size 184)
    IODTNVRAM                view @ carve 0xb1afd0  (rec 1090, kt_size 184)
    IOPowerConnection        view @ carve 0xb1c190  (rec 1161, kt_size 192)

## 2. Layout facts established this session [VB-DISASM]

New decode rule: 26.2 KCs use LC_DYLD_CHAINED_FIXUPS — pointer slots in __DATA are
`low32 = target container file offset`, `high32 = next | 0x80000000`. Corroboration:
the table @ carve 0xad2588 decodes as

    [2] 0x8011377101730eac -> 0x1728eac (IODTNVRAM cluster)   <- vtable/dispatch row
    [3] 0x801156b701730c84 -> 0x1728c84 (IODTNVRAM cluster)
    [4..13] 0x161f300-0x161f348 (OSObject/libkern generic methods)
    [14] 0x1751980
    [15] 0x8071160101730bd4 -> 0x1728bd4 (the ZFI alloc wrapper)

Object layout, from the alloc wrapper @ 0x1728bd4 and cluster stores:

    +0x00  chain word -> view+0x10, PAC-decorated  (str x16,[x0] with movk #52641<<48)
    +0x08  refcount = 1                            (str w8,[x0,#8], 5 sites)
    +0xB5  init flag = 1                           (strb w8,[x0,#181], 2 sites)
    +0x98  nulled in IODTNVRAM / IOPowerConnection (str xzr/x1,[x0,#152])
    +0x88  nulled in IOCPU/ICPUIC                  (str xzr,[x0,#136], 2 sites)

## 3. Store census — ALL four types, complete

Command: `llvm-objdump -d --start-address=<cluster>`; unique `str` destinations on the
object base register:

| type | cluster bounds | object-local stores | +0x10 | +0x18 | +0x30 | +0x40 |
|---|---|---|---|---|---|---|
| IODTNVRAM | 0x1728b00-0x172a200 | +0x00, +0x08 x5, +0x98, +0xB5 x2 | — | — | — | — |
| IOCPU / IOCPUInterruptController | 0x1718c80-0x1719700 | +0x08 x5, +0x88 x2 | — | — | — | — |
| IOPowerConnection | 0x1773880-0x1774100 | +0x08 x5, +0x98 | — | — | — | — |

The only +0x10-looking write in the IOCPU/ICPUIC cluster (`str w11,[x8,#16]` @
0x1718f9c and 0x17191c4) is inside a bit-shift loop storing to a hardware MMIO
register (interrupt EIRQ pending register), not a heap object field:

    1718f84: b.eq   0x1718f98
    1718f88: add    x10, x10, #1
    1718f90: b.ne   0x1718f78        ; loop over set bits
    1718f98: sub    w11, w11, #1
    1718f9c: str    w11, [x8, #16]  ; MMIO register write, x8 = controller base

## 4. C1-C4 verdict — ALL FOUR IOKIT NEIGHBOURS ARE DEAD [VB-DISASM]

    C1 +0x10 attacker value : ZERO. Never written by any of the four classes.
    C2 +0x18 attacker target: ZERO. Never written. The WWW would compute
                             *(+0x18) = NULL and store through NULL.
    C3 +0x30 bit 0x100      : ZERO. AIO_COMPLETED never set; the knote stays
                             SILENT — the reclaim produces NO event at all
                             (Z_ZERO slot, undetectable by the read channel).
    C4 +0x40 writable VA    : ZERO. procp = 0 -> aio_proc_lock(NULL) data abort.

Verdict per type: IODTNVRAM, IOCPU, IOCPUInterruptController, IOPowerConnection —
**BRONZE->DEAD, carried no further**. Not a scoring gap: the census is exhaustive
over each class's cluster (the only code that can write these objects), so the
absence is a fact, not an unfinished read.

Explicit death note per anti-drift rule: the competitor does not die because
+0x10 is PAC-decorated chain data (that would only matter if +0x10 were a pointer);
it dies because +0x10/+0x18/+0x30/+0x40 are **never written at all** — Z_ZERO
leaves them zero, and the WWW then writes through NULL.

## 5. Consequence for the plan

- The cross-type write channel has exactly ONE live candidate: dn_flow_queue
  (SILVER, C1/C2 via crafted IPv6 dst_ip6, C3 via flow label, C4 natural mbuf
  pointer, craft budget >= 0x480 B).
- Everything now hinges on the dummynet reachability verdict from D3. If D3
  returns EPERM/EACCES, dn_flow_queue dies and the cross-type plan needs a NEW
  neighbour class — which makes the site-scan method in this doc (view ->
  adrp+add site scan -> cluster bounds -> store census) the reusable tool for
  any future candidate type.
