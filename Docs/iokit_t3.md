# iokit_t3.md — T3 IOKit neighbour scoring, session 2026-10-10

Target: iOS 26.2 / 23C55 / iPhone14,5 / A15. Carve: `Artifacts/carve/kernel.carve.macho`
(rebased; VMA == carve file offset; container offsets −0x8000). Hand-decoded adrp/add
(llvm-objdump adrp display is invalid against the rebased image).

## 1. Bucket membership — confirmed from the carve [VB]

Re-ran `Tools/bucket_map.py` on the container fileset entry (com.apple.kernel),
1261 kalloc_type_view records; the 192-class (kalloc.type.192) members:

    IOCPU                    rec 1086  size 184  flags 0x61  view vm 0xfffffff007b26ed0
    IOCPUInterruptController rec 1087  size 184  flags 0x61  view vm 0xfffffff007b26f10
    IODTNVRAM                rec 1090  size 184  flags 0x61  view vm 0xfffffff007b26fd0
    IOPowerConnection        rec 1161  size 192  flags 0x61  view vm 0xfffffff007b28190
    aio_workq_entry          rec  706  size 184  flags 0x61  view vm 0xfffffff007b20fd0

flags 0x61 same family as aio_workq_entry (ZFI + zone-params bits). Output saved to
`Artifacts/bucket_map.json`.

## 2. New object layout fact — [VB-DISASM]

kalloc_type objects in xnu-12377.62.10 start with a CHAIN WORD, not a raw vtable:

    IODTNVRAM alloc wrapper @ carve 0x1728bd4 (adrp view @0xb1afd0, mov w1,#184,
    mov w2,#0x44104, bl kalloc_type 0xff7834):
      1728c38: mov w8,#1; strb?/str w8,[x0,#8]     ; +0x08 = 1        (refcount)
      1728c40: adrp x16 -> view+0x10; add x16,x16,#16
      1728c58: str x16,[x0]                        ; +0x00 = view+0x10 chain (PAC-dec)
      1728c5c: strb w8,[x0,#181]                   ; +0xB5 = 1        (init flag)
    Metaclass init @ 0x1729fdc: OSMetaClass(name="IODTNVRAM", w3=184) bl 0x16175e0,
      same chain-word scheme (str x16,[x0] with movk #52641,lsl #48 decorator).

Consequence for a slot reclaimed by one of these objects: slot+0x00 = kernel VA
(pointing into __DATA_CONST view chain), slot+0x08 = 1. This is DIFFERENT from the
old UNSCORED assumption "vtable@+0x00" — there is no user vtable visible at +0 in
this build.

## 3. C1-C4 scoring — PARTIAL (session-bounded)

| type | C1 +0x10 | C2 +0x18 | C3 +0x30 | C4 +0x40 | verdict |
|---|---|---|---|---|---|
| IODTNVRAM | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | **still not SILVER** |
| IOCPU | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | still not scored |
| IOCPUInterruptController | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | still not scored |
| IOPowerConnection | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | still not scored |

What IS proven this session:

- **IODTNVRAM user surface is real and blob-shaped.** The property path at
  0x1728a40–0x1728af8 parses a 38-byte userspace record (`cmp x0,#38` @0x1728a88;
  `ldp q0,q1,[x20]` = 32-byte copy; `ldr w8,[x20,#32]`; `ldrb w9,[x20,#36]`), then
  hands name/value to a 0x1666120 helper. This is the NVRAM variable name+value
  copy-in land the old note guessed at.
- Class sizes: IODTNVRAM = 184 (mov w3,#184 @0x172a008), sibling
  IODTNVRAMPlatformNotifier = 144 (mov w3,#144 @0x172a040).
- IOCPU cluster (0x1719200–0x1719600) references its own class name at three
  sites (0x1719254/0x17192d8/0x17193d4) — metaclass + method region confirmed
  co-located.

## 4. Exact next steps to finish the scoring (one session each type)

For IODTNVRAM (priority):
1. From the metaclass block @0x1729fdc read the vtable pointer argument of the
   `OSMetaClass(name,size,vtable)` ctor at bl 0x16175e0 — the vtable lives in
   __DATA_CONST; decode x2 (meta1 -> 0x3ad7558 chain) and the x16 chain target
   0xad2588 for the vtable slot array.
2. Vtable[externalMethod] for IODTNVRAM's user client (or the driver's
   setProperty path — the 0x1666120 helper) resolves the struct ctor; the ctor's
   `str` sequence names +0x10/+0x18/+0x30/+0x40.
3. Score: user-controlled value at +0x10/+0x18 = C1/C2 user-controlled; +0x30 bit
   reachable = C3; +0x40 pointing at a writable kernel VA = C4.

Same method for IOCPU / IOCPUInterruptController / IOPowerConnection clusters
(0x1718c80+, 0x1773880+).

## 5. Verdict

T3 not closed. The four IOKit neighbours stay out of the write-channel plan until
step 4 completes. dn_flow_queue remains the only SILVER (conditional on dummynet
reachability, which is a device probe, not a static question). No fabricated
table rows were added (R3).
