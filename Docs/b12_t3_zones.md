# B12 T3 — kalloc_type zone map (device KC, xnu-12377.62.10 / 23C55)

Source: kc.bin decompressed with ipsw (bvx2) -> 64,536,576 B Mach-O;
__kalloc_type views parsed from __DATA_CONST (record stride 0x20:
name_rel @+0x00, signature_rel @+0x10, kt_size @+0x1C; string VAs are
base-relative where base = 0xFFFFFFF007004000).

## aio_workq_entry
- kt_size = 184 (ON-DEVICE confirmed), signature = `11112221122222222222111`
  (23 qwords, 1=pointer 2=data — matches the struct field classes).
- 21 views share the zone (same signature string => one zone):
  - `site.struct dn_flow_queue`
  - `site.struct dn_flow_set`
  - `site.IOCPU`
  - `site.IOCPUInterruptController`
  - `site.IODTNVRAM`
  - `site.IOPearlCameraFrame`
  - `site.AppleS5L8960XNCO`
  - `site.AppleSEPARTService`
  - `site.AppleUSBCardReaderBlockStorageServices`
  - `site.AppleTypeCPhyDisplayPortInterface`
  - `site.IOKernelDebugger`
  - `site.IOPCIHostBridge`
  - `site.IOPCIDevice`
  - `site.RTBuddyEntropyEndpoint`

## VERDICT (closes the SILVER / dn_flow_queue line)
- `struct dn_flow_queue`: +0x00 next, +0x08..0x14 ip_flow_id (dst/src/proto),
  +0x18 mbuf *head. Blind TAILQ on it => tqe_next = proto byte, tqe_prev = mbuf ptr
  => write B lands an mbuf pointer, never a chosen address. Also needs ipfw
  config (privileged) to allocate at all.
- `struct dn_flow_set`: +0x10 = dn_pipe *pipe (kernel). Same dead end.
- All remaining mates are IOKit/driver objects: allocated by driver activity,
  not sprayable from the app sandbox, and none has user data at +0x10/+0x18.
- Therefore: the only sandbox-reachable zone-mate is aio_workq_entry itself,
  whose +0x10/+0x18 are kernel list pointers. The blind remove gives list
  surgery, NOT what/where control. The aio write channel has no value control.

## Write frame — direct disasm in the 62.10 image
`aio_proc_remove_done_locked` @ 0xFFFFFFF008478060 (__TEXT_EXEC):
```
  ffffffff00847806c  ldr  x9, [x1, #24]      ; elm->aio_proc_link.tqe_prev (+0x18)
  ffffffff008478070  ldr  x10, [x9]          ; *tqe_prev
  ffffffff008478074  cmp  x10, x1            ; consistency check (the panics)
  ffffffff008478078  b.ne <brk #0xbffd site> ; 'AIO on a proc list that does not belong...'
  ffffffff008478084  ldr  x8, [x8]           ; tqe_next (+0x10)
  ffffffff008478088  ldr  x9, [x10]
  ffffffff00847808c  str  x8, [x9]           ; *** WRITE B: *(tqe_prev)=tqe_next ***
  ffffffff008478090  str  xzr, [x10]         ; TRASHIT
  ffffffff00847809c  mov  w9, #0xffffffff    ; atomic add -1
  ffffffff0084780a0  ldadd w9, w8, [x8]
  ffffffff0084780ac  ldr  w8, [x0, #1148]   ; procp+0x47C p_aio_total_count [CONFIRMED]
```
- doneq.tqh_last write target at procp+0x5E8 => p_aio_doneq.tqh_first @ procp+0x5E0 [CONFIRMED].
- Panic class in-image: `brk #0xbffd` (instruction abort, EC=0x25, far=0 in the logs).
