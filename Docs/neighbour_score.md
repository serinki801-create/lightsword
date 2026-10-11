# neighbour_score.md — kalloc.type.192 neighbour set, C1-C4 rubric (T3)

Target: iOS 26.2 / 23C55 / iPhone14,5 / A15. Device KC: com.apple.kernel fileset entry,
Kernel UUID 0C92DE50-2BF0-35FB-B461-A869B2ACEB5E (matches both panic logs), extracted by
`bucket_map.py` (section `__kalloc_type` @ vm 0xfffffff007b15f50, 1261 x 64B
`struct kalloc_type_view` records, chained-pointer rule: target = file offset stored
as uint32 at +0x10; validated by rec706 -> "site.aio_workq_entry", kt_size = 184).

## Rubric (from section 3B)

C1  +0x10  tqe_next = attacker VALUE (the 8 bytes written)
C2  +0x18  tqe_prev = attacker TARGET (the address written; `*(tqe_prev)=tqe_next`)
C3  +0x30  AIO_COMPLETED (0x100) bit set, else the knote never arms
C4  +0x40  a writable kernel VA — filt_aioprocess does `aio_proc_lock(p)` with
           p = *(slot+0x40) BEFORE the remove (kern_aio.c 61.12:2569),
           `lck_mtx_lock(&p->p_mlock)` = lock word at p+0x58; then
           `procp->p_aio_total_count--` (61.12:478) panics on <= 0
           ("proc %p: p_aio_total_count accounting mismatch").
GOLD = C1-C4 all user-controlled. SILVER = C1-C3 + C4 natural-valid.
BRONZE = C1-C2 only -> DEAD (write lands, panic follows, reboot erases it).

## The 192-class neighbour set (18 sites, read from the binary)

aio_workq_entry is 184 on device; the zone class for struct sizes 177-192 is
kalloc.type.192 [VP]. Members, with layouts from XNU 61.12 source where open:

| type | sites | size | C1 +0x10 | C2 +0x18 | C3 +0x30 | C4 +0x40 | rank |
|---|---|---|---|---|---|---|---|
| dn_flow_queue | 4 | 184 | **id.dst_ip6[0:8]** — crafted IPv6 dst [ip_flowid.h:65-80, dst_ip6 @+0x10 of id, id @+0x08] | **id.dst_ip6[8:16]** [same] | **id.flow_id6** — ip6 flow label from crafted packet [ip_flowid.h:72] | head = `struct mbuf *` — natural kernel heap ptr [ip_dummynet.h:272] | **SILVER** |
| dn_flow_set | 4 | 184 | pipe* [ip_dummynet.h:322, kernel-written] | — | weight/qsize ints | rq* ptr | BRONZE |
| necp_client_flow_registration | 2 | 192 | rbe_left — RB tree link [necp_client.c:466, kernel-written] | rbe_right | bits inside RB colour/flags | client* ptr | BRONZE |
| nxctl_traffic_rule_inet | 2 | 192 | ntr_uuid[0:8] — USER via ioctl [nexus_traffic_rule.h:126, uuid @+0x10] | ntr_uuid[8:16] | ntr_procname bytes | ifname/link bytes — no pointer | BRONZE |
| nxprov_params | 1 | 192 | nxp_name[16:24] — USER-supplied name [os_nexus_private.h:91, name[64] @+0x00] | nxp_name[24:32] | nxp_name[48:56] — USER, bit8 settable | nxp_namelen/nxp_type u32s — NOT a pointer | BRONZE |
| IOCPU | 1 | 184 | closed IOKit, vtable@+0x00, ivars | same | same | same | UNSCORED (disasm) |
| IOCPUInterruptController | 1 | 184 | closed | | | | UNSCORED |
| IODTNVRAM | 1 | 184 | closed | | | | UNSCORED |
| IOPowerConnection | 1 | 192 | closed | | | | UNSCORED |

## Citations

dn_flow_queue (bsd/netinet/ip_dummynet.h:267, XNU 61.12):

```c
struct dn_flow_queue {
        struct dn_flow_queue *next;      // +0x00
        struct ip_flow_id id;            // +0x08 .. +0x40  (56 bytes)
        struct mbuf *head, *tail;        // +0x40 head  <== C4
        u_int len; u_int len_bytes;      // +0x50
        ...
```

struct ip_flow_id (bsd/netinet/ip_flowid.h:65):

```c
struct ip_flow_id {
        u_int32_t dst_ip;                // +0x00
        u_int32_t src_ip;                // +0x04
        u_int16_t dst_port;              // +0x08
        u_int16_t src_port;              // +0x0A
        u_int8_t  proto;                 // +0x0C
        u_int8_t  flags;                 // +0x0D
        u_int8_t  addr_type;             // +0x0E
        struct in6_addr dst_ip6;         // +0x10  <== C1 (bytes 0-7)
        struct in6_addr src_ip6;         // +0x20
        u_int32_t flow_id6;              // +0x30  <== C3 (bit 8 = flow-label bit 8)
        u_int32_t frag_id6;              // +0x34
};                                      // sizeof 0x38
```

In-slot mapping: +0x10/+0x18 = id.dst_ip6, +0x30 = flow_id6/frag_id6, +0x40 = head.
byte-exact with the computed 0xB8 = 184 struct that the KC's kt_size reports.

## The C4 problem, stated exactly

The fire sequence on a reclaimed slot (kern_aio.c 61.12:2557-2577):
`p = entryp->procp` (+0x40) -> `aio_proc_lock(p)` (lck_mtx acquire at p+0x58) ->
blind TAILQ_REMOVE (the WWW) -> `procp->p_aio_total_count--` panics if the qword
at p + p_aio_total_count_off decs to <= 0. For dn_flow_queue, p is an mbuf: the lock
word at mbuf+0x58 and the decrement qword fall inside the mbuf data area, which
holds OUR packet payload. A crafted packet that zeroes/big-positives those bytes
makes the fire survivable by construction. Both offsets are open questions:

- lck_mtx_lock on a non-group pointer: release XNU does not validate `lck_grp`;
  it CASes the lock word and on contention calls into `lck_mtx_lock_wait` with a
  bogus group ptr — HANG RISK if the lock word looks held. Craft the packet so
  the qword at +0x58 reads zero (unheld) — deterministic acquire.
- p_aio_total_count offset within `struct proc`: **[VB-DISASM — CLOSED
  2026-10-10] proc+0x47C.** Resolved from the carve: aio_proc_remove_done_locked
  @ carve 0x146c028 does `ldr w8,[x0,#1148]; sub w9,w8,#1; str w9,[x0,#1148];
  cmp w8,#0; b.le -> panic "proc %p: p_aio_total_count accounting mismatch
  @%s:%d" (kern_aio.c:479)`. Provenance + full stream: panic_symbolization.md §6.
  Also derived there: p_aio_doneq @ proc+0x5E0 (tqh_last @ +0x5E8). Craft budget:
  1500B packet carries payload past +0x480 with slack.

## Reachability — the gate that remains open

dn_flow_queue allocates only from dummynet code paths (the 4 sites in
ip_dummynet.c): a queue must be configured (IPFW/dummynet pipe+queue) for
`dn_flow_find...` to allocate one. On stock iOS the dummynet config socket
(`/dev/ipfw` equivalent) is root-only. UNRESOLVED on device. Tests, in order:
1. From the sandbox: try to create a pipe/queue via `sysctl net.inet.ip.dummynet.*`
   or the ipfw2 socket interface; log the exact EPERM/error.
2. If gated: the type still exists in the zone but the spill has no trigger.
3. Fallback trigger for a dn_flow_queue-shaped object with controlled bytes at
   +0x10/+0x18/+0x30: any 176-192B allocation with user bytes at +0x10/+0x18 —
   see UNSCORED rows (IOCPU/IODTNVRAM/IOPowerConnection, closed IOKit, need kext
   disasm; IODTNVRAM's user-visible surface is NVRAM properties — copy-in land).

## Verdict

GATE: PARTIAL — one SILVER candidate (dn_flow_queue: C1/C2 user-controlled via
crafted IPv6 flow, C3 user-controlled via ip6 flow label, C4 natural mbuf pointer
with a deterministically-crafted survival window). No GOLD. The four IOKit
neighbours are unscored pending kext disassembly, and necp/nxctl/nxprov are
BRONZE and therefore not carried forward.

Implication for the plan: T2's occupancy map is no longer optional ornament —
it is what fingerprints a dn_flow_queue reclaimer in slot (ext[1]/ext[0] reads of
+0x20/+0x28 of a reclaimed slot: if a queue's +0x28 reads our flow label bytes
rather than aio returnval/errorval, the neighbour is confirmed before any fire).
And the dummynet reachability test is a required T2 check-in, not a footnote.
