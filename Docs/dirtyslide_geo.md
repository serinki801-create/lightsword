# DirtySlide (CVE-2026-43724) — geometry verdict for iOS 26.2 / iPhone14,5 / A15

Task: T0d. Sources read this session:
- writeup: https://gracecondition.github.io/posts/dirtyslide/ (published 2026-06-25)
- PoC: github.com/gracecondition/DirtySlide
- iOS port: github.com/khanhduytran0/DirtySlide (fork, README + build notes only)
- NVD/CVETodo advisory text (fixed iOS 26.5.2 / 18.7.10, macOS Tahoe 26.5.2)

## Q1. Write primitive shape

8-byte read-modify-write per hop, at `rebaseLocation`, value transform
(vulnerable v5 loop, writeup quotes `xnu-12377.120.72` verbatim):

```c
value = (value & 0x3FFFFFFFFULL) + value_add + slide_amount;
if (isAuthenticated) { /* PAC re-sign */ memcpy(rebaseLocation, &value, sizeof(value)); }
else { value += high8; memcpy(rebaseLocation, &value, sizeof(value)); }
```

- `value_add` is a `uint64_t` read from the attacker-supplied `slide_info`
  struct (copied in via `copyin()` from syscall 536). Fully controlled.
- Written value = `(orig_low34 + value_add + slide) + (orig_bits34..41 << 56)`.
- It is an ADD-RMW, not a value-set. Bits 34-55 of the target survive from the
  original content; high 8 bits are original bits 34-41.
- Implication for a data-only target: we can add a chosen 64-bit addend to the
  low 34 bits of an adjacent object. To forge a heap pointer we must already
  know the original value (no free info leak in this primitive itself).

## Q2. Boundedness — UNBOUNDED (forward-only), with page-relative first hop

The guard that is missing (writeup, comparing against `vm_dyld_pager.c`):

```c
// vm_shared_region_slide_page_v5(), vulnerable xnu-12377.120.72:
uint8_t* rebaseLocation = page_content;
uint64_t delta = page_entry;   // page_starts[pageIndex], raw uint16 from userspace
do {
    rebaseLocation += delta;
    ... // NO check that rebaseLocation is inside [page_content, page_content+0x4000)
} while (delta != 0);

// vm_dyld_pager.c: fixupPage64() DOES check, verbatim:
if ((uintptr_t)chain < contents || (uintptr_t)chain + sizeof(*chain) > end_contents) { ... }
```

- First hop: `page_starts[i]` is a raw `uint16_t` copied from userspace, added
  directly — up to 0xFFFF past page start; page is 16 KB (`page_size: 16384`
  in `struct vm_shared_region_slide_info_entry_v5`). No alignment check, no
  range check in the vulnerable build.
- Subsequent hops: `delta = (value & 0x7FF0000000000000ULL) >> 52) * 8`, i.e.
  0..0x3FF8, decoded from bytes wherever the pointer currently sits.
- Hop count: unbounded in the vulnerable loop (no running offset accumulator).
- Direction: strictly forward (deltas unsigned).
- 26.5.2 fix (Hex-Rays from the fixed kernelcache) adds both a per-step bound and
  a table check — quoted in the writeup:
  `if ( page_offset > 0x3FF8 ) return 5;` and
  `if ( start >= 0x3FF9 ) { printf("vm_shared_region_slide_sanity_check_v5: ..."); }`

Verdict: **UNBOUNDED-forward, adjacent-frame-targeted.** The distance is not
the limiting factor; what the neighbour frame IS, is.

## Q3. Bytes and stride

- 8 bytes per hop (`sizeof(uint64_t)` reads and writes).
- Stride = `((value >> 52) & 0x7FF) * 8`, attacker-influenced via page bytes;
  first stride is the raw u16 `page_starts[i]`.

## Q4. Does the privilege step touch page tables?

Yes — and that is the whole power step. Writeup:

> On arm64 the target is a page-table page. If I groom the kernel so a leaf
> page-table page lands physically adjacent to the slide destination, the OOB
> write lands on a page-table entry instead of on data. A PTE I control maps a
> virtual page I own onto a physical frame I choose.

> Exploit is VM only, due to SPTM/TXM locking page tables on physical Apple
> Silicon.

On iPhone14,5 (A15, SPTM) the PTE-forge step is dead: page tables are owned by
SPTM, not by pmap userspace-visible grooming. The writeup's own iOS section
agrees: "It also needs an SPTM bypass, and there is little public information
on bypassing SPTM."

## Q5. Any non-page-table step that still achieves a kernel data write?

Not demonstrated anywhere public. The demonstrated chain is
OOB → forge PTE → physical R/W → scan for `posix_cred` (uid==501) → zero
uid/gid in place. Every step after the OOB is either page-table work or
physical-memory work that rides on the forged PTE.

The iOS port (khanhduytran0/DirtySlide) reaches the bug on iOS via
`DYLD_SHARED_CACHE_DIR` + shim dylibs + `_POSIX_SPAWN_RESLIDE` +
`xcrun devicectl ... --no-activate -e '{"_SafeMode":"1",...}'` — and its
documented result is "Kernel panicked". No primitive on iOS hardware, only a
crash. The physical-scan half of the exploit is not ported at all.

For a data-only path, the OOB would need a *kernel heap data* page physically
adjacent to the slide destination page. dyld shared cache pages are mapped in
their own VM region early in boot; their physical neighbours are other cache
pages, not kalloc heap. No public grooming of that adjacency exists.

## VERDICT

**BOUNDED-with-adjacent-object-hit geometry, but the power step is
page-table-only and dead on A15/SPTM.** On this target CVE-2026-43724 is a
panic/DoS plus a theoretical heap-adjacent ADD-RMW with no demonstrated heap
grooming. It does NOT get promoted to primary write channel.

Consequences for the plan:
- W-B (DirtySlide write channel): parked. Conditions to re-open, in order:
  (a) a demonstrated way to make a kalloc-heap data page the physical neighbour
      of the slid cache page, or
  (b) an SPTM PTE-forge primitive, or
  (c) B12 delivers a reliable kernel read that tells us what sits adjacent.
- Keep the bug on the board for T6-adjacent work: the Apple-side crash is free
  and the missing info-leak is exactly what B12's read channel can supply.
- W-A (B12 double-free free-list corruption) remains the primary write path.
  W-C (cross-type TAILQ unlink) remains fallback.
