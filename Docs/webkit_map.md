# WebKit map — CVE-2026-43709 / CVE-2026-43701 (W-T1)

Target: iOS 26.2 / build 23C55 / iPhone14,5. Both CVEs were fixed in the
Safari/iOS **26.5.2** wave (advisory 2026-06-29; WSA-2026-0004 dated 2026-07-10;
upstream fixes 2026-07-01 / 2026-07-06). iOS 26.2 predates that wave by ~7
months → both bugs are inside the version window (see §3).

## 1. Source inventory (public)

| CVE | WebKit Bugzilla | rdar | Upstream fix commit | Fix date | Credit |
|---|---|---|---|---|---|
| CVE-2026-43709 | 314398 | 176201738 | `9d2cc8c989` | 2026-07-06 | (none listed in APPLE-SA-06-29-2026-3) |
| CVE-2026-43701 | 315004 | 177019828 | `f23ffb5a84` | 2026-07-01 | Aaron Grattafiori — NVIDIA AI Red Team |

Sources pulled: APPLE-SA-06-29-2026-3 (fulldisclosure archive, PGP-signed),
WSA-2026-0004 (webkitgtk.org), upstream commits via GitHub API
(github.com/WebKit/WebKit/commit/{9d2cc8c989,f23ffb5a84}). Bugzilla bugs
314398/315004 are access-restricted; commits are the public surface.

## 2. CVE-2026-43709 — ANGLE Metal occlusion-query UAF (bug 314398)

- **Class:** use-after-free — dangling raw GL-object pointer on an
  allocation-failure path.
- **Component:** `Source/ThirdParty/ANGLE/src/libANGLE/renderer/metal/` —
  ANGLE Metal backend, GPU process. NOT JSC, NOT the WebContent renderer.
- **Mechanism** (commit message, verbatim):

      ContextMtl would populate QueryMtl *ContextMtl::mOcclusionQuery before
      visibility buffer allocation:
        mOcclusionQuery = query;
        ANGLE_TRY(startOcclusionQueryInRenderPass(...));
      If the allocation failed, frontend would not keep the Query instance
      alive.

- **Fix shape:** the `QueryMtl *mOcclusionQuery` member of `ContextMtl` is
  deleted outright; occlusion-query state moves into `OcclusionQueryPool`,
  callbacks take `QueryMtl &` instead of raw pointers. Key hunks:

      ContextMtl.h: - QueryMtl *mOcclusionQuery = nullptr;   (member deleted)
      ContextMtl.h: - startOcclusionQueryInRenderPass(QueryMtl *query, bool clearOldValue);
      mtl_command_buffer.mm: - if (mOcclusionQueryPool.getNumRenderPassAllocatedQueries())
                             + if (mOcclusionQueryPool.hasPendingVisibilityResults())

  Files: ContextMtl.h/.mm, QueryMtl.h/.mm, mtl_command_buffer.mm,
  mtl_occlusion_query_pool.h/.mm, mtl_render_utils.h/.mm (+ gl_tests).
- **Trigger surface:** WebGL occlusion query
  (`glBeginQuery(GL_ANY_SAMPLES_PASSED/GL_ANY_SAMPLES_PASSED_CONSERVATIVE, …)`)
  while the visibility-buffer allocation fails — i.e. an OOM/memory-pressure
  path. Determinism is weak; Apple impact text says "unexpected process crash".
- **Verdict:** crash-class GPU-process UAF. No stable allocation/reuse control
  documented publicly → NOT an RCE-grade primitive. Off the critical path;
  carry as GPU DoS only.

## 3. CVE-2026-43701 — data: URL download-policy sandbox escape (bug 315004)

- **Class:** sandbox escape — compromised WebContent (CWC) drives the UIProcess
  to write attacker-chosen bytes to disk with no user interaction.
- **Component:** UIProcess navigation policy
  (`WebPageProxy::receivedNavigationResponsePolicyDecision`) + WebCore
  `DocumentLoader::continueAfterContentPolicy`. Not JSC.
- **Mechanism** (commit message, verbatim):

      The renderer opens a popup navigation to a data:application/octet-stream;
      base64,<payload> URL; because the MIME type is not showable, the
      navigation delegate's stock policy returns
      WKNavigationResponsePolicyDownload.
      WebPageProxy::receivedNavigationResponsePolicyDecision unconditionally
      mints a real DownloadProxy for the data: URL ... and the data: URL bytes
      land on disk. The renderer-supplied user-gesture token is forged to
      bypass the popup blocker.

- **Fix hunks (exact, 3 files, +24/-0):**

  1. `Source/WebKit/UIProcess/WebPageProxy.cpp` (+13) — primary fix:

      +    if (action == PolicyAction::Download && request.url().protocolIsData()
      +        && (!navigation || !navigation->isFromAPIClientRequest())) {
      +        WEBPAGEPROXY_RELEASE_LOG(Loading, "... refusing to download data: URL ...");
      +        action = PolicyAction::Ignore;
      +    }

  2. `Source/WebKit/UIProcess/API/APINavigation.h` (+1):

      +    bool isFromAPIClientRequest() const { return m_requestIsFromClientInput; }

     — `m_requestIsFromClientInput` is set only by UIProcess paths
     (`-loadRequest:`), NOT by the renderer-supplied
     `isRequestFromClientOrUserInput` flag. That distinction is the fix.
  3. `Source/WebCore/loader/DocumentLoader.cpp` (+10) — defense-in-depth:

      +        if (disallowDataRequest()) {
      +            protect(frameLoader())->policyChecker().cannotShowMIMEType(m_response);
      +            stopLoadingForPolicyChange();
      +            return;
      +        }

- **Exploit surface:** requires a prior renderer RCE (this is the escape that
  *follows* it). On the stock `WKNavigationDelegate` path
  (`decidePolicyFor navigationResponse`) returning
  `.download` is the default for unshowable MIME types, so the same flow runs
  inside an embedded WKWebView. Result: arbitrary attacker-chosen bytes written
  to a fixed path (Downloads/Unknown) in the UI process — no gesture, no
  `download` attribute, no Content-Disposition.
- **Verdict:** real UIProcess-side arbitrary-bytes-to-fixed-path write. Fixed
  destination limits direct abuse (no path control), but it is a genuine
  post-RCE pivot: plant bytes another component later reads (e.g. a file the
  app itself loads). Secondary pivot, not the exec primitive.

## 4. Presence in the 23C55 build

- Both upstream fixes (2026-07-01, 2026-07-06) shipped in the 26.5.2 wave:
  Safari 26.5.2 / iOS 26.5.2 / iPadOS 26.5.2 / macOS Tahoe 26.5.2 /
  WebKitGTK 2.52.5 (WSA-2026-0004). Our device runs iOS 26.2 (23C55) —
  **inside the vulnerable window**.
- **[UNVERIFIED]** on-device items — exact commands to close:
  1. In the in-app WKWebView run JS `navigator.userAgent` → the AppleWebKit
     build token must predate the 26.5.2 WebKit line.
  2. JS `document.createElement('canvas').getContext('webgl2')` +
     `gl.getExtension('WEBGL_debug_renderer_info').UNMASKED_RENDERER_WEBGL`
     → expect `ANGLE (Metal)` to confirm the ANGLE Metal backend (the 43709
     surface) is active.
  3. Trigger check for 43701: load a local page that fetches
     `data:application/octet-stream;base64,…` in a popup-shaped navigation
     with unshowable MIME → pre-patch the file lands in
     `NSDownloadsDirectory`/Unknown of the app container (post-patch it is
     refused).

## 5. Chain read for Stage W

- Neither bug is a JSC renderer-RCE primitive: 43709 is a GPU-process crash;
  43701 is a post-RCE escape. If Stage W needs renderer code execution, the
  scope must widen to JSC/WebCore memory-corruption bugs unfixed at 23C55 —
  that is W-T1b (next inventory task), NOT derivable from this pair.
- Stage W bootstrap order that still holds: local page → renderer RCE
  (W-T1b bug) → 43701 pivot (UIProcess file write) → native exec in host →
  B12 kernel path. Do not spend critical-path time on 43709.

## 6. W-T1b — JSC primitive for 23C55: FOUND, kill gate NOT tripped (2026-10-10)

Public, complete, version-matched PoC: **`github.com/retX0/safari-26.2-dfg-type-confusion`**
(pushed 2026-03-26). This is a renderer-side RCE primitive for EXACTLY our build.

### The bug [VB from PoC + upstream fix commit 3f6f7836068]

`Source/JavaScriptCore/dfg/DFGNodeType.h` (line 592 in the affected tree):

    macro(MapIterationEntryKey,   NodeResultInt32)   // BUG
    macro(MapIterationEntryValue, NodeResultJS)      // correct

`MapIterationEntryKey` — the node extracting the key inside a `Map.forEach()`
callback — is declared as producing a 32-bit int. Its runtime op returns an
arbitrary NaN-boxed `JSValue` which MAY hold a heap pointer.

Fix commit `3f6f7836068` (commits.webkit.org/308853@main, authored
2026-03-07), the exact hunk:

    -    macro(MapIterationEntryKey, NodeResultInt32) \
    +    macro(MapIterationEntryKey, NodeResultJS) \

plus regression test `JSTests/stress/map-forEach.js` (store-key-into-tenured +
Eden scan + spray; asserts `object.key[0] === 2.2` never holds).

### Chain, verbatim from the PoC README

    StoreBarrierInsertionPhase::Fast: child->result() == NodeResultInt32
      -> FencedStoreBarrier skipped for the key stored into a tenured object
      -> Eden GC frees the key object, dangling pointer remains in the holder
    Spray JSArray: cells -> IsoSubspace (no reuse); butterflies -> Gigacage
      (reused) -> DoubleShape cell reads NaN-boxed pointer as raw float64
      (addrof); JSArray reads written raw bits as JSValue (fakeobj)
    Phase 3: WebAssembly Portable globals (i64 g0 / i32 g1), two instances
      (Navigator/Executor), redirect Navigator.g0 value slot -> Executor.g1
      -> read32/write32/read64/write64
    iPhone adaptations: cell sled (64x {0:0.0} after storeKey),
      deepClobber(300), await sleep(50), 3000-5000 iteration DFG warmup.
    End-to-end success ~80% (tested iPhone iOS 26.1, macOS 26.2).

### Version window for 23C55

- PoC affected table: "Safari <= 26.2 (WebKit 21623.1.14.11.9)" — our OS build.
- Fix landed 2026-03-07, i.e. AFTER the 26.2 wave (Dec 2025) -> present on 23C55.
  This is a fix-date argument; [UNVERIFIED] device-side check remains the same
  two commands as W-T1 §4 (userAgent + the PoC's own AAR/AAW demo inside WKWebView).

### Verdict

- Stage W now has its renderer primitive: local page (exploit.html/js) loads
  `wasm_rw.js` logic in WKWebView -> AAR/AAW in the WebContent process.
- Combined with CVE-2026-43701 the pivot to the UIProcess (arbitrary bytes to a
  fixed path) is public. dyld CVE-2026-20700 (patched 26.3, so PRESENT on 26.2)
  remains the standby PAC/TPRO lever if native exec needs it — NOT on the
  critical path.
- Track status: ALIVE, bounded. Per R13 it consumes no critical-path time:
  native B12 work (T2 frame probe on device, T3 field RE) outranks it.

## 7. W-T0 device verdict [VP-DEVICE] — 2026-10-10 18:27, build 181624/183906

- Fingerprint (chassis unitFingerprint, native-bridged to trace.log):
  `ua=Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15
  (KHTML, like Gecko) Mobile/15E148`, `gl=Apple GPU/Apple Inc.`,
  `glsl=WebGL GLSL ES 3.00`, `hasResizableArrayBuffer=true`,
  `hasAtomicsWaitAsync=true`, `hasBigIntMap=true`. The UA OS token (18_7) is a
  guest anomaly on a 26.2 device and the AppleWebKit token is frozen Safari
  legacy — UA is NOT a version signal; GL confirms ANGLE/Metal active.
- **W-T0=PRESENT [VP-DEVICE]** via the strengthened detector (600-round groom,
  5000-iteration DFG warmup, cell sled, deepClobber x2): the marker check
  `object.key[0] != 100.1+r` fired at round 10 — the MapIterationEntryKey
  type confusion is live on 23C55. Apple's own 100-round regression test alone
  had returned ABSENT (weak detector, not a negative — keep the strong groom).
- R20 VERDICT **[REACHABLE]** by option matrix on device: control option 250 ->
  ENOPROTOOPT(42) generic rejection (matches 61.12 ip_ctloutput); IP_FW3(21) ->
  EINVAL(22) at both len32 and len4, and getsockopt(IP_FW3) returns r=0 — the
  option is distinguished and validated by a handler. dn_flow_queue stays SILVER.
  Note: our hand-built dn_sess cookie still fails struct validation (EINVAL);
  the exact 62.10 dn_sess/flow_mask layout is the next static item if the T2
  fingerprint needs a real pipe to exist.

---

## 8. W-T3 — native pivot (built 2026-10-12, device fire pending)

Code: `Resources/webkit/exploit.js` (`nkNativePivot`), button **NATIVE PIVOT (W-T3)**
in `exploit.html`, `GETPATH` bridge in `Sources/App/UIBridge.swift`. Host-side
toolchain: theos/iphone clang, ad-hoc signed, `Packages/srk801_20261012-191228.ipa`.

### 8.1 The site problem and the movz fingerprint

Patching JIT code needs a deterministic address *inside* the compiled body.
Per-build offsets are dead (62.10-JSC layout unpublished), so the pivot module
is a wasm `(i64 x 192) -> i64` whose body is a straight-line xor chain with a
64-bit constant spliced in:

    local.get 0; i64.const 0xB1C2D3E4F5A607B8; i64.xor; local.get 1; i64.xor; ...

All four 16-bit halves of the constant are non-zero, so the arm64 backend MUST
emit a movz/movk sequence for it. The low-half movz (`movz xD, #0x07B8, lsl #0`)
is a byte-exact fingerprint: `(w & 0x7f800000) == 0x52800000 &&
((w >>> 5) & 0xffff) == 0x07B8`. The hunt scans the code mapping qword-wise for
it; first match = the patch site. No fixed offsets anywhere.

Verified on-device-independent: the module builder (LEB/SLEB, type/func/export/
code sections) validates in a standards runtime, `chain(0,…,0) == MAGIC`,
`chain(arg3=0xFF) == MAGIC ^ 0xFF`; the arm64 hand-encoder was checked against
`llvm-mc`/`objdump` (movz/movk/stp/ldp/adr/svc/mov encodings plus the assembled
shellcode itself).

### 8.2 The hunt (R1) — every dereference is a followed pointer

1. JS wrapper dump: `addrof(executorRef)` body, 0x000–0x180, qwords classified
   JS-cage / malloc-zone / external. **Device-calibrated (run 2026-10-12):**
   the Gigacage (butterflies ~0x1_6x_xxxxxx) and the C++ malloc heap (WasmGlobal
   ~0x1_0a/0x1_0b_xxxxxx, Instance/module pointers up to +0x420000 above wgp)
   sit in the SAME 4 GB-aligned block — block arithmetic cannot separate them.
   The rule that works: 16 MB window around the two *verified* `WasmGlobal`
   pointers (the trigger reads them at wrapper+16), checked FIRST, then the
   4 GB block containing the wrapper = cage. The first device run shipped the
   naive flat-window classifier and collected `ext=0, cpp=0` — no external
   candidates at all; the order-and-window fix is in the built code.
2. One indirection into the malloc-zone pointers: the C++ `Wasm::Instance` body
   (0x000–0x120) yields the pointers out to other mappings. Page-aligned values
   are candidates even when cage-classified — the device INSTDUMP shows
   mapping bases at wrapper+16 (0x…000) and +72/+80 (0x…000), and skipping page
   bases is exactly what would hide the wasm code mapping.
3. Fingerprint scan per external candidate: one bounded 0x1000 window, or 4
   pages when the candidate is page-aligned (walk stops when a page reads
   empty — the unmapped-tail guard).

The whole walk is ~200 guarded reads; failure logs the candidate set so the
next round can widen windows, not guess offsets.

### 8.3 Write-test and hook shape (R2/R3)

- R2: at the site, flip the low byte (`0x??5A`), read back, restore, read back.
  Both must match or the pivot aborts *before* any instruction patch.
- R3: inline hook, `PIVOT_PATCH_LEN = 256` B (8 cache lines; margin against the
  ~800 B chain body), hand-assembled arm64:
  1. `[scratch] = marker` — scratch is a live `Uint8Array`'s own backing,
     proven by JS-write → native-read-back before use.
  2. native proof: `open(path, O_WRONLY|O_CREAT|O_APPEND, 0644)` +
     `write("SHELLCODE\n")` + `close`, path delivered by the C `GETPATH`
     bridge (`nk_home_path("trace.log")` — the renderer cannot know the
     container UUID). Renderer writes the guest container path directly
     (WebContent shares the app sandbox).
  3. trampoline: `br` to `site + 256` — past everything the hook replaced.
- Hook is one-way: no self-restore is possible while executing inside the
  overwritten range (a restore front would chase the PC), and it is not needed
  — every re-call of the export re-runs the shellcode (marker + one trace.log
  line per call). The export's return value is garbage after the hook, by
  design; nothing downstream reads it.

### 8.4 Gates and known risks

- PASS gate: `SHELLCODE` line in `Documents/trace.log` written by native
  syscalls; secondary: the marker qword visible via `read64(scratch)`.
- Risk 1 — icache coherence: the patch is written through the wasm data
  transport. If the JIT pages are not store-coherent to the icache, the first
  call still executes the original bytes (clean retry signal). Driver retries
  3 calls and logs the marker per attempt; a three-call no-marker run with a
  passing write-test means "pages writable, ic stale" — the fix is then an
  explicit `ic ivau` before transfer, not a layout change.
- Risk 2 — unmapped page in the walk: bounded to 4 pages from a page-aligned
  candidate, 1 window otherwise; worst case is a renderer FATAL, which the
  `W-T0` machinery already observes (and the run restarts).
- Risk 3 — the fingerprint site lands too deep in the body for the 256 B
  window: retried with `PIVOT_PATCH_LEN` raised (256 has ~540 B of margin
  against the chain body).

### 8.5 Device-fire calibration pass 2 (2026-10-12, runs 20:05–20:07)

Three more clean runs: W-T0 PRESENT (rounds 9/21/32), W-T2 ECHO OK, magic ok —
and with the magic module primed unconditionally this time. The pivot was
pressed pre-arming both times (expected: `primitives-not-armed`).

Replaying the three device INSTDUMPs through the hunt (offline, same code path)
found a **guaranteed renderer death** before it shipped: wrapper+88 carries
`0x400000000` — identical in every run, i.e. a layout constant (a reservation
size), not an address. A 4-page walk from it reads PROT_NONE space. Fixes now
in the built code:

- `const4g()`: values that are exactly 4 GB-aligned are constants, never
  candidates.
- Candidate split: **extPage** (page-aligned mapping bases — scanned first,
  4-page walk) vs **extSoft** (interior pointers, bounded to the REMAINDER OF
  THEIR OWN PAGE: a live pointer guarantees that page is mapped, the next one
  may be PROT_NONE, e.g. the Gigacage reservation tail).
- Dedup: wrapper+72 and +80 carry the same page base (run data:
  0x16b7f0000 / 0x16b400000 / 0x16d72c000 — consistent +94–180 MB above the
  malloc heap, the code-region suspect); it is scanned once now.

Replay result, identical shape on all three runs:
`extPage=[+0x10 page, +0x48 page]  extSoft=[+0x00 interior]  cpp=8`.
The +0x48 value (page-aligned, appears twice) is the primary fingerprint
target; the +0x10 value (~+4 MB above wgp, malloc-zone page) is secondary; the
+0x00 interior pointer (0x5500_xxxx_xxxx, stable low bits across runs — a
wasm-cage style region) gets a bounded tail scan. If the fingerprint misses
all of them, the hunt logs every candidate and exits cleanly — next round
widens the extPage walk (4 → 8 pages) instead of guessing.

### 8.6 Device-fire with the auto-chain (2026-10-12 21:44, runs 1–2) — hunt v2 shipped

The pivot now fires ON arming (trigger=armed auto-chain, Resources/webkit/exploit.js —
`nkAutoPivot`, latched per arming, `window.__wt3Auto=false` disables). Both device
runs behaved identically and cleanly: W-T0 PRESENT (rounds 18/12), W-T2 ECHO OK
(matchIdx 1237/1219, jsSees=true, v128off=0x168), auto-pivot begin armed=yes magic=ok —
then the v1 hunt failed with a structural defect, now fixed:

- **extPage set had no code mapping in it.** Candidates were wrapper+16
  (0x10f423000, malloc-zone page), wrapper+72/+80 (0x16db64000 — the GIGACAGE:
  0x1_6db6_4000 sits inside the same 4 GB block as the cage; butterflies, not
  code), and +0x1100bb000 from the instance indirection: all readable, 4-page
  walk each, no movz. No dumped object carried a pointer into the compiled body.
- **The single extSoft candidate killed the renderer.** instance+0 =
  0x0000550010f8e328 (run 2: 0x000055001108e4b8) is the JSCell HEADER
  (compressed map + flags), not a pointer. Its page-tail read lands 94 TB away
  in PROT_NONE → SIGSEGV → WebContent death → new run. That is the "run restarts"
  of §8.4 risk 2, observed twice.

Hunt v2 (in exploit.js, replaces the v1 classifier): (1) dump offsets <0x10 are
header qwords, never candidates; (2) interior candidates must be within 4 GB of
the verified set (wrapper + both WasmGlobals + page-verified bases) — the 94 TB
header value is now unreachable by construction; (3) the dump set grew to every
object that carries a pointer INTO the compiled code — navigator wrapper,
v128/executor/navigator/magic instance wrappers, the exported `chain` FUNCTION
wrapper, the magic MODULE wrapper (module+fn refs now kept), and the two
WasmGlobal C++ bodies; (4) the page-aligned walk is 8 pages, stop at an empty
page. Every read still lands in a page already proven mapped.

### 8.7 Device-fire pass 2 (2026-10-12 21:57, runs 1–2) — hunt v3 shipped

v2 ran clean both times (no SIGSEGV, self-test PASS 17/0, pivot `fired-fail`
latched and reported) — the log isolates exactly why code was not reached:

- Every candidate the v2 hunt could touch lives on the **data side** of the 4 GB
  cage block: the malloc pages (wrapper+16 = 0x10b423000/0x112423000, +18 MB
  past wgp = 0x10b2a3000/0x112284000, one malloc page from the indirection =
  0x10f295000) and the Gigacage base (wrapper+72/+80 = 0x16f0cc000/0x16b1cc000).
  8-page walks each: readable, no movz.
- Cut 1 — `cpp[]` **saturated at 8 from the navigator wrapper alone**, so the C++
  pointers carried by the magic instance / exported `chain` function / MODULE
  wrappers were never dereferenced: the only path to `Wasm::Module → Wasm::Code`
  was cut before it started.
- Cut 2 — one indirection level cannot reach the code region anyway:
  module body → `Code*` → `jumpTable` is **two** hops, and the jump table is an
  **interior code pointer** that v2's 4 GB rule would have discarded.

Hunt v3 (multi-level BFS): L0 cage dumps feed a 32-slot zone-pointer list
(dumps ordered module → fn → magic instance first); L1 dereferences up to 32
C++-zone bodies; L2 dereferences up to 16 pointers found inside L1 bodies.
Interior pointers discovered **inside C++ bodies** bypass the 4 GB span rule
(a plausible 8-aligned qword inside a real C++ object is almost always a
pointer; a far value at the cage-dump level is a JSValue/header artifact) and
only their own page is touched. The fingerprint now accepts both the `movz`
immediate **and** the raw 64-bit constant (guards against an LLVM literal-pool
materialization); a literal hit logs the mapping landmark and the preceding
0x800 bytes are searched for the `movz`, so the hook site is always an executed
instruction. Interior candidates are scanned over their full page.

### 8.8 Device-fire pass 3 (2026-10-12 22:05, runs 1–2) — hunt v4 shipped

v3's BFS worked structurally: both runs show `cpp1=32 cpp2=16`, all 32 L1
bodies and all 16 L2 bodies read (`Wasm::Module`/`Code` depth reached), the
fingerprint scan started — and both runs still died the same way:

- The `fromCpp` span relaxation admitted **garbage**: the final candidate list
  carried `0x3000010000`, `0x400080000000`, `0x8000010000` (page-shaped ints)
  and `0x6f00000070`, `0x7f00000080` (packed u32 pairs). Run 2's log ends at
  the walk over `0x3000010000` (PROT_NONE → renderer death); run 1 died at the
  first page walk after L2. Real candidates were ALL inside the 4 GB cage block
  (malloc pages `0x112423000`/`0x112283000`/`0x10f28d000`, the Gigacage base,
  the fn-wrapper's own cage pages `0x112938000`/`0x112934000`).
  Calibration conclusion: every value the hunt touched lives on the data side;
  no code-region pointer surfaced, and the far-interior rule is too dangerous
  to keep scanning blind.

Hunt v4 doctrine — **the BFS can no longer kill; only the code scan can**
(and each death is a reload that re-runs the hunt):
- **DEREF GATE**: a value is dereferenced only inside the proven-mapped C++
  zone (±64 MB around the two verified WasmGlobals). The BFS itself is
  SIGSEGV-impossible; L1/L2 bodies widened from 0x120 to 0x200 (the
  entrypoint/jump-table fields sit past the old bound).
- **FREQUENCY FILTER**: every surviving value from every body is counted.
  Real pointers to shared structures (Code region, jump table) appear in
  multiple bodies; garbage ints appear once. Hot (≥2) far candidates are
  scanned; **cold far candidates are never scanned** — printed as `far=` data.
- Garbage shapes dropped cold: packed u32 pairs (low-32 < 0x10000) and the
  4 GB-aligned layout constants; dump offsets <0x10 stay header-neutral.

### 8.9 Device-fire pass 4 (2026-10-12 22:14, runs 1–2) — hunt v5 shipped

v4's ±64 MB deref gate was the regression: the run log shows run 1 completing
14 L2 dumps and dying **at the 15th L2 dereference** — the 64 MB span contains
unmapped holes, and garbage ints from C++ bodies (any 8-aligned value) land in
it easily. Run 2 died in the same phase. The code scan never began in either
run (soft list grew to 18, unscanned). cpp2 also lacked deduplication —
`0x10e14f720` / `0x106bd8` / `0x106be8` were each dumped twice, burning cap
slots.

Hunt v5 reverts the deref gate to the **proven 16 MB wt3Region "cpp" window**
(v3's structure completed every L1/L2 dump in both 21:57 runs; v3's death was
later, at the page walk — which v4's frequency filter already fixed), adds cpp
deduplication, and keeps v4's doctrine for everything outside the window:
hot-far scanned, cold-far printed as `far=` data, movz-OR-literal fingerprint,
0x200 bodies, garbage-shape filters. The BFS is again SIGSEGV-impossible and
the next run reaches the code-scan phase for the first time since v3.

### 8.10 Device-fire pass 5 (2026-10-12 22:19, runs 1–2) — hunt v6 shipped

The 16 MB gate held exactly as v3's did: both runs completed all 32 L1 dumps
(cpp2=32, page=8, soft list saturated at 24) — and then run 1 died at **L2
dump #31, still inside the BFS**: the 16 MB window has unmapped holes, and
cold garbage from L1 bodies lands in them. Run 2 died in the same phase. The
fingerprint scan has now failed to run in **every pass since v3** — the BFS
kept eating the run before the payload stage began.

Hunt v6 makes the scan independent of the BFS: **A** L0 cage dumps → **B** L1
(the proven-safe 32) → **C** SCAN FIRST PASS (page candidates hot-first with
the 8-page walk, then softs over their own page) → **D** L2 best-effort with
**hot-only** zone pointers (freq ≥2, cross-deduped against cpp1, cap 8 — a
value seen in two different bodies is a real reference; cold = hole risk) →
**E** SCAN SECOND PASS. The scan now runs on every armed pivot before any L2
risk exists.

### 8.11 Device-fire pass 6 (2026-10-13 14:42, runs 1–2) — hunt v7 shipped

v6's reorder worked — the BFS finished — but the scan's output still never
appeared: both runs died ~125 ms after `wt3 L1 done` (the runtime of a full
scan pass, ~20 K reads), and `nkNativePivot` has no try/catch around the hunt
(a JS exception would have printed `ATTEMPT=1/4 THREW`), so the scan hit an
unmapped page. Root cause of the silence: **unitRwxHunt is one synchronous
block — the bridge's outgoing queue cannot drain while the JS thread is
blocked, and the renderer death discards the whole queue.** `L1 done` had
time to drain before the sync scan block started; the candidates/miss lines
did not.

Hunt v7: `scanAll` is async and yields (`sleep 1`) after every log line, so
the bridge drains per candidate; candidates are **tiered by provenance** —
`extPageSafe` (bases found in cage wrappers at L0, walked without death in
the v2 era) scan first, then the near-verified soft list, then `extPageCpp`
(page values found inside C++ bodies — the untested tier) last; every
candidate gets a `wt3 try q=... src=...` line **before** its reads, so the
kill site is the last line even if the miss line is lost; the candidate
report is three short lines (page/soft/far) instead of one 1 KB line. The
next run names the exact candidate that kills it.

### 8.12 Trigger-entry calibration (2026-10-13 14:56, runs 1–2) — auto-reload shipped

Two runs in a row never armed, both upstream of the hunt — no hunt code ran:
- run 1: the DFG detector exhausted its 550-round budget (~70 s) → `wt0=ABSENT`;
- run 2: attempt 1 died at `PHASE 2 ... err=v128-leak-failed` (exploit.js:499),
  attempt 2 ground in PHASE 0 for 29 s until the page was reloaded.
The W-T0/W-T2 trigger is the probabilistic upstream PoC stage (~70–80% per
load across the session history); a failed page load spends its budget but
the session does not end. `exploit.html` now auto-reloads on a failed arm:
`location.href = "exploit.html?r=N+1"` after 3 s, the counter rides in the URL
query (no storage-API dependency on file://), capped at 10 — a genuinely
broken page stops and waits for a manual Reload; a successful arm logs
`ARMED after N auto-reload(s)`.

### 8.13 Scan-phase calibration (2026-10-13 15:08, runs 1–2) — hunt v7.1 shipped

v7's instrumentation did its job: both runs armed in 3–4 s (auto-reload did
not fire), the BFS completed 32/32 L1 with cpp2=8, and the scan phase RAN
for the first time in six passes. The kill site is now named precisely:

- `cand-page scan1 = 0x112423000` (wrapper+16, malloc — walked, miss),
  **`0x112c4e000` (page-aligned value from the `fn` wrapper body — KILLED the
  run at its page walk)**, `0x16b044000` (Gigacage). Run 2 repeated the shape
  identically (`0x10e0ac000`).
- the soft tier holds 24 near-verified cage values (5 of them hot) and never
  got scanned; the far tier is pure garbage — `0x3000010000p`, `0x8000010000p`
  (reservation constants), `0x4301128ed40s`/`0x2c10e80158s` (packed u32s),
  `0x550010e8ecb8s` (a JSCell header).

v7.1: the "L0 pages are real" premise was only ever true for two fields —
wrapper+16 and wrapper+72/+80 (the only page bases walked without death
across all eight passes). `dumpObj` now takes a `prov` flag: only the
navigator wrapper and the two WasmGlobal bodies push page-aligned body
values into `extPageSafe`; every other object's page-aligned values
(including the fn-wrapper's) demote to `extPageCpp`, scanned last. Expected
next run: the pSafe walk and the full 24-entry soft scan complete, and the
death (if any) moves to the Cpp tier with `try q=... src=Cpp` naming it.

### 8.14 hop repair (2026-10-13 15:23) — hunt v7.2 shipped

Audit of the BFS on the 15:08 data found a dropped hop: the cpp2 (L2) tier
was hot-gated — a holdover from the 22:14 ±64 MB hole fix. But in-window
values (`wt3Region "cpp"`, the 16 MB proven heap) are the same deref-safety
class as cpp1's, which are dumped unconditionally. The hot rule therefore
dropped cold `Wasm::Module → Wasm::Code*` pointers — referenced exactly
once — and that is precisely the hop that reaches the jump table / code
mapping. v7.2: the L2 tier dumps ALL in-window values (deduped,
cross-deduped against cpp1, cap 32). Also: the `cand-page` log line now
prints the `cpp=` tier as well, so the module-cluster page candidates are
visible even if a later tier kills the run.

### 8.15 Cpp-tier discovery + scan reorder (2026-10-13 15:26) — hunt v7.3 shipped

v7.2's hop fix worked on device: `cpp2=32` in both runs and the C++ depths
surfaced page bases never seen before — `0x112cd1000`, `0x10d2c7000`,
`0x110d10000`, and two hot candidates OUTSIDE the 4 GB cage block:
`0x1404a2000` (~5.4 GB) and a hot far interior `0x1067617480` (~71 GB). But
the scan order spent its budget on the 24-entry cage-data soft tier before
the C++ tier, and two recurring hot reservation constants —
`0x3000010000`, `0x8000010000` (packed `[X:Y]` pairs that pass every
pointer filter) still rode the cpp tier.

v7.3: scan order is now **pSafe → pCpp → softFar (hot, outside the 4 GB
span) → softNear (cage data)** — the C++ tier, the only tier that can hold
the wasm code, is scanned second, right after the two proven L0 pages; the
two reservation constants are denylisted per-build; and the full **scan
plan** (`wt3 plan … safe=[…] cpp=[…] farHot=[…] near=[…]`) is logged before
any read, so it survives the renderer death that can lose the
per-candidate lines (both the 15:08 and 15:26 runs lost them to the IPC
batch not flushing before the kill).

### 8.16 in-tier death + cold clusters (2026-10-13 15:40) — hunt v7.4 shipped

v7.3's order executed exactly as designed: both runs walked the two pSafe
pages (`miss`), entered the Cpp tier, and died there — run 1 at Cpp
candidate 2, run 2 at `0x10fd64000` (the log's last line; the user's "why
does the log stop" — the renderer died mid-walk, the try line was the last
flushed message). Two artifacts fixed: the Cpp tier re-walked the two proven
pages (hot values repeat across bodies — now deduped against pSafe), and the
far list carried a genuine new signal: **three cold page pointers inside one
1 MB region** (`0x10ec10000`/`0x10ec11000`/`0x10ec13000`). Cold singles are
noise; a cluster of independently-referenced pages in one megabyte is a
reservation. v7.4 promotes cold clusters (region's lowest page) into the
Cpp tier before each scan pass and logs `wt3 cluster promote=N`.

### 8.17 VERDICT — the JS pointer graph is closed (2026-10-13 15:53) + the B12 seam

The 15:53 pass executed the complete v7.4 pipeline: `cluster promote=1`,
full scan plan, both pSafe pages walked and missed, then the Cpp tier's first
candidate killed the run (`0x10e2a3000` / `0x10e28d000`) — exactly as in
15:40. Combined with the ten passes before it, the tier characterization is
complete:

| tier | device evidence | verdict |
|---|---|---|
| pSafe | wrapper+16 (malloc), wrapper+72/+80 (Gigacage) — walked clean every pass, never a fingerprint | data, proven |
| pCpp | hot page-aligned cage-block values; first candidate kills every run (`0x10ec0a000`, `0x10e2a3000`, `0x10e28d000` — unmapped holes in the cage reservation) | holes + data |
| softFar (hot, outside 4 GB) | `0x1800_10e8_f118` (a JSCell header), `0x286f485090`/`0x326f485090` (packed u32 pairs — top byte differs, low bits identical) | garbage |
| softNear | 24 entries, all within the wrapper/malloc cage neighborhood | data |
| far | reservation constants (`0x3000010000`, `0x8000010000`), headers (`0x5500_10e8_f0b8` = instance+0), packed pairs (`0x1067617480`) | garbage |

No reachable pointer leads to the wasm JIT code region; the code mapping is
outside every path the renderer exposes. **The JS-side hunt is closed.**
Shipped this pass: the **B12 → WebKit seam** — `WebKitHolder.setCodeHint(hex)`
(Swift) → `window.__wt3CodeHint` → `unitRwxHunt` skips the pointer chase and
scans the kernel-supplied mapping base for the movz directly. When the native
line's read channel (aio-kevent read → renderer task mappings) produces the
code address, W-T3 gets its target for free: hint → scan → write-test →
inline-hook → shellcode, the whole downstream chain unchanged.

### 8.18 hunt convergence (2026-10-13 16:36, runs 1–2) — shipped

Two user-facing truths from this pass, both fixed:
1. **the log "stops"** because WebContent death in the LiveContainer guest
   never fires `webContentProcessDidTerminate` (no FATAL line in the entire
   session) and the JS-side navigation discards the in-flight IPC batch —
   the last words after `try q=` are lost. The native side now detects the
   death by construction: every `try q=` opens a candidate walk, every
   `miss q=`/`FINGERPRINT` closes it; a walk still open at the next
   `nk_run_begin` (a fresh page) is the lethal candidate. It is appended to
   `Documents/wt3_dead.txt` and logged as `probe-dead: 0x…` at the START of
   the new run — the last words of the dead run are never lost again.
2. **the scan could never get past the first lethal Cpp-tier page.** Now the
   page fetches the dead list on load (bridge `GETDEAD` → `window.__wt3Dead`)
   and skips every listed candidate (`wt3 skip dead <tier> <q>`). Each
   reload therefore eliminates exactly the page that killed the last one and
   advances one step deeper through pCpp — reaching the farHot tier (which
   finally holds the hot ~71 GB candidate `0x1067617480*`) within a few
   reloads instead of never. `?dead=clear` (or the CLRDEAD bridge tag)
   resets the list.

### 8.19 slot-keyed convergence (2026-10-13 17:35) — v2, installed build supersedes 16:48

The 17:35 device pass ran the 16:48 build only partially in effect and
exposed the design flaw: the dead list was keyed by ADDRESS, but every
pointer is ASLR-randomized per page load — run 1 died on the Gigacage walk
(`try q=0x16f1d4000` absent, death between the L0 idx=0 miss and its try) and
the next run gets a completely different Gigacage base. An address blacklist
can never match. Also observed: the Gigacage walk is INTERMITTENTLY lethal —
the 8-page walk stops only on an empty page, so a hole after a committed page
kills it on some runs and completes (`miss`) on others.

17:41 build: the dead list is keyed by **TIER:INDEX** (`L0:0`, `Cpp:1`,
`farHot:0`, `soft:3`) — the tier-slot position is stable across reloads even
though every address moves. The `try q=`/`miss q=` lines now carry
`src=<tier> idx=<k>/<n>`; the C bridge tracks `tier:idx`, marks the walk that
never closed, appends it to `wt3_dead.txt` (deduped on read), and the JS
skips that slot with `wt3 skip dead <tier> idx=<k>`. Each reload eliminates
exactly the lethal slot and advances; the scan reaches farHot/near after a
handful of reloads instead of never.

### 8.20 slot convergence — deep-run evidence + parser fix (2026-10-13 17:43)

The 17:43 pass (17:41 build) drove the scan deeper than any prior run: run 2
walked the Gigacage clean (`miss q=0x16b8e0000 src=L0 idx=1/2` — confirming
the intermittence), then `Cpp idx=0` clean, and died at `Cpp idx=1`
(`0x1120b7000`). But no `probe-dead:` line appeared: `probe_track` used
`strncmp(msg, "try q=", …)` while every JS line arrives label-prefixed
(`wt3 try q=…`), so tracking never armed. 17:46 build: `strstr` search for
`try q=` / `miss q=` / `FINGERPRINT` — the walk-open/walk-closed state now
tracks correctly and the first `probe-dead: Cpp:1` lands at the next
`nk_run_begin`. From here each reload skips one lethal slot: the next run
starts at `Cpp idx=2`/farHot and the tiers fall in sequence.

### 8.21 unarmed session (2026-10-13 17:49, runs 1–3) — v128-leak retry shipped

This pass never reached the hunt: run 1 attempt 1 failed `v128-leak-failed`
(hb4 → exploit.js:499), attempt 2 ground PHASE 0 and the page reloaded at
+15 s; run 2 exhausted the detector's full 550-round budget (~60 s) →
`wt0=ABSENT` → self-test FAIL → **auto-reload fired exactly as designed**
(run 3 began 3.0 s after the FAIL — the 3000 ms navigation), and the page
re-entered the detect→arm cycle. The trigger's probabilistic stage had a bad
session; nothing in the hunt/convergence path was involved.

Two device observations (14:56 and now) show the same death spot: the v128
leak reads through `addrof` results captured once, and a GC between the
container/structArr allocation and the scan leaves them stale →
`v128-leak-failed` on attempt 1. 17:54 build: the leak scan now runs up to
**3 passes**, each with freshly allocated container/structArr and re-captured
addresses (~90 cheap wasm calls per pass, no await, no bridge inside the
critical section). A stale-capture pass costs one extra pass instead of the
whole attempt.

### 8.22 convergence PROVEN on device (2026-10-13 17:57) — the scan reaches farHot

First pass with a working `probe_track` — the full convergence chain ran on
device, both halves visible in one log:
- run 1: pSafe idx=0/1 clean (`miss`), then `try q=0x112c10000 src=Cpp idx=0/2`
  — renderer death mid-walk;
- `[17:57:19.588] [SCAN] probe-dead: Cpp:0` — the C bridge detected the
  walk-never-closed at the next `nk_run_begin` and logged the last words of
  the dead run natively (this is the "log stops" complaint closed);
- run 2 (fresh ASLR everywhere): pSafe clean again, **`wt3 skip dead Cpp idx=0
  0x110d23000`** — the lethal slot skipped by position, its address is
  different but the slot is the same — then `Cpp idx=1` clean `miss` and
  **`try q=0x18001108f578 src=farHot idx=0/3` — the farHot tier is reached for
  the first time in fifteen device passes**.

17:59 build: farHot shape filter so the garbage slots don't each cost a
reload — JSCell-header values (top-16 flags `0x18xx`/`0x55xx`, the
instance+0 header pattern) and packed-u32 pairs (two farHot values sharing
low-32 with different high halves — two integers in one qword). Both
signatures repeat in every pass and neither is a code pointer; skipped with
`wt3 skip shape farHot … packed-u32|jscell-header`. What remains after the
shape filter and the dead-slot skips: the near tier (cage data), then the
complete verdict — all tiers walked, full candidate record.

### 8.23 silent-stop signature + dual watchdogs (2026-10-13 18:23/18:35)

The 18:23 pass exposed a failure shape the convergence could not classify:
run 2 walked `Cpp idx=1` to a **clean `miss`** and then the log stopped —
no `try idx=2`, no new run, no FATAL, for at least 49 s. Not a mid-walk death
(the miss proves the walk closed); not a JS exception (that path logs
`ATTEMPT=1/4 THREW`); a hard silent stop with no recovery. The earlier
"automatic restarts" were a side path, not a mechanism — this pass proved the
page can stay dead.

18:35 build — dual watchdogs so every stop shape self-heals:
- **JS watchdog** (`wdBump`, resets on every SCAN line, 10 s budget): a hunt
  that goes quiet reloads the page itself — covers hangs where the JS thread
  is alive but stopped logging;
- **native watchdog** (app-process `Timer`, 2 s tick): scan activity within
  the last 60 s plus >8 s of total bridge silence = `native watchdog: hunt
  silent 8s — reload`. Runs in the APP process, so it survives a hard
  renderer death — the case the JS watchdog cannot see. Idle pages (stale
  last-SCAN) are left alone.

### 8.24 watchdog observability (2026-10-13 19:14/19:23) — the watchdog never fired

The 19:14 pass died at `try q=0x10d500000 src=Cpp idx=2/4` and the log
ended there — but the user pasted 4.5 minutes later and the native watchdog
had NOT fired and NOT logged. No heartbeat line existed, so "timer dead vs
condition wrong" was unanswerable from the log. Fixed in the 19:23 build:
- native heartbeat `watchdog tick=N anySilence=… scanSilence=…` every 15th
  tick (every 30 s) — the log alone answers whether the timer is alive;
- JS watchdog lifecycle lines: `wt3 watchdog armed (10s of hunt silence ->
  js reload)` at pivot start, `js watchdog: hunt silent 10s — reloading` when
  it fires, `wt3 watchdog disarmed (pivot settled)` when the pivot resolves —
  a healthy armed page never fires it (dead-slot skips and clean misses keep
  bumping; the disarm at settlement covers the idle-after-verdict case);
- the native reload now also logs its own `native watchdog: hunt silent 8s —
  reload` line (the heartbeat and the action are separate lines).

### 8.25 black-page root cause + fix (2026-10-13 19:30/19:34)

The 19:30 pass: run 1 died between the last L1 dump and the `L1 done`/plan
lines — a pure-JS gap with no reads at all. That is the known fragility of
the armed primitive: the hunt keeps fakeobj anchors live for its whole
duration, and a GC in a bad instant walks the conservative stack onto them
(the upstream PoC's own risk). The page then went **black** and stayed
empty — the user's main complaint — and the watchdog did not recover it.

Root cause of the dead watchdog, found in this pass's heartbeat: it printed
`anySilence=63927671437.3s` — i.e. `Date.distantPast`. The timestamps were
updated inside `NKBridge.forward`, **which nothing calls** (messages go
through `NKScriptMessageHandler.didReceive`), so both stamps never moved and
the reload condition could never be true. 19:34 build: `NKBridge.touch(tag)`
is called at the top of `didReceive` for every message; the reload condition
is scan-activity within 90 s plus >6 s of total bridge silence; the reload
itself stamps `lastAnyAt` so it cannot re-enter immediately; the JS watchdog
(10 s) remains the in-page backstop for hangs, the native one (6 s, app
process) covers hard renderer death — the black page.

### 8.26 treadmill verdict + deep-body read (2026-10-13 19:38/19:40)

The 19:38 pass is the treadmill proven with four data points: run 1 died at
`Cpp:0` → `probe-dead: Cpp:0`; run 2 skipped it and died at `farHot:0` →
`probe-dead: farHot:0`; run 3 skipped that (by a DIFFERENT value — ASLR
re-draws the tier every load) and died at `farHot:1`; run 4 skipped both and
died at `Cpp:2`. Four reloads, four fresh lethal slots, **zero complete
passes**. Conclusion, structural not incidental: lethality is a distribution,
not a fixed set — every load re-randomizes the candidates, so the dead-slot
mechanism samples the distribution but the probability of ~30 consecutive
clean slots (the near tier alone) is ~1e-9. The grind cannot close by
iteration; the watchdog keeps the session alive while the seam does the real
work.

The one unplayed deterministic card, shipped in 19:40: **deep bodies** —
L1/L2 dump depth 0x200 → 0x600. `Wasm::Instance` and friends are far larger
than 0x200; the jump-table / entrypoint pointers (values OUTSIDE the cage
block — the executable region) live deeper in those bodies than the first
64 qwords. Reads stay in the proven 16 MB heap window; whatever out-of-block
non-garbage pointers appear are either hot (→ farHot tier) or printed in
`cand-far` — and across passes their signatures (stable low-32 with a varying
top byte = the PAC-tag pattern, cf. the recurring `0x…67617480`) will name the
real code pointer if one is reachable at all. If the deep pass surfaces
nothing new, the JS graph is closed for good and `setCodeHint` is the only
remaining delivery path — which is exactly the B12 convergence.

### 8.27 watchdog PROVEN + reservation-constant family (2026-10-13 19:44/19:47)

The 19:44 pass proves both watchdog halves on device:
- `watchdog tick=1 anySilence=0.9s scanSilence=0.9s` — the heartbeat prints
  real timestamps (the dead-watchdog bug is gone);
- run 2 died in the pure-JS gap right after the plan line (the GC-vs-armed-
  primitive fragility), the fast restart did not trigger this time, and the
  **native watchdog fired at +6 s**: `native watchdog: hunt silent 6s —
  reload` → WKLOAD → run 3. The black-page failure mode is closed.

And the deterministic find: the Cpp tier's slot 0 in BOTH runs was
**`0x2000010000*`** — the same value, hot, page-aligned, lethal, hence two
consecutive `probe-dead: Cpp:0`. It is a member of the reservation-constant
family `[small top][0x10000|0x80000000]` (cf. `0x3000010000`,
`0x8000010000`, `0x400080000000`) that the original two-value denylist
missed. 19:47 build: the denylist is the family rule — low-32 equal to
`0x10000` or `0x80000000` — so the hot constants can never reach a scan tier
again. Remaining treadmill cost is the ASLR-drawn holes only.

### 8.28 reservation-deny PROVEN + farHot magnitude gate (2026-10-13 19:52/19:55)

The 19:52 pass confirms the family deny on device: **run 3 walked the entire
Cpp tier clean** (`0x10dca7000 → miss`, `0x10c0bd000 → miss`,
`0x10c3a9000 → miss` — only the last slot died, `probe-dead: Cpp:3`). The
guaranteed slot-0 killer is gone; the Cpp tier is fully passable. The native
watchdog fired again twice (run 2 and run 4 deaths, +6 s each) and the
heartbeat printed `tick=16 anySilence=1.3s` — live timestamps.

The last repeating killer: farHot slot 0 `0x6e01f1074c40*` (~60 TB) and its
family (`0x51067617480` ~5.5 TB, `0x1067617480` ~69.7 GB) — hot-status
garbage at absurd magnitudes; nothing above 64 GB has ever been a readable
page in ten passes. 19:55 build: a magnitude gate on farHot — values
≥ 0x10_0000_0000 (64 GB) are printed as far data only (`wt3 skip shape
farHot … above-64GB`), never scanned. Legitimate out-of-block pointers (the
renderer binary / dyld-cache region) sit at 6–10 GB, well inside the gate, so
the gate costs nothing and removes the far tier's entire garbage family.

### 8.29 FINGERPRINT ON DEVICE (2026-10-13 20:00) — the hunt found the code

**Run 3 of the 19:59 pass, `Cpp idx=0` = `0x10ecfd000`:**

    wt3 FINGERPRINT q=0x000000010ecfd000 site=0x000000010ed008d0
    W-T3 WRITETEST ok site=0x000000010ed008d0 orig=0xf2beb4d0d280f710

The `orig` qword's low half `0xd280f710` is literally `movz x16, #0x07B8` —
the fingerprint instruction, in place. The deep-body read (0x600, 19:40's
change) is what surfaced the mapping: `0x10ecfd000` came from a C++ body's
deep fields, the 8-page walk found the movz inside it, and the byte-level
write test (write `0x5A`, verify, restore, verify) **passed** — the wasm code
page is writable through the renderer AAR/AAW. Every prior pass was hunting
for exactly this; the combination deep-bodies + reservation-deny + far-gate
finally carried the scan to it.

The run then died 79 ms later, between `WRITETEST ok` and the first payload
log — the only unlogged memory touches in that window are the scratch-resolve
probe reads (`window.read64(cand)` on unvalidated candidate pointers), each
of which can SIGSEGV. 20:04 build: full payload instrumentation —
`wt3 scratch-resolve begin`, a logged `wt3 scratch probe <addr>` before every
candidate read (with the 64 GB gate carried over from the far tier),
`wt3 payload path=`, `wt3 patch write begin`, and a safe marker read for the
verdict line. The next FINGERPRINT run will name the exact step, and the
gate is one line away: `W-T3 SHELLCODE PASS` = marker qword + `SHELLCODE`
line written by the pivot shellcode.

### 8.30 dead-mark scoping fix (2026-10-13 20:09/20:17) — marks can blind the prize

The 20:09 pass re-examined the dead-slot mechanism itself and found a real
flaw: **Cpp/farHot/near re-draw every load** (ASLR), so a mark at position k
blinds WHATEVER sits at position k in the next run — including the code
mapping. The 20:00 FINGERPRINT landed at `Cpp idx=0` and survived only
because `Cpp:0` happened to be unmarked. For re-drawn tiers a positional
mark is a coin flip (skip a hole vs. skip the prize). L0 is the exception:
idx=0 is always `wrap+16` and idx=1 always the Gigacage base — positionally
stable, marks are pure win there. 20:17 build: dead-skip is scoped to L0
only; Cpp/farHot/near runs announce `(was-dead, re-drawn)` and walk anyway.
The holes are re-paid per run, but the code mapping can never be skipped.

### 8.31 first L0 death + walk-depth tiering (2026-10-13 20:20/20:23)

The 20:20 pass: run 1 died in the pure-JS gap before the first try (the
GC-vs-armed-primitive window again); run 2 died at **`L0 idx=0`** —
`probe-dead: L0:0`, the session's first death on the `wrap+16` walk, which
had read clean in ~20 prior passes. Diagnosis: the walk extends 8 pages above
the mapping base and stops only on an *empty* page; with the heap drifted,
one of the deeper pages in the window is a hole — the base page itself has
never been the problem. The L0 tier produced zero fingerprints across all 20
passes (the code always came from Cpp — at 20:00 it sat at +0x38D0, page 3 of
a Cpp mapping), so its deep walk is pure death-surface with no yield. 20:23
build: `walkPage` takes a depth — **L0 walks 1 page** (page 0 of a verified
base has read clean every pass), Cpp keeps the full 8. Next pass should walk
L0 → Cpp with the death surface materially reduced.

### 8.32 cage-block tier rule (2026-10-13 20:29/20:33) — masks leave the tier

The 20:29 pass: tiered L0 depth works (1-page walks complete, `miss` in ~6 ms);
the Gigacage base page is itself intermittently uncommitted (mark handles it
within a session; the dead list does not survive fresh ipa installs — new
container = wiped Documents). And the Cpp tier acquired a new guaranteed
killer: run plans carried `0x3fffff0000*` / `0x3fffffff0000*` — reservation
masks with small/odd top-32, alongside the earlier `0x2000010000` family.
Every address the device has ever read successfully has **top-32 == 1** (the
4 GB cage block: 0x10ecfd000, 0x10ed19000, 0x10b…*). 20:33 build:
`isCageBlock(v)` = `(v >> 32) === 1` gates both page tiers — the whole
reservation/mask family can no longer reach the Cpp tier at all. What remains
lethal there are genuine heap holes (0x10b0bd000-type), which the treadmill
handles one per run. Miss lines now print the real depth (`pages<=1`).

### 8.33 steady-state grind confirmed (2026-10-13 20:37/20:41)

The 20:37 pass is the cleanest full pass of the machinery yet: run 2 skipped
the dead L0 slot, walked L0 at the 1-page depth (`pages<=1`), walked the
**entire Cpp tier clean** (3/3 misses), and the farHot shape filters both
fired (`above-64GB`, `packed-u32`). The run then died at farHot idx=2 — the
~5 ms pure-JS GC window between the try log and the filter computation (the
value itself would have been filtered: packed with idx=1 and above 64 GB).
20:41 build: farHot filters compute BEFORE the try log — a skipped candidate
never enters the window. Steady state: all systematic killers are eliminated
(masks, reservation constants, far garbage, JSCell headers, deep-page walk
deaths); the residual deaths are the GC window and genuine heap holes, one
per run at most. The payload instrumentation (20:04) stands armed for the
next FINGERPRINT run.

### 8.34 watchdog false-positive fix (2026-10-13 20:45/20:49)

The 20:45 pass exposed the native watchdog's false positive: run 1 ground
PHASE 0 for 6.7 s (a legitimate silent phase — the UAF hunt loop logs nothing
between ENTER and OK) and the 6 s silence rule reloaded the run mid-attempt;
the detector's ~5.3 s per-50-round logging also ran close to the threshold.
20:49 build — two separated rules with measured bounds: (1) hunt in flight
(`W-T3 pivot begin` seen, cleared by `watchdog disarmed`) + >12 s of total
silence → reload — the in-page JS watchdog fires at 10 s if the thread is
alive, so 12 s means a hard death; (2) pre-arm total silence >300 s → reload
— PHASE 0 legitimately grinds up to ~180 s (600 rounds) and the detector
logs every ~5.3 s, so only a real death hangs that long. The heartbeat now
also prints `huntSilence`.

### 8.35 plan-line split (2026-10-13 21:59/22:02) — the run that died at its own log
The 21:59 run 1 had the hunt at its best position in the session: the nd-dumps
of `0x103e0f050` (cand=7) and `0x1052374f0` (cand=15) produced a 24-entry W
tier (pages `0x10c2e5000`, `0x10c68c000`, `0x10c4fb000`, `0x10c6e9000`, then
the contiguous ladder `0x10c018000..0x10c364000` step 0x4000) — and the
renderer died mid-`wt3 plan`, the line torn after `0x10d898180` with binary
garbage on the tail. One cause: the plan line carried five lists in a single
~1.5 KB bridge message, and the C sink's buffers are 512 B (`g_last_msg` in
nk_jsbridge.c:21). Fix: `planLine()` prints one tier per line, drained with
`sleep(1)`, capped at 10 entries per line plus `+N`. Build
`srk801_20261013-220203.ipa`. Run 2 after the fix proved the rest of the
pipeline clean end-to-end: `sweep done src=W n=0`, F tier 2 candidates x 8
pages page-major, all 7 farHot above-64GB shape-skipped, soft idx=0..13 all
`miss` — zero deaths in the whole sweep.

### 8.36 GETDEAD roundtrip wired (2026-10-13 22:10/22:12) — the convergence loop was one-way
Dead-slot audit: `nk_run_begin` marks a still-open walk dead (nk_jsbridge.c:37),
UIBridge's `GETDEAD` case reads and delivers `window.__wt3Dead` — and nothing
ever sent `GETDEAD`. The JS read `window.__wt3Dead || []` (line 1344) of a
variable only Swift's unreachable branch writes, so convergence existed purely
as unwired intent. Fix mirrors the claim pattern exactly: `getDeadList()`
registers `window.__onDead`, posts `log("GETDEAD","request")`, resolves on
callback with a 2 s fallback; Swift fires `__onDead` after setting the array.
Hunt now logs `wt3 dead-list inherited n=...`. Skip semantics unchanged by
design (8.30): re-drawn tiers keep index-skip OFF — the mark is advisory
until a positionally-stable key appears. Build
`srk801_20261013-221203.ipa`.

### 8.37 W-T3 PHASE 2 — mprotect fallback (2026-10-14 14:58) — payload выходит за 256-байтное окно
Замеченный по пути факт: без кодового сайта native entry point НЕ СУЩЕСТВУЕТ —
единственный вызываемый примитив до пивота это сам экспорт wasm, а он landит в
код. Значит mprotect не замена охоте, а путь payload ПОВЕРХ охоты:
- stage-1 на сайте (44 B, лимит 256): `mprotect(scratch, 0x8000, RWX); br scratch`
  (SYS_mprotect=74 arm64-Darwin; страницы округляются вниз ядром — 0x8000
  накрывает весь 32 KB TA бэкинг даже если backing не выровнен);
- payload в RWX-scratch (до 0x8000 B): маркер-линия @+0x8000, канарейка
  "MPRXP" @+0x8008 (отличает полный прогон payload от одного stage-1),
  open/write/close trace.log "MPROTECT-EXEC\n", br site+PATCH_LEN назад в цепь.
Ключевой выигрыш структурный: потолок payload перестаёт быть окном хука.
Соединение: nkNativePivot теперь ресолвит scratch на 0x8000
(`wt3ResolveScratch(64|0x8000)`, паттерн 0x5AA5F00D5AA5F00D с проверкой через
ta[0]), ветвится mode=mprotect-phase2 (default; `window.__wt3Mprotect=false`
вернёт прямой путь); при фейле phase2 — фолбэк на прямой 256 B патч.
Юнит self-test `native-pivot-mprotect` утверждает marker+canary; при
found=0 — честный skip (mprotect требует сайта). Билд
srk801_20261014-145825.ipa.

### 8.38 dead-page run — script never executed (2026-10-14 15:16/15:23)
Device: run=0 holder init → WKWebView → WKLOAD → watchdog tick=1 (anySilence
6.4e10 s!) → SELFTEST EXCEPTION window.nkSelfTest is not a function. В логе
21:59 сразу шёл `[RUN] run=1 begin` (его шлёт HTML после IIFE) — здесь его
нет: IIFE не стартовал вообще. Локальная проверка: файл в IPA байт-в-байт
равен репозиторию (sha256, 119795 B), V8-парсер проходит, новых top-level
statements нет, весь не-ASCII — в комментариях. Значит причина на устройстве:
частичная копия exploit.js в Documents (LiveContainer тащит app в
Documents/Applications по тому же UUID контейнера 4FDBB51D) или устаревший
WK-кэш страницы. Фиксы обеих сторон:
- HTML pre-flight: `!window.nk || !window.nkSelfTest` → WARN
  `nk-missing — exploit.js did not parse/execute` в trace.log + ОДНА
  перезагрузка (?r=N+1) вместо вечно мёртвой страницы (catch и раньше оставлял
  страницу трупом);
- WebKitStage tick: `.distantPast` печатается как `never` вместо 6.4e10 s.
Билд srk801_20261014-152345.ipa. Если следующий ран повторит nk-missing —
это установка/контейнер, а не сборка: снести контейнер в LiveContainer и
поставить ipa заново.

### 8.39 nk-missing LOOP — файл на устройстве не исполняется стабильно (2026-10-14 15:32/15:38)
Ран 15:32: nk-missing на КАЖДОЙ загрузке, перезагрузки не лечат + мой же
предыдущий фикс (10 попыток) устроил спам-петлю — срезано до одной попытки.
Раз файл не меняется от перезагрузки к перезагрузке — это не «частичная
копия», а стабильно неисполняющийся exploit.js на устройстве (LiveContainer
держит app-каталог в Documents по тому же UUID контейнера, установка поверх
живой копии может оставлять старый/битый файл). Новый предполётной
диагностический блок в HTML: fetch(exploit.js) -> `js-bytes=<len> tail=<last
24 chars>` + `new Function(text)` -> parse=OK/FAIL + на parse=OK динамический
`<script>` с onload/onerror. Ответы дают триаж: bytes != 119795 или
parse=FAIL -> файл на устройстве битый/не тот (снести контейнер); parse=OK +
dyn-load=FAIL -> отказе script-тега (MIME/кэш); dyn-load=OK + nk=false ->
выполнение парсится, но падает до window.nk. Билд srk801_20261014-153819.ipa.

### 8.40 INLINE FIX — exploit.js не грузился с устройства (2026-10-14 15:49/15:56)
Симптом: `fetch=FAIL Load failed` при живой загрузке самого HTML из
Documents/Applications/<uuid>/.../webkit/ — внешний `<script src="exploit.js">`
не читался из LiveContainer-копии приложения. Проверено по чек-листу:
(1) оба файла в IPA есть; (2) node --check чист; (3) loadFileURL +
allowingReadAccessTo корректен и для Bundle, и для Documents — проблема не в
правах каталога, а в самой копии гостя. Лечение по шагу 4 чек-листа:
`build_inline.sh` подставляет `<!--WT3_INLINE_JS-->` в exploit.html полным
содержимым exploit.js (с guard'ами: node --check, запрет `</script>` в JS,
sanity-grep window.nkSelfTest), package_ipa.sh зовёт его до упаковки, меняет
стейдж-html на инлайновый и удаляет внешний exploit.js из бандла — гость
грузит РОВНО ОДИН файл. Билд srk801_20261014-1556xx.

### 8.41 ROOT CAUSE nk-missing — scope bug в моём же patch (2026-10-14 16:21)
КРАСНАЯ страница / nk-missing на каждой загрузке. Локально файл ВСЕГДА был
чист (node --check, sha IPA==repo) — потому что poison не в синтаксисе. При
вставке Phase-2 (14:57) helper'ы `wt3ResolveScratch` / `unitNativePivotMprotect`
осели ВНУТРИ `nkNativePivot` (edit был привязан к комментарику scratch-probe
внутри функции), а namespace `const nk = { ..., wt3ResolveScratch: wt3ResolveScratch }`
на уровне IIFE ссылается на них — ReferenceError при оценке объектного литерала
→ IIFE умирает ДО `window.nk = nk` → nk-missing на любом билде с этим кодом.
(22:02 planLine и 22:12 GETDEAD, судя по всему, были ни при чём — на устройство
после рабочей 21:59-сессии впервые встал именно 14:5x-билд.) Всеобщий урок:
после вставки функций в этот файл — аудит namespace-идентификаторов на
разрешимость в скоупе IIFE (сделано node-скриптом: все 31 id резолвятся).
Фикс: Phase-2, planLine-разбивка, getDeadList и инлайн-машина (build_inline.sh +
хук в package_ipa.sh) вырезаны полностью; scratch-probe в nkNativePivot
восстановлен в оригинальном inline-виде; package_ipa.sh откачен к репо-версии
(`git checkout HEAD --`); .theos staging почищен от exploit.inline.html. Билд
srk801_20261014-162721.ipa: ровно exploit.html (external script src) +
exploit.js. Переустановка: снести гостя в LiveContainer, поставить ipa.
Повторный лендинг Phase-2 — ТОЛЬКО с helper'ами на уровне IIFE и проверкой
`nk.unitNativePivotMprotect` после сборки.

### 8.42 FIX CONFIRMED ON DEVICE + Phase-2 re-land (2026-10-14 16:31/16:34)
Ран 16:31 (билд 162721): страница жива — RUNBEGIN, вся цепочка self-test,
W-T0 PRESENT round=23/24, W-T2 ECHO OK, auto-pivot armed=yes, hunt с
dump/L1/nd/plan/sweep. Run1 умер на `sweep q=0x10b2f5000 src=W pg=0/4` —
первое чтение страницы первого W-кандидата (killer-class, watchdog перезагрузил
через 150 мс). Run2: W tier = [0x10a0bd000] (ASLR перерисовал), sweep пошёл.
Phase-2 возвращён ПОСЛЕ подтверждения живой страницы: builder'ы и helper'ы на
уровне IIFE (4-пробельный отступ — проверка регуляркой), namespace резолвится
(аудит-скрипт: все значения есть в top-level), mode-ветка mprotect-phase2 по
умолчанию с фолбэком на прямой 256 B патч, self-test юнит
native-pivot-mprotect при found=0 честно скипается. Билд
srk801_20261014-163448.ipa. Ожидание на устройстве: `WT3-PHASE2 payload=…B
stage1=44B` → `WT3-PHASE2 SHELLCODE PASS marker=0x5a5aa15a5a5aa15a
canary=0x4d50525850` либо diagnose-линия (mprotect-RWX denied на non-MAP_JIT).

### 8.43 steady grind продолжается (2026-10-14 16:40/16:41, билд 163448)
Обе сессии (16:31, 16:40) — один паттерн: self-test зелёный, W-T0 PRESENT,
W-T2 ECHO OK, auto-pivot armed, hunt доходит до plan+sweep.
- 16:40 run1: смерть ВНУТРИ L1-dump — последняя метка `L1:0x10b0477f0`
  (58.573), следующая метка не напечаталась → kill внутри dumpObj-тела этого
  объекта; run2 через 127 мс.
- 16:40 run2: W tier наконец 3 кандидата (`0x10b377000 0x10b2cd000 0x10b26b000`
  — из `L1:0x10b131c30 cand=1`, `L1:0x10b3f1620 cand=1`, `nd:0x10e90d1a0 cand=1`),
  skip L0 idx=0/1, sweep пошёл (лог оборван).
- 16:31 run1: смерть на `sweep q=0x10b2f5000 src=W pg=0/4` — первое чтение
  первого W-кандидата (killer-class).
Phase-2 (mprotect) в этих ранах не достигнут: он требует САЙТ (fingerprint),
а охот умирает до сайта — это by design, а не регресс. Детерминированный
шорткат остаётся прежним — B12-хинт: `WebKitHolder.setCodeHint("0x…")` →
`window.__wt3CodeHint` → hunt скипается, сканируется переданный mapping
(`wt3 hint=… — hunt skipped`). GATE по плану без изменений: SHELLCODE в
trace.log (прямой путь) либо WT3-PHASE2 SHELLCODE PASS (mprotect-путь).

### 8.44 SWEEP ORDER F-FIRST + depth 16 (2026-10-14 16:47/16:50)
Доказательство из логов дня: W-кандидаты — in-cage страницы (0x10b2xxxxx /
0x10b3xxxxx), которые убивают на pg=0 каджый ран (16:31 `sweep
q=0x10b2f5000 src=W pg=0/4` → death; 16:40 оба рана до sweep не дошли —
умерли в dump-фазе) и не дали НИ ОДНОГО fingerprint за всё время. При этом
20:00 (8.29) код пришёл из far/Cpp-body deep field: `q=0x10ecfd000
site=0x10ed008d0` (movz на +0x38D0). Far-кандидат сегодняшнего run2 —
`0x10ecf3000`, тот же банд 0x10ecfxxxx. W-first порядок (v8, комментарий
「20:00 provenance」 относился к Cpp-классу той эпохи) гарантированно умирал
ДО того, как F получал шанс. Фикс: F свипается ПЕРВЫМ, глубина 8 → 16
страниц (0x10000 — покрывает банд от любой страницы в нём); W остаётся
фолбэком. Билд srk801_20261014-165003.ipa.

### 8.45 F-FIRST FIRST LIGHT (2026-10-14 16:52, билд 165003)
Первый боевой прогон F-first: run2 дошёл до
`sweep q=0x1100a0000 src=F pg=0/16 hot` — впервые за сессию F-тиер получает
свип ПЕРВЫМ. Кандидат — горячий кластер: far=[0x1100a0000* 0x1100aa000
0x110340000], второй член кластера ровно +0xA000 от первого (та же форма, что
предшествовала 20:00-успеху: кластер 0x10ec10000/0x10ec11000/0x10ec13000 →
код на 0x10ecfd000). Глубина 16 страниц = 0x1100a0000..0x1100affff —
покрывает второго члена кластера (0x1100aa000) и весь банд, включая
+0x38D0-зону, где 20:00нашёлся movz. run1 умер в фазовом окне plan→cand-far
(118 мс, GC-класс, без чтений — 8.43). Ожидание: `wt3 FINGERPRINT
q=0x1100a0000 site=0x1100axxx` либо смерть на pg=0 → dead-mark F:0
(адресный, позиционный, advisory).

### 8.46 odds-рычаги: deep-dumps 0x1000 + F-sweep 64 страницы (2026-10-14 17:37)
Лотерея (слепые чтения кандидатов, ASLR перерисовывает всё каждый ран) крутится
25+ прогонов без попадания после 20:00. Бьём по обоим рычагам odds, оба с
журналовыми доказательствами:
1. `DUMP_DEEP = 0x1000` (было 0x600 везде: L1/nd/L2). 8.29 дословно: «the
   deep-body read (0x600) is what surfaced the mapping» — указатель на кодовую
   страницу пришёл из ГЛУБОКИХ полей C++-объекта. L1/nd/L2-дампы чтL1
   0x600 десятков живых объектов в mapped cpp-блоке без единой смерти за все
   сессии → 0x1000 = больше указателей за ран при том же safety envelope.
2. F-sweep глубина 16 → 64 страницы (256 KB): члены кластера стоят 0/+0xA000,
   movz 20:00 был на +0x38D0; 256 KB накрывает весь бэнд от любой страницы в нём.
Билд srk801_20261014-173728.ipa.

### 8.47 F-first выжил + план-регресс возвращён (2026-10-14 17:50/17:54)
Полный лог 17:50 дал два факта:
1. F-first РАБОТАЕТ: run2 срезал 14 кандидатов F-тира подряд на pg=0 без
   единой смерти — кластер 0x1660c8000/0x1660f0000/0x1660f8000/0x1660fc000 и
   0x1672fc000..0x167dec000 (+0x10d0a0000/0x10d289000/0x10d47c000) все
   прочитались и были отброшены контент-гейтом (reserved-пустышки, nonZero<4 —
   гейт работает как задуман). Смерть на 15-м кандидате 0x10d0b1000 (кiller),
   16-й 0x103e20000 не достигнут. run1 тем же путём умер на первом же F
   (0x11287b000 pg=0).
2. РЕГРЕСС: plan-строка снова binary-мусором (near-list хвост) — откат
   planLine-сплита 16:21 вернул класс смерти 21:59: C-сток g_last_msg=512B,
   ~1.3KB строка обрезается, хвост буфера течёт мусором. Сплин по спискам
   (safe/win/far/farHot/near, ≤10 на строку, с дренажем) возвращён.
Состояние odds: F-тир самофильтруется (пустушки ~4мс, киллеры = смерть рана),
W-тир (18 кандидатов, ladder 0x10c018000..0x10c24b000 от указатель-таблицы
nd:0x103e0f050 cand=11) сегодня не достигался — F умирал первым. Кодовая
страница остаётся поэрановой лотереей; единственный не-лотерейный путь —
B12-хинт (setCodeHint). Билд srk801_20261014-175428.ipa.

### 8.48 STRATEGIC PIVOT — WebKit pivot as the IOGPU race driver (2026-10-14 20:00)
Device sweep (build 194208): services=1091 opened=83 denied=1086
mutations=50 leaks=0 — из app-sandbox'а GPU-поверхность недоступна
(IOServiceOpen на IOGPU/AGX denied, указателей в ответных буферах нет).
ОТСЮДА ВЫВОД, МЕНЯЮЩИЙ ПЛАН: CVE-2026-43743 (IOGPUFamily) нельзя гонять из
приложения — нет GPU-entitlement. WebContent им обладает (WebGL/ANGLE
подтверждены fingerprint'ом устройства). Наш W-T3 pivot даёт native code В
WebContent => (1) IOServiceOpen(IOGPU user clients) проходит там, (2) гонка
гонится с точным двухпоточным интерливингом вместо фазерного перебора.
Цепочка kernel r/w становится: pivot (renderer code exec) -> in-WebContent
race driver -> IOGPUFamily UAF -> r/w. Payload под это — Phase-2 (RWX scratch,
32KB) уже собран. Свои 0-day — параллельно, но не конкурент следующему
device-прогону.

### 8.42 SWEEP Q= НЕ ТРЕКАЛСЯ — dead-slot файл молчал (2026-10-14 20:47/20:52)
Лог 20:29: sweep впервые прошёл pg=0 трёх кандидатов (`0x10d27b000`,
`0x10d122000` — чтены; `0x10d44a000` — смерть). Но `wt3_dead.txt` не
пополнился: C-парзер `probe_track` ловил только `"try q="`, а sweep-строки
имеют формат `"wt3 sweep q=… src=W pg=0/4"` — невидимки. Каждый ран
заново читал тот же tier-список. Фикс:
- JS: sweep-строка теперь несёт `idx=N` (слот кандидата в тире);
- C: обе формы (`try q=` / `sweep q=`) сводятся к одному `probe_key_of`
  (TIER:SLOT), sweep-ветка фолдится в него же;
- JS: `sweepPages` сначала вырезает помеченные слоты (`dead.indexOf(src+":"+i)`).
Ключ позиционный, никогда адресный: ASLR перерисовывает указатели, слот
внутри тира — стабилен. Билд srk801_20261015-204748.ipa.

### 8.43 CONVERGENCE PROVEN — probe-dead ловит sweep kill (2026-10-14 21:54/21:56)
Лог 20:54: ран доходит до 4-го W-кандидата, смерть на `0x10f126000`,
и C-мост пишет `[SCAN] probe-dead: W:3` — формат `sweep q=… idx=N pg=M/K`
теперь разбирается `probe_key_of` (TIER:SLOT), файл wt3_dead.txt пополняется,
ран перезапущен через 140 мс. Сквозной путь проверен: HTML → GETDEAD →
Swift `window.__wt3Dead` → `scanAll` → `sweepPages` вырезает помеченные слоты
до чтений. Глубина за ран выросла 2→4 кандидата; ран N+1 пропускает слот 3.

### 8.44 RELOAD-STORM BREAKER (2026-10-14 21:38/21:42)
Лог 21:30: приложение вошло в петлю релоадов — `run=4 begin`,
`run=5 begin`, `run=6 begin` трижды за 10 мс, затем `native watchdog:
silence 13.4s — reload`, и так по кругу; каждый цикл ~12 s сессии. Это
ровно та silent-restart-loop, которую журнал предсказывал (18:51): один
мёртвый рендерер — норма, десять за минуту — битая установка или отравленная
куча, и лишние релоады только жгут сессию. Предохранители с двух сторон:
- native (WebKitStage): таймстампы релоадов в окне 90 s; burst 8/8 →
  `native watchdog: burst 8/8 reloads in 90 s — DISARMED. Restart the app`;
- JS (`wdBump`): счётчик `?r=` выживает релоад; r ≥ 12 → `js watchdog:
  burst r=N — NOT reloading`, таймер снят, состояние в логе сохранено.
Билд srk801_20261015-213823.ipa. Операционное правило после DISARMED:
полный рестарт приложения (свежий процесс), не повторные нажатия.

### 8.49 LADDER CAP + SHARED RELOAD BUDGET (2026-10-15 22:20, билд packages/srk801_20261015-221747.ipa)
Три правки по итогам run3 (16:42): W-tier шёл из 22 слотов, из них 12+ —
плотное семейство резервации одного объекта (nd:0x101e0f050 cand=7 → pW=24,
кап тира выбран) в одном 1 MB-регионе (0x10a018000..0x10a03c000). Настоящие
code-pointers модуля вытеснены, и петля умирала на постороннем убийце, не
дойдя до тира. Фикс: `pushPage` ведёт per-tier реестр 「tier:region」 и пускает
максимум LADDER_CAP=3 страницы на регион — семейство резервации даёт десяток,
настоящий C++-объект 1-2.
Гонка reload'ов: `load()` в нативе всегда грузил exploit.html БЕЗ `?r=N`, так
что burst-бюджет жил только в памяти умирающей JS-страницы, и JS-watchdog
(10 s) + native-watchdog (12 s) срабатывали в одном окне тишины — run4 ушёл в
5 begin'ов за миллисекунды. Фикс: `?r` — общий бюджет. Каждая навигация (любой
watchdog или кнопка Reload) инкрементирует r через URLComponents-query, JS
читает тот же location.search, обе стороны разоружаются на r >= burstMax=12.
Native watchdog отступает, если r сменился с прошлого тика (JS владеет циклом).
JS-watchdog получил first-shot таймер: PHASE-0 setup не логирует SCAN, поэтому
hang был виден только нативу — теперь страница ловит его сама за 10 s.
Бонус: package_ipa.sh писал в `Packages/` (большая P), agent_build.sh искал
`packages/` — каждый билд отчитывался FAIL после успешной сборки. OUT поправлен
на нижний регистр.
AAR/AAW (read64/write64 через wasm-transport) привязаны к жизни рендерера:
убийца свипа забирает примитивы. Качество кандидатов — единственный рычаг
снижения килла; после капа регион-шум больше не занимает тир.
