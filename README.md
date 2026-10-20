# ⚔️ Lightsword

> iOS **26.2 (build 23C55)** exploit research toolkit — WebKit renderer pivot chassis,
> IOKit/IOGPU probes and UAF/OOB PoCs, on-device logging, all built from Linux with Theos.

**Built for interest.** This is a personal research project — a playground for
understanding how iOS 26 internals work (WebKit/JavaScriptCore, IOKit, the GPU stack,
the kernel). Nothing here is a finished jailbreak; it is best treated as a
documented expedition log with working probes.

**All testing was done on the author's own device: iPhone 13 (A15, arm64e, T8110),
iOS 26.2 / 23C55 (xnu-12377.62.10), IOGPUFamily 129.3.2, AGXG14P 342.3.**

---

## Why it exists

Sent from curiosity, not for harm: every routine runs inside a **sandboxed,
entitlement-less, ad-hoc signed app** delivered via LiveContainer. Everything
logged on-screen (`[W-T0]`, `[oob]`, `[uaf]`, `[probe2]` tags) — no persistence in the
host environment, no infrastructure hits, no distribution.

## What's inside

| Component | Path | Role |
|---|---|---|
| WebKit pivot chassis | `Sources/WebKit`, `Sources/App/WebKitStage.swift` | DFG/JS-run instrumentation, **W-T0/T2 renderer primitive verification** |
| State machine / home | `Sources/Core/nk_home.*`, `nk_state_machine.*` | run sequencing, phase gates, log transport |
| IOKit probes | `Sources/Legacy/iogpu_oob.m`, `iogpu_probe2.m` | IOGPU registry sweep: types 1..33, sel 0..127, zero/struct/scalar passes |
| Method-map probe | `Sources/Legacy/iogpu_oob64.m` | external-method map: 8 services x 8 types x 128 selectors, with per-selector kr matrix and a cmd/capacity replay |
| AIO UAF (track B) | `Sources/Legacy/aio_kevent_rw.c/.h` | deterministic reclaim trigger + kevent read channel; **proven kernel read** |
| Spray helper | `Sources/Legacy/nk_spray.m` | Mach-port spray (E1) — a dedicated `aio_workq_zonep` spray is the next piece |
| UAF PoC | `Sources/Legacy/iogpu_uaf64788.m` | CVE-2026-64788 (iOS 26.6 shape) probe, Metal/IOSurface-driven |
| Durable logging | `Sources/Core/nk_trace.c` | `Documents/srk801.log`, `oob64.log`, `aio_uaf.log` — fsync per line, survives a kernel panic |
| SPTM map | `Docs/sptm_23c55.md` | full offline analysis of the 23C55 SPTM binary (FTE layout, 64-type matrix, addresses) |
| Kernel slide / KASLR | `Sources/Kernel/kslide.c` | live KASLR base detection from device logs |
| Diagnostics | `Sources/Diag/*` | crash-guard, symbols, dtrace spikes |
| Fuzzer surface | `Sources/Legacy/*fuzz*.c` | IOKit / mach message fuzzers |

Everything routes back into the in-app log console — every phase, hit, and
verdict lands in `LogView` for iteration.

## Vulnerability surface under research

Full registry with per-item status, offsets and next steps: **[`VULNS.txt`](VULNS.txt)**.

The toolkit compiles probes for **publicly documented** vulnerability shapes and
their 23C55 field verification status:

| CVE / bug | Family | Status on 26.2 (23C55) |
|---|---|---|
| **AIO kevent UAF** (track B, "B12") — `filt_aioprocess` walks a freed `aio_workq_entry`; `kev.ext[0/1]` = slot `+0x28`/`+0x20`, `kev.ident` = `+0x48` | xnu bsd/kern | **UAF PROVEN on device** — the kevent is delivered to the freed entry. Not yet an arbitrary read (the slot currently holds our own donor values) and not yet a write: `TAILQ_REMOVE` writes through the entry's own `+0x10/+0x18`, `aio_entry_unref` can double-free, `aio_proc_lock` reads `procp` (0 ⇒ PANIC FAR=0x58). Both need a **controlled object in `aio_workq_zonep`** (224 B) — the cross-type reclaim, which was closed for the 192-byte bucket but never checked for the 224-byte aio zone. **Selected path to kernel R/W** (the only device-proven primitive in the tree) |
| **WebKit DFG type confusion** (MapIterationEntryKey-shaped node, per public writeups) | JavaScriptCore / WebKit | **[R/W] PROVEN on device** — 9+ verified W-T0 runs, AAR/AAW echo confirmed (W-T2). Renderer primitive; needs W-T3 native pivot to reach non-sandbox user clients |
| **CVE-2026-20667** — libxpc, "an app may be able to break out of its sandbox" | libxpc | **[LIVE]** — fixed in iOS 26.3, unpatched on 23C55. No public PoC. XPC is reachable from any sandboxed app |
| **CVE-2026-20615 / -20617** — CoreServices, "an app may be able to gain root privileges" (path handling / race condition) | CoreServices | **[LIVE]** — fixed in 26.3. Authors: Csaba Fitzl (@theevilbit), Gergely Kalman |
| **CVE-2026-20626** — Kernel, "a malicious app may be able to gain root privileges" | Kernel | **[LIVE]** — fixed in 26.3. Author: Keisuke Hosoda. No public PoC; most valuable, most closed |
| **CVE-2026-20628** — Sandbox, "an app may be able to break out of its sandbox" | Sandbox | **[LIVE]** — fixed in 26.3. Author: Noah Gregory (wts.dev) |
| **CVE-2026-20637** — AppleKeyStore use-after-free | AppleKeyStore | **[LIVE]** — fixed in 26.3. Author: Johnny Franks (zeroxjf) |
| **CVE-2026-20634 / -20675** — ImageIO, disclosure of process memory | ImageIO | **[LIVE]** — fixed in 26.3. Authors: gkarchemsky + Trend Micro ZDI |
| **CVE-2026-20609** — CoreMedia, crafted file may disclose memory contents | CoreMedia | **[LIVE]** — fixed in 26.3. Author: Yiğit Can YILMAZ |
| **CVE-2026-20611** — CoreAudio out-of-bounds access | CoreAudio | **[LIVE]** — fixed in 26.3. Trend Micro ZDI |
| **CVE-2026-20660** — CFNetwork, remote user may write arbitrary files | CFNetwork | **[LIVE]** — fixed in 26.3. Author: Amy (amys.website) |
| **CVE-2026-20700** — dyld memory corruption, **exploited in the wild** before iOS 26 | dyld | **[LIVE]** — fixed in 26.3. Author: Google TAG. Needs pre-existing memory write (our goal, not our tool) — proof that kernel write is reachable on iOS 26 |
| **CVE-2025-24257** — IOGPU `IOGPUGroupMemory::init` bitmap underflow (`(capacity>>6)-1` unchecked) | IOGPUFamily OOB | **DEAD on 26.2.** The 18.4 fix is present in 23C55 (`cmp w2,#0x3f` at `0x9f60fcc`): capacity < 64 ⇒ `kIOReturnNoResources`. Also: the real IOGPUFamily table is `0x7e67c58` = **two** 56-entry tables (type 1 → A, type 33 → A+B); sel 64 exists only on type 33; groups are actually created by **sel 8 on type 1** |
| **CVE-2026-64788** — `create_resource_iosurface` invalid-release UAF | IOGPUFamily UAF | **not vulnerable** at 23C55 (dims validator precedes resource insertion); vulnerable shape lives in 26.6 / 23G71 |
| **CVE-2026-43743** — IOGPUFamily race | IOGPUFamily | **closed** as a vector here (no sandbox entry point) |
| **vm_fault_copy** (re)type race — found in xnu-61.12 source, not in any advisory | xnu vm | **DEAD on 26.2** — SPTM makes the aperture physically write-protected ⇒ panic-DoS, not a write. Related: the **23C55 SPTM binary is available offline and unencrypted** (`Firmware/sptm.t8110.release.im4p`, unlike `sep-firmware`) — full map in [`Docs/sptm_23c55.md`](Docs/sptm_23c55.md) |

_[LIVE] = the fix landed in iOS 26.3 (build 23D127) and is therefore **absent
from 23C55 / 26.2**; the presence of the fix in 26.3 was confirmed by binary diff
of the two kernelcaches (only the kernelcache was pulled, 64 MB instead of 11 GB).
Exploitability is **not** proven — no public PoC exists for these as of
2026-10-20. See `VULNS.txt` §3 for the exact diff and the two attribution
corrections._

## Selected path to kernel R/W

**Not** the AIO track (deferred): the `aio_workq_entry` UAF is proven on device,
but turning it into a write needs a controlled object inside `aio_workq_zonep`
(224 B) and the only spray in the tree is Mach-port based, which never lands in
that zone. Details and the honest status are in `VULNS.txt` §1.

The route in flight is **DCP pipe-limit OOB-write + libxpc sandbox escape**:

1. **DCP (`AppleMobileDispH14P-DCP`) — OOB write, [LIVE].** In iOS 26.3 Apple
   added pipe accounting and a platform limit (`"Platform limits applied %u
   overall limited %u"`, `"Update Ext Pipe state: is_plug %u total count %u limited
   %u Apple Display %u pipes %u"`, counters in `__DATA_CONST +0x668/+0x66c/+0x670`).
   In 26.2 that code does not exist: there is no limit on how many display pipes
   can be created, while 26.3 indexes a fixed array by a vtable-returned count
   (`0x947807c`: `cmp w0,#4` -> bail, then `add x8,x21,w0,uxtw; sub x20,x8,#4`).
   No limit ⇒ create past the array capacity ⇒ OOB write.
2. **CVE-2026-20667 (libxpc) — sandbox escape, [LIVE].** Fixed in 26.3, so
   unpatched on 23C55; "a logic issue was addressed with improved checks" means a
   missing validation. XPC is reachable from any sandboxed app, so this is the
   cheapest new reverse-engineering target. Combined with the already-proven
   WebKit renderer primitive (W-T0/W-T2) it yields native code outside the
   sandbox, which is what makes the entitlement-gated IOKit clients reachable.
3. **CVE-2026-20615 / -20617 (CoreServices → root, [LIVE]).** Csaba Fitzl
   (@theevilbit) and Gergely Kalman; path handling + race condition.
4. **Regression hunting 26.1 → 26.2.** 26.1's kernelcache is now local
   alongside 26.2 and 26.3, and the diff harness is in
   `~/ios262_lab/diff27/` (`regress.py`, `removed_checks.py`, `filter_regress.py`).
   Between 26.1 and 26.2 the kernel lost **107 code paths** and AGXG14P 21.
   A dropped bound check there is a bug nobody has filed, so nobody patched it.

`VULNS.txt` §6 documents the harness and the first results.

## Further fate

1. **DCP pipe path** — find the 26.2 equivalent of 26.3 `0x947807c`, confirm the
   missing bound, then reach the DCP user client from the sandbox and overflow
   the pipe array.
2. **libxpc** — diff the 26.2/26.3 xpc handlers for the added check; XPC is
   callable from a plain app.
3. **Regression sweep** — run `filter_regress.py` over the 107 removed kernel
   code paths (26.1→26.2) looking for `cmp #imm` + branch that became `cbz`.
4. Keep the WebKit pivot chassis (W-T0/W-T2, proven) as the way in.
5. IOGPU 24257 stays documented but closed on 26.2 (the 18.4 fix is present).

## Build

Linux + Theos (no Xcode needed):

```sh
export THEOS=$HOME/theos
./package_ipa.sh                       # builds the app → .ipa (ad-hoc signed)
```

Artifact: `packages/srk801_*.ipa` — ad-hoc (`ldid -S`). Install via
LiveContainer / Sideloadly / AltStore with the app-group sacrifice, then press
**WebKit Stage / IOGPU Probe2 / OOB (24257)** on the Actions page.

## Notes

* Targeted specifically at **iOS 26.2 build 23C55, iPhone 13 (A15)**.
* LiveContainer guest delivery means zero entitlements and a strict call budget
  per run — every probe is written watchdog-safe by design.
* Everything was verified by reading the **kernel binary statically** first
  (llvm-objdump on `~/theos` toolchain on Linux), then confirmed on-device.

## License

[Apache License 2.0](LICENSE) — © 2026 Lightsword contributors.

Use wisely. Research-only; the authors take no responsibility for any misuse
of this codebase.
