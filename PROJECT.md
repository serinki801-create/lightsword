# PROJECT natsuk1 / lightsword — полный технический дамп

Дата: 2026-10-12. Устройство: iPhone14,5 (iPhone 13, A15 T8110, arm64e), iOS 26.2 build 23C55.
Kernel: xnu-12377.62.10 (источник не опубликован). Delivery: LiveContainer guest, native arm64 IPA.
Репозиторий: github.com/serinki801-create/lightsword (PRIVATE).

---

## 1. ДЛЯ ЧТО СДЕЛАН

Цепочка полного компромитирования устройства с sideloaded-приложения внутри LiveContainer,
БЕЗ веба, БЕЗ Safari, БЕЗ entitlements, БЕЗ серверов:

  WebKit-стейдж (renderer RCE)  ──►  нативный мост  ──►  B12 (kernel UAF)  ──►  data-only root  ──►  semi-untethered jb

Две линии, одна критерий:
- **B12 (нативная, критический путь)** — эксплойт AIO/kevent в ядре → kernel r/w → root.
- **WebKit (доставка, co-primary)** — renderer-экзек в WebContent → нативный пивот → подаёт тот же B12.

---

## 2. СТАТУС ЛИНИЙ

| Линия | Статус |
|---|---|
| LiveContainer delivery | ✅ живой (guest грузится, bundle-ресурсы, мост JS↔C) |
| Crash-обсервабилити (нативная) | ✅ guard RECOVERED, run/phase/HB телеметрия, state-machine |
| B12 — каркас (T1) | ✅ PROVEN (source): aio_return → aio_entry_unref → aio_free_request → zfree; kevent64 reap → filt_aioprocess on stale kn_hook |
| B12 — смещения [VB] | ✅ таблица ниже; p_aio_total_count @ proc+0x47C [VB-DISASM]; p_aio_doneq @ proc+0x5E0 |
| B12 — канал чтения | ✅ PROVEN (каждый выстрел течёт slot VA + ext[1]/ext[0]) |
| B12 — канал ЗАПИСИ | ⚠️ ЕДИНСТВЕННЫЙ кандидат dn_flow_queue (SILVER, гейт dummynet — VERDICT [REACHABLE] by option matrix) |
| IOKit-соседи по 192-бакету | ❌ ВСЕ МЁРТВЫ (полный store-ценз: +0x10/+0x18/+0x30/+0x40 не пишутся ни в одном классе) |
| B12 — T5 root | ⏸ data-only plan готов (proc_ro->p_ucred → cr_posix uid/gid), ptrauth не мешает |
| WebKit W-T0 (fingerprint) | ✅ [VP-DEVICE] баг ПРИСУТСТВУЕТ на 23C55 (round 9–17, 6 независимых прогонов) |
| WebKit W-T1c | ✅ PoC разобран, порт проверен |
| WebKit W-T2 (renderer AAR/AAW) | ✅✅ [VP-DEVICE] двойная верификация: wasm readback + JS-visible (jsSees=true), PASS 16/0, round=10/12 |
| WebKit W-T3 (native pivot) | ⏳ СЛЕДУЮЩИЙ — JIT-hunt → RWX → shellcode маркер в trace.log |
| WebKit W-T5 (aio из renderer) | ⏳ второй шанс на dummynet-гейт (R22) |
| T2 frame probe (1000 раундов) | ⏸ устройство, ПОСЛЕ ребута (R9); 50x паникует ядро (механизм огня живой — PAC/TRASHIT подтверждены) |
| T4 benign fire | ⛔ НЕ начинать: не закрыты предусловия (occupancy-map, fingerprint, TRASHIT-пропагейшн) |

---

## 3. ИСПОЛЬЗУЕМЫЕ УЯЗВИМОСТИ

### 3.1 JSC: MapIterationEntryKey type confusion (WebKit renderer RCE) — АКТИВНА, работает
- Дефект: `Source/JavaScriptCore/dfg/DFGNodeType.h:592` — `macro(MapIterationEntryKey, NodeResultInt32)` — узел доступа к ключу в Map.forEach объявлен 32-битным int'ом; фактически возвращает произвольный NaN-boxed JSValue (может быть heap-указателем).
- Следствие: DFG Store Barrier пропускается для ключа, записанного в tenured-объект → Eden GC собирает объект ключа → UAF → addrof/fakeobj → AAR/AAW.
- Фикс: `3f6f7836068` (commits.webkit.org/308853@main, 2026-03-07) — one-token `NodeResultInt32 → NodeResultJS` + JSTests/stress/map-forEach.js.
- Окно: 23C55 (дек. 2025) старше волны 26.5.2 (июль 2026) → баг ПРИСУТСТВУЕТ, подтверждено на устройстве.
- Публичный PoC: github.com/retX0/safari-26.2-dfg-type-confusion (W-T1c разбор — Docs/webkit_poc_review.md).

### 3.2 CVE-2026-43701 (bug 315004, rdar 177019828, credit Aaron Grattafiori/NVIDIA) — ПОСТ-ЭКСПЛОЙТ ПИВОТ, не реализован
- Sandbox escape: скомпрометированный WebContent заставляет UIProcess скачать data:-URL (байты атакера на диск, без жеста).
- Фикс f23ffb5a84 (2026-07-01): WebPageProxy.cpp +13, APINavigation.h +1, DocumentLoader.cpp +10.
- Статус: зарезервирован как путь записи файла ПОСЛЕ renderer-RCE (не для получения RCE).

### 3.3 CVE-2026-43709 (bug 314398) — GPU-process UAF, ЗАКРЫТА как источник
- ANGLE Metal occlusion query dangling pointer. Фикс 9d2cc8c989 (2026-07-06). Не renderer → не применимо.

### 3.4 B12 kernel UAF (aio_workq_entry × kevent64) — АКТИВНАЯ ОСНОВА
- Frame: aio_return → aio_entry_unref → aio_free_request → zfree, затем kevent64-reap → filt_aioprocess на протухшем kn_hook. Component (iv) активен; (i)(ii)(iii) — не эксплойт-путь; free-list assert не сработал ни разу → double-free steering НЕ канал.
- Симптом на устройстве: слепой remove доводит TRASHIT (-1) в link'и слота; далее poisoned LR → PAC-auth fail → instruction abort (esr 0x96000006, EC=0x25, far=0). x23=-1 sourced to `mov w9,#-1` @ carve 0x146c09c.

### 3.5 Хеджи (не блокируют, однонедельные исследования)
- CVE-2026-43743 IOGPUFamily race — промоут в CRITICAL PATH если dummynet-гейт умрёт (R20).
- CVE-2026-20637 AppleSEPKeyStore — gated on T0e.
- CVE-2026-20700 dyld PAC oracle — HEDGE ONLY (T5 proven data-only).

---

## 4. СМЕЩЕНИЯ (B12, устройство xnu-12377.62.10)

struct aio_workq_entry = 184 B [VB on-device] / slot 192 B [VP]; slack = qword 23 only (0xB8-0xBF); "176B" — dead claim.

  +0x00/+0x08  aio_workq_link
  +0x10/+0x18  aio_proc_link tqe_next/tqe_prev    ← WWW операторы
  +0x20        returnval → kev.ext[1] (64-bit)
  +0x28        errorval  → kev.ext[0] (32-bit)
  +0x2C        aio_refcount
  +0x30        flags (AIO_COMPLETED=0x100, re-arm gate)
  +0x40        procp
  +0x48        uaiocbp
  proc+0x58    p_mlock
  proc+0x47C   p_aio_total_count   [VB-DISASM: ldr w8,[x0,#1148]; sub; str; b.le → panic accounting mismatch kern_aio.c:479]
  proc+0x5E0   p_aio_doneq          [VB-DISASM: 3 независимых сайта]
  lst2 @ proc+0x5D0, panic "Negative total AIO count!" kern_aio.c:476, глобальный счётчик @ vm 0x7a65128
  [AS]: +0x50/+0x58 aiocb copy, +0xA0/+0xA8 vfs_context, +0xA8/+0xB0 aio_map

Важно (R16): ДВА счётчика — per-proc @0x47C И глобальный @0x7a65128; бюджет AIO учитывает ОБА.

---

## 5. КАНАЛ ЗАПИСИ — ЕДИНСТВЕННЫЙ КАНДИДАТ

dn_flow_queue (kalloc.type.192, 184B): C1 +0x10 dst_ip6 (value), C2 +0x18 dst_ip6 (target), C3 +0x30 flow label (AIO_COMPLETED bit), C4 +0x40 = mbuf head (natural, survival через крафт mbuf+0x58=0 и mbuf+0x47C>0; бюджет пакета ≥ 0x480 B).
- Гейт: device option matrix — control opt=250 → ENOPROTOOPT(42); IP_FW3=21 → EINVAL(22) на len32 и len4; getsockopt(IP_FW3) r=0. Итог: **[REACHABLE]** (handler опции 21 существует). Полный pipe-config в силами ещё нет (dn_sess layout НЕ сверен с 62.10).
- IOKit 4 (IOCPU/IOCPUInterruptController/IODTNVRAM/IOPowerConnection): все мёртвы — +0x10/+0x18/+0x30/+0x40 не пишутся (Docs/iokit_field_map.md).
- BRONZE: dn_flow_set, necp_client_flow_reg, nxctl_traffic_rule_inet, nxprov_params — не ведём.

---

## 6. КАК ИСПОЛЬЗОВАТЬ (команды)

    # сборка (всегда через symlink — Theos не ест пути с пробелами)
    cd "/home/abzal/jailbreak 26/Test-main" && bash package_ipa.sh
    # актуальный ipa → Packages/natsuk1_*.ipa, ставить в LiveContainer (удалять гостя!)

    # нативные кнопки: Run Exploit · Slide Only · AIO UAF B1/B2 (10x) · T0e Spike (SEP/dtrace, внутри AppleSEPKeyStore) ·
    # T2 Frame Probe (50x) · T2 Dummynet Probe · Guard Test · Reset Probe State · PAC Oracle A2 · WebKit Stage

    # WebKit: WebKit Stage → страница сама гоняет self-test; кнопки на странице: KILL RENDERER (F1 acceptance), TEARDOWN,
    # Reload (в тулбаре). JS-API: addrof/fakeobj/read64/write64, nk.trigger(), nk.teardown(), nk.killRenderer()

    # ядро-карve: bash Tools/carve_kernelcache.sh  → Artifacts/carve/kernel.carve.macho (VMA==file offset after rebase)
    # panic triage: bash Tools/panic_triage.sh <ips>
    # bucket map: python3 Tools/bucket_map.py <kernelcache> --json

Телеметрия WebKit (что смотреть в Documents/trace.log):
- `[RUN] run=N begin label=...` — релоад/новый контекст = новый N;
- `[HB] hbNN` — heartbeat критической секции (последний перед смертью = место смерти);
- `PHASE=n ENTER/OK/FAIL` — скобки фаз с err+stекфрейм;
- `[WK] FATAL ... webcontent-terminated` + Documents/wk_fatal.txt — смерть рендерера;
- `[DN] ...` — dummynet probe; `RESULT W-T0=` — вердикт DFG-бага; `W-T2 echo` — гейт AAR/AAW.

---

## 7. АРХИТЕКТУРА ПРОЕКТА

    Sources/App/      SwiftUI (AppMain/WebKitStage/UIBridge) — нативный вход + WKWebView-хост (singleton)
    Sources/Core/     exploit core: home, trace, state machine, jsbridge (run/phase телеметрия)
    Sources/Diag/     crash guard (siglongjmp), probe runner (стадии 1-5), T0e spike
    Sources/Probes/   aio_spray (T2 frame), dummynet probe (option matrix)
    Sources/Kernel/   b12_offsets.h, kslide.c (KASLR), write_mechanism.md
    Sources/Legacy/   невычеркнутые, но нев списке: fuzz/hunt
    Docs/             webkit_map.md, webkit_poc_review.md, iokit_field_map.md, fire_log.md, panic_symbolization.md, write_mechanism.md, neighbour_score.md
    Tools/            carve_kc.py, bucket_map.py, panic_triage.sh, recon.py
    Dead/             retired: nk_probe_runner.c.bak (fork — мёртв в LC), Makefile.bak
    Packages/         ipas   Artifacts/ — кернелкеш + carve (см. .gitignore, в репо не идут)

Ключевые уроки (все — операционные):
- FORK в LC-госте мёртв (дочерняя смерть = смерть гостя). Изоляция = sigsetjmp/siglongjmp.
- HOME в LC не экспортится — nk_set_home(NSHomeDirectory()) в onAppear, всё в Documents/.
- WKWebView должен быть singleton'ом; построчный @Published = пересоздание representable = релоад страницы посреди эксплойта.
- WebContent-смерть через fallback-чтение вне живой области = SEGV: любой «произвольный» read требует guard'а диапазона [device-observed JS cage].

---

## 8. ЧТО ДАЛЬШЕ (план)

1. **W-T3 native pivot** (следующий): через read64 hunt JIT/RWX страницы WebContent (через инстансы → скомпилированный wasm-код), write-test маркер-байта, если RWX — shellcode `write("marker") → Documents/trace.log`, перевод управления. Гейт: строка SHELLCODE в trace.log.
2. **W-T5**: из renderer-контекста зонд aio_read + kevent64(EVFILT_AIO) — [CONFIRMED]/[BLOCKED] с errno (R22: второй шанс на dn_flow_queue-гейт).
3. **T2 after reboot**: frame probe 50x → 1000x, occupancy map (24 qword, qword 23 = slack), aiocb +0x50 vs +0x58 [VB].
4. **dummynet**: сверка dn_sess layout на 62.10 (дизасм carve) → полноценный pipe-config → подтвердить C1-C3 readback по ext[1]/ext[0] перед любым огнём.
5. **T4 first benign fire**: целевой скретч-объект, сентинел-запись, ≤2 benign / ≤5 live; оба счётчика в бюджете (R16).
6. **T5 cred substitution**: value-write cr_posix (uid/gid=0) → getuid()==0 + denied-op succeeds.
