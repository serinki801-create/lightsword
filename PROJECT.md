# PROJECT srk801 / lightsword — полный технический дамп

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
| B12 — канал ЗАПИСИ | ❌ **МЁРТВ** (док-во 4.4.4: 21 зонный сосед, ни один не даёт controlled +0x10/+0x18; blind-remove = list surgery) |
| IOKit-соседи по 192-бакету | ❌ ВСЕ МЁРТВЫ + zone-seqr док-зано (kc.bin дизасм, реестр Artifacts/kalloc_type_registry.json) |
| B12 — T5 root | ⏸ data-only plan готов (proc_ro->p_ucred → cr_posix uid/gid), ptrauth не мешает |
| WebKit W-T0 (fingerprint) | ✅ [VP-DEVICE] баг ПРИСУТСТВУЕТ на 23C55 (round 9–17, 6 независимых прогонов) |
| WebKit W-T1c | ✅ PoC разобран, порт проверен |
| WebKit W-T2 (renderer AAR/AAW) | ✅✅ [VP-DEVICE] + РЕТРАЙ v128-leak (device 17:49: две неудачи взвода — v128-leak-failed (hb4) и wt0=ABSENT (детектор 550 раундов); авто-релоад отработал штатно (run3 через 3с); 17:54 build: leak-скан 3 пасса со свежими container/structArr) |
| WebKit W-T3 (native pivot) | ✅✅ FINGERPRINT НА УСТРОЙСТВЕ + page-major sweep + dead-slot петля (device 21:59: run1 умер посреди plan-строки (5 списков, ~1.5KB одним bridge-message — C-буферы 512B); 22:02 фикс: план построчно с дренажем, run2 прошёл sweep целым; 22:10 аудит: GETDEAD никто не слал — dead-list всегда пуст; 22:12 roundtrip по образцу claim; 14:58 PHASE 2 mprotect: stage-1 на сайте делает mprotect(RWX)+br, payload живёт в scratch-странице — потолок 256B снят, юнит native-pivot-mprotect) |
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
- CVE-2026-43743 IOGPUFamily race — ЗАКРЫТА как источник (нет точки входа из sandbox).
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
    # актуальный ipa → Packages/srk801_*.ipa, ставить в LiveContainer (удалять гостя!)

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

1. **W-T3 native pivot** — СОБРАН 2026-10-12, АВТО-ЦЕПОЧКА на арм-состоянии триггера (`nkAutoPivot` в exploit.js: кнопка больше не нужна, `window.__wt3Auto=false` выключает, защёлка на один арм): magic-модуль (i64-цепочка, 192 пара, MAGIC=0xB1C2D3E4F5A607B8) → hunt v3 ищет movz-иммидиат ИЛИ литерал MAGIC в кодовом маппинге (без фикс-офсетов) → byte write-test → inline-hook 256B → shellcode: marker + open/write/close trace.log (путь из C-моста GETPATH) + трамплин на site+256. Гейт: строка SHELLCODE в trace.log; вторичный: marker-qword в scratch. Device 21:44 + 21:57: armed оба раза, ECHO OK, hunt пока мимо — v3 вводит BFS L0/L1/L2 (module/fn/magic-instance приоритет, второй уровень косвенности module→Code→jumpTable, интерьер-указатели из C++-тел) и литерал-фингерпринт. Re-call экспорта ре-ранит шеллкод (хук однонаправленный, без self-restore). Риски на устройстве: icache-когерентность JIT-страниц (retry x3), детали — Docs/webkit_map.md §8.
2. **W-T5**: из renderer-контекста зонд aio_read + kevent64(EVFILT_AIO) — [CONFIRMED]/[BLOCKED] с errno (R22: второй шанс на dn_flow_queue-гейт).
3. **T2 after reboot**: frame probe 50x → 1000x, occupancy map (24 qword, qword 23 = slack), aiocb +0x50 vs +0x58 [VB].
4. **dummynet**: сверка dn_sess layout на 62.10 (дизасм carve) → полноценный pipe-config → подтвердить C1-C3 readback по ext[1]/ext[0] перед любым огнём.
5. **T4 first benign fire**: целевой скретч-объект, сентинел-запись, ≤2 benign / ≤5 live; оба счётчика в бюджете (R16).
6. **T5 cred substitution**: value-write cr_posix (uid/gid=0) → getuid()==0 + denied-op succeeds.

### 4.1 B12 — прямой дизассемблер device KC + зоны kalloc_type (2026-10-14 18:54)
kc.bin декомпрессирован (ipsw, bvx2 -> 64.5MB Mach-O); из __DATA_CONST вытащен
реестр kalloc_type (2525 view). Канал записи подтверждён в прямом дизассемблере
62.10 (aio_proc_remove_done_locked @ 0xFFFFFFF008478060: `str x8,[x9]` — слепой
write B, `str xzr,[x10]` — TRASHIT; procp+0x47C p_aio_total_count и
p_aio_doneq.tqh_last @ procp+0x5E8 — по immediates). T3 закрыт с доказательством:
21 тип делит зону aio_workq_entry (сигнатура 11112221122222222222111), ни один
не даёт user-controlled +0x10/+0x18, из песочницы спамmable только сам aio =>
канал записи через blind TAILQ_REMOVE value-control НЕ имеет. Детали и таблица
соседей — Docs/b12_t3_zones.md, реестр — Artifacts/kalloc_type_registry.json.

### 4.2 B+ — CVE-2026-64788 PoC интегрирован; реестр kalloc.256 для cross-type (2026-10-14 20:29)
Шаг 1 (интеграция PoC): `Sources/Legacy/iogpu_uaf64788.m` — полный PoC
bytev0rtex (Metal newTextureWithDescriptor:iosurface:, 1x65535 overflow,
KDALLOC.256 spray 0x300 x MTLBuffer(0x100), return-code oracle
0xe00002c2 -> 0xe0002be) + обёртка `nk_iogpu_uaf_run()`, кнопка
**IOGPU UAF 64788**, Metal/IOSurface в Makefile. Билд
srk801_20261014-202911.ipa.
Шаг 2 (статический реестр): kalloc.256-class = 33 types. Кандидаты
cross-type под zone-seqr: `AppleBasebandPCIControlUserClient (256)`,
`IONetworkUserClient (248)`, `IOStreamUserClient (248)`, `IOUserUserClient (248)`,
`struct socket_filter (248)` — userclient-классы с callback-указателями,
reachable из sandbox. Дампинг указателей — по 23C55-коду каждого.

### 4.3 CVE-2026-64788 НЕ уязвим на 23C55 — доказано (2026-10-14 21:10)
PoC интегрирован и прогнан на iPhone 13 / iOS 26.2 / A15:
conn открыт (IOServiceOpen type=1 из песочницы — entitlement не нужен),
Metal-триггер создал текстуру 1x65535, но stale-ID нет (sweep 1..4096:
processed=0). Статика объяснила: валидатор dimensions в 129.3.2 стоит
ДО вставки ресурса — @ 0xfffffff009f4e5c0: `cmn w2,w4; b.cs → error`
+ `adds w24,w3,w4; b.cs → error` → error-ветка = log + retab(0xe00002c2),
без аллокации и без табличной записи. Уязвимая форма (вставка, потом
проверка без release) есть в 26.6/23G71, куда писался PoC.
Похоже, 129.3.2 уже содержит раннюю форму этого fix'а.
Вывод: CVE-2026-64788 закрыт на 23C55. Возврат к WebKit-линии
(pivot armed) как единственному рабочему вектору + hold на
IOGPU 130.13/130.14 (26.4/26.5) как на версии без этого порядковаый fix'а.

---

## 4.4 СТАТУС НА 2026-10-15 17:55 — после IOGPU-исследования и возврата в веб

### 4.4.1 ЦЕЛЬ И ОСЬ
- Устройство: iPhone13 (iPhone14,5, A15 T8110, arm64e), **iOS 26.2 build 23C55**.
- Kernel: xnu-12377.62.10, IOGPUFamily **129.3.2**, AGXG14P 342.3.
- Delivery: LiveContainer guest, IPA. Entitlements: **НЕТ** (sandbox app).
- Конечная цель: kernel read/write → data-only root (proc_ro->p_ucred).

### 4.4.2 КАКИЕ БАГИ ИСПОЛЬЗУЮТСЯ
| Баг | Где | Статус на 23C55 |
|---|---|---|
| JSC MapIterationEntryKey type confusion | DFG-узел объявлен Int32, возвращает JSValue → UAF → addrof/AAR/AAW | ✅ **РАБОТАЕТ** [VP-DEVICE], W-T0 confirmed 9+ прогонов |
| B12 aio_workq_entry × kevent64 | ядерный UAF aio/proc link | ⚠️ frame PROVEN, запись **МЁРТВА** (док-во ниже) |
| CVE-2026-64788 IOGPUFamily UAF (dimensions) | create_resource_iosurface без release при overflow | ❌ **НЕ УЯЗВИМ**: валидатор стоит ДО вставки (@0xfffffff009f4e5c0) |
| CVE-2025-24257 IOGPUFamily bitmap underflow | (capacity>>6)-1 без проверки ≥64 | 🔶 **БАГ В КОДЕ ЕСТЬ**, но из sandbox **НЕ ДОСТИЖИМ** (см. 4.4.5) |
| CVE-2026-43743 IOGPUFamily race | — | ❌ закрыта как источник (нет точки входа) |

### 4.4.3 ЧТО РАБОТАЕТ (доказано на устройстве)
1. **WebKit W-T0** — DFG-баг присутствует,round 9–17, 6 независимых прогонов.
2. **WebKit W-T2** — renderer AAR/AAW: `read64/write64` через wasm-global commutation, двойная верификация JS↔native. ECHO OK на устройстве.
3. **WebKit W-T3 цепочка** — собрана полностью: magic-module (192 пара) → hunt (page-major sweep) → byte write-test → inline-hook 256B → shellcode (marker + open/write/close trace.log). **Armed=yes дважды** (device 21:59 / 16:40), hunt доходит до sweep.
4. **Статический инструментарий** — kc.bin декомпрессирован (ipsw bvx2 → 64.5MB Mach-O), реестр kalloc_type (2525 view) извлечён, дизассемблер настроен (aarch64-linux-gnu-objdump / llvm-objdump-18), патентован обход chained-pointer'ов (top16 0x8011/0x8021 + low32 = parent __TEXT_EXEC file offset).

### 4.4.4 ЧТО МЁРТВО (с док-вами)
**B12 канал записи — МЁРТВ.** Прямой дизассемблер device KC:
- `aio_proc_remove_done_locked` @ 0xFFFFFFF008478060: `str x8,[x9]` (слепой write B) + `str xzr,[x10]` (TRASHIT) — frame живой.
- Но value-control невозможен: **21 тип делит зону aio_workq_entry** (сигнатура `11112221122222222222111` = kalloc_type zone-sharing key). Ни у одного нет user-controlled +0x10/+0x18.
- `dn_flow_queue`: +0x18 = `mbuf*` (kernel), не выбранный адрес; +0x10 = proto byte. Из песочницы не аллоцируется (нужен ipfw).
- Единственный sandbox-reachable зонный сосед = сам aio_workq_entry, чьи +0x10/+0x18 = kernel list pointers.
- Итог: blind TAILQ_REMOVE даёт **list surgery, не arbitrary write**.
- Реестр: `Artifacts/kalloc_type_registry.json`, таблица: `Docs/b12_t3_zones.md`.

**CVE-2026-64788 — НЕ уязвим на 23C55.** PoC прогнан: conn open OK, Metal texture 1×65535 created, но stale-ID=0 на sweep 1..4096. Статика: валидатор dimensions стоит ДО вставки ресурса (error-ветка = log + retab без аллокации). Уязвимая форма — в 26.6/23G71.

### 4.4.5 CVE-2025-24257 — БАГ ЕСТЬ, ДОСТУПА НЕТ
Полная цепочка создания группы (всё дизассемблером):
```
dispatch@0xfffffff007e669b8  (24B: {fn, fn2, inScalar, inStruct, outScalar})
  fn = 0xfffffff009f541ec    ← хендлер создания группы, inScalar=0 inStruct=0 outScalar=0
   └─ 0xfffffff009f56df4 ── 0xfffffff009f7314c ── 0xfffffff009f60a84
        = IOGPUResource::newResourceGroup(dev, ?, capacity)
        · проверка ТОЛЬКО "степень двойки" (0x9f61028) — 1,2,4,8,16,32 проходят
        └─ 0xfffffff009f611ec = IOGPUGroupMemory::init
             0x9f612a4: lsr w9,w21,#6 ; sub w9,w9,#1 ; str [obj+40]   ← БАГ: cap<64 → 0xFFFFFFFF
cleanup (vtable slot[1]) @ 0xfffffff009f5f084
     bound = [obj+40]; for group_idx 0..bound:
         arrayC[(group_idx<<6)+bucket] → ldr + str xzr                  ← OOB read/write ×32GB
```
**Почему не достижимо:** dispatch-запись с этим хендлером принадлежит user-client классу,
который **не открывается** из sandbox: `IOServiceOpen("IOGPU", task, 1)` и `33` — единственные
живые типы; селекторный свип 0..95 на обоих даёт одинаковый `0xe00002c2`. Запись с
`inScalar=0/inStruct=0` означает, что движок отсекает любой scalar/struct ДО хендлера.
PoC Wang Yu'я использовал `init_type=5` — на 23C55 type 5 **не открывается**.

### 4.4.6 ЧТО ОСТАЛОСЬ ДО KERNEL R/W
Порядок по réalisme:
1. **W-T5 (aio из renderer)** — если pivot добьёт сайт, aio_read + kevent64(EVFILT_AIO)
   из WebContent даёт второй шанс на dn_flow_queue-гейт. Статус: ⏳.
2. **IOGPU из WebContent** — WebContent GPU-entitled (WebGL/ANGLE active per fingerprint).
   Если pivot работает, `IOServiceOpen(IOGPU, type 5)` из рендерера должен ПРОХОДИТЬ →
   dispatch@0xfffffff007e669b8 достижим → CVE-2025-24257 стреляет OOB. **Это самый
   прямой путь к kernel r/w, но он заперт за W-T3.**
3. **Свой user client** — найти класс, владеющий 1-entry таблицей @0xfffffff007e669b8.
   Требует: парсинг __mod_init_func kext'а + metaclass-строк. Не начато.

### 4.4.7 БЛИЖАЙШИЙ ШАГ
Один чистый device-прогон, где hunt ловит код-сайт → W-T3 shellcode-гейт (`SHELLCODE` в
trace.log / `WT3-PHASE2 SHELLCODE PASS marker=0x5a5aa15a5a5aa15a canary=0x4d50525850`).
После этого — W-T5 и/или IOGPU-from-WebContent. Всё остальное (B12, 64788) закрыто.

### 4.4.8 ДОБАВЛЕННЫЕ УЯЗВИМОСТИ (2026-10-14/15)
- CVE-2026-64788 (IOGPUFamily UAF, bytev0rtex PoC) — интегрирован, прогнан, **НЕ уязвим на 23C55**.
- CVE-2025-24257 (IOGPUFamily bitmap underflow, wh1te4ever PoC + Wang Yu разбор) — статически подтверждён в 129.3.2, **не reachable** (см. 4.4.5).
- CVE-2026-28992 IOHIDFamily race / CVE-2026-43668/43684/43686 / CVE-2026-43810 — отслеживаются, PoC публично недоступен.

### 4.4.9 CVE-2025-24257 — ТУПИК ИЗ SANDBOX (2026-10-15 18:10, доказано)

Полная попытка достичь группового OOB из app-sandbox'а — **завершена тупиком**:

1. **Dispatch-таблица** группы найдена: @ `0xfffffff007e668b0`, 12+ методов,
   запись 24 байта = `{chained fn; chained fn2; u32 inScalar; u32 inStruct; u32 outScalar}`.
   Групповой создатель = **селектор 11**, `fn=0xfffffff009f4e0bc`, `inScalar=0 inStruct=0 outScalar=0`.
2. **Эмпирический поиск клиента**: 1094 сервиса реестра перечислены, **99 открыты**,
   у каждого открытого пробиты селектор 11 (нулевая форма) и все типы 1..8.
   **Итог: sel11-hits=0.** Таблица @0xfffffff007e668b0 не принадлежит ни одному
   открываемому из sandbox клиенту.
3. **type=1 (IOGPUDeviceUserClient)** — селектор 8 живой, но его хендлер
   `0xfffffff009f4e700` — это **query** (сумма размеров через `[x0+176]`/`[x0+184]`,
   рабочий вызов `0xfffffff009f81c28`), отказая ветка @0x9f4e82c → `0xe00002be`.
   Не групповой путь.
4. **type=33 (IOGPUMemoryInfoUserClient)** — открывается, но молчит на всех
   селекторах 0..23 с любым payload'ом.
5. PoC Wang Yu'я использовал `init_type=5` — **на 23C55 type 5 НЕ открывается**
   (живы только 1 и 33).

**Вывод: CVE-2025-24257 на 23C55 статически присутствует (init @0xfffffff009f612a4),
но его dispatch-вход принадлежит классу, недостижимому из sandboxed-приложения.**
Примитив OOB из приложения получить НЕЛЬЗЯ.

**Единственный путь к нему — через WebKit-пивот**: WebContent GPU-entitled
(WebGL/ANGLE активны per fingerprint), `IOServiceOpen(IOGPU, 5)` оттуда должен
проходить → dispatch@0xfffffff007e668b8 (sel=11) достижим → `capacity=1` →
`[obj+40]=0xFFFFFFFF` → cleanup @0xfffffff009f5f084 уводит петлю
`arrayC[(group_idx<<6)+bucket]` в **OOB read/write на 32GB**.

**Следовательно OOB-примитив и kernel r/w — оба заперты за W-T3.**
Ближайшее действие: WebKit-ран, в котором hunt ловит код-сайт.

### 4.4.10 «Свой user client» ЗАКРЫТ СТАТИЧЕСКИ (2026-10-17 10:40)

§4.4.6 item 3 («найти класс, владеющий 1-entry таблицей @0xfffffff007e669b8;
требует парсинг __mod_init_func + metaclass-строк; не начато») — начат и
закрыт за один проход, отрицательным результатом. Три статических скана по
полному 64МБ образу (`Artifacts/carve/kernelcache.release.iPhone14,5`,
VA = fileoff + 0xFFFFFFF007004000):

1. ADRP+ADD-пары на таблицу: adrp → страница 0xFFFFFFF007E66000,
   add-imm ∈ {0x8b0, 0x9b8, 0x9c0} — **0 пар по всему образу**.
   Контроль корректности метода: тот же adrp-скан по той же странице даёт
   644 референса; на смещение LDR #0x648 — 389hit'ов (горячий глобал-флаг),
   семейство #0x638/#0x5f8/#0x678/#0x610 — соседние флаги IOGPU.
2. ADRP+LDR (adrp; ldr xN,[ page,#0x8b0/0x9b8/0x9c0]) — **0**.
3. Данные: сырые qword (0xFFFFFFF007E668B0 / 0xFFFFFFF007E669B8) и
   chained-энкодинги (low32 = fileoff цели: 0x00e628b0/0x00e628a8/
   0x00e629b8/0x00e629b0/0x00e629c0) — **0 слотов в любом сегменте**
   (скан по каждым 4 байтам, fileoff 0x8000..0x3D80000).

**Вывод (камень): блок @0x…68b0..0x…69b8 НЕ ДИСПЕТЧИРУЕТСЯ. Ни код, ни
данные образа на него не ссылаются → «свой user client» через этот блок
невозможен по построению.** Эмпирика §4.4.9 (99 открытых сервисов ×
selector 11 = 0 попаданий) теперь объясняется не «тип не открывается», а
фактической несвязностью блока.

Подтвердающий, НЕ load-bearing (пере-выводимо): словарь символов
(symbols_all, /tmp/kc262 — утрачен на reboot, пересобирается `nm`-style);
`vtable for IOGPUVirtualMemory` @0x…68a8 и MetaClass-vtable @0x…69e0
ограничивают блок — он интерьер C++ vtable IOGPUVirtualMemory (слоты 32-36:
fn→0x9F4E0BC, fn2→0x9F4AFB0 — IOGPU-код; соседние слоты — XNU __TEXT_EXEC
generic OSObject-методы, согласуется с §2 Docs/iokit_field_map.md).
Раскладка «24 байта = {fn, fn2, inScalar, inStruct, outScalar}» из §4.4.5
— артефакт: в этом блоке нет закромлённых u32-полей, каждый 8-байтовый
слот — chained fixup на код.

Открытые вопросы после закрытия:
- Какой живой вход ветвляет в group-creator (0x9F4E0BC→…→0x9F60A84,
  §4.4.5-цепь) — псевдотаблица не даёт ответа; хозяин диспетчеризации
  должен определяться runtime-sweep'ом из WebContent (как §4.4.9, item 2),
  статический «поиск владельца» снят с плаша.
- IOGPUVirtualMemory сам по себе без единого референса на свой vtable —
  класс может быть вырезан/деадкожен в этой сборке; если он вырезан, то
  и слоты его vtable — мертвовес, что согласуется с нулём ссылок.

Поправка к «cmdовскому» весу §4.4.9: эмпирика осталась в силе, но
интерпретация («таблица принадлежит не-открываемому клиенту») заменена:
блок не принадлежит НИКАКОМУ открышему клиенту, т.к. не подключён ни к
чему. §4.4.6 item 3 → DEAD. Критический путь не меняется: W-T3 пивот →
WebContent; OOB-диспетчеризация там — по результатам новой части.

### 4.4.11 Кандидат #4 (vm_fault_copy busy-page race) — снят по источнику (2026-10-17)

Дзен-разбор DJ-сессии: REPORT-23C55 #1-#8. DJ-вердикт «потолок низкий» подтверждён
исходником 61.12→81.4, панель:

- Окно 62.10: vm_fault_copy vm_fault.c:7837-7928 — последняя dst_object-лок-пара
  (:7849-7861, проверка vo_copy) дропается ДО физической записи
  (:7868-7928: vm_page_part_zero_fill / vm_page_part_copy / vm_page_zero_fill /
  vm_page_copy — pmap_copy_page / pmap_copy_part_page через transient KVA aperture).
  Состояние dst_page (vmp_busy / vmp_cleaning / iopl_wired / frame type) не
  перепроверяется — признана дропнутой нить.
- 81.4 фикс (vm_fault.c ~7858 diff): (a) recheck dst_page->vmp_busy после дропа →
  teardown + continue (livelock-safe, comment: vm_fault_page подождёт unbusy);
  (b) re-verify vmp_iopl_wired → KERN_MEMORY_ERROR, vmp_cleaning → vm_page_sleep;
  (c) CONFIG_SPTM: PMAP_PAGE_IS_USER_EXECUTABLE → pmap_disconnect_options(
  ..., PMAP_OPTIONS_RETYPE) «Consumers ... will be forced to re-fault ... 
  re-validate it for codesigning»;
  (d) dst_object-лок ДЕРЖИТСЯ через копию (SET_PAGE_DIRTY без unlock/relock) —
  основное устранение окна; full-page копия переведена на vm_page_part_copy.
- Замки в записи (vm_resident.c:6998/7050): vm_page_is_restricted panic обе
  стороны; vm_page_copy CS-валидация при code_signed src; MTE-tag паника
  untagged→tagged.
- Attacker-model: триггер = mach_vm_read / vm_copy / mach_msg OOL — полностью
  sandbox-легально, НО жертва = чистый dst_object (свежий при vm_map_copyout
  vm_map.c:11359 или keep-existing при copyin-оверхайте vm_map.c:11871) —
  входящий OOL буфер, не kernel-структура. Restricted-page = panic;
  exec-фрейм = SPTM aperture сам энафорит тип («physical aperture mapping is
  write-protected» — фикс-коммент) → в 62.10 это panic-DoS, не corrupted write;
  cross-task через "пережившие" маппинги нет — free-list фрейм отдаётся без
  extant pmap mappings (disconnect = hygiene после retype, не вешать атаку).
- Статус: CLOSED, на device-log не ставить. Если aperture писать можно при
  несовпадении frame_type → баг SPTM-firmware, другая категория.

---
