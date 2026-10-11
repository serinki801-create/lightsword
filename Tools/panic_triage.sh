#!/bin/bash
# language: bash, file: panic_triage.sh
# T0a — panic-full .ips classifier for the B12 AIO kevent UAF hunt.
# Target: iOS 26.2 / 23C55 / iPhone14,5 / LiveContainer panics.
#
# Usage: panic_triage.sh <panic-full.ips> [<panic-full.ips> ...]
# Output: one line per log: quoted assert, far, esr, verdict class.
#
# Classification rules (per GROOMER T0a):
#   "element modified after free (off:N, val:V...)"  -> WAF  (offset+value printed)
#   "double free" / "element freed twice"           -> FREE-LIST (T4a-direct opens)
#   "data abort" far=0x58  (slot zeroed)            -> UAF-READ-UNRECLAIMED
#   "data abort" far=0x0   (spray marker in regs)   -> UAF-READ-RECLAIMED-CORRUPT
#   "zone require failure"/"element size mismatch"  -> GUARD (adjust spray geometry)

set -u

for f in "$@"; do
    [ -r "$f" ] || { echo "MISSING: $f"; continue; }

    # .ips = two JSON lines: header, body. Pull fields with python (stdlib only).
    out=$(python3 - "$f" <<'PYEOF'
import json, re, sys

path = sys.argv[1]
lines = open(path, encoding='utf-8', errors='replace').read().split('\n', 1)
if len(lines) < 2:
    print("PARSE_ERR\t%s" % path); sys.exit(0)
body = json.loads(lines[1])
ps = body.get('panicString', '')
build = body.get('build', '')

# faulting address + syndrome from the panic header line
far = re.search(r'\bfar:\s*0x([0-9a-fA-F]+)', ps)
esr = re.search(r'\besr:\s*0x([0-9a-fA-F]+)', ps)
far_v = int(far.group(1), 16) if far else None
esr_v = int(esr.group(1), 16) if esr else None

# 0x4141... spray markers live in the register dump
regs = re.findall(r'x\d+:\s*0x([0-9a-fA-F]+)', ps)
marker = any(v.startswith('41414141') and v != '4141' for v in regs)

# panicked process
proc = body.get('Panicked task') or ''
m = re.search(r'pid (\d+): (\S+)', proc) or re.search(r'pid (\d+): ([^\s:]+)', str(body.get('processByPci','')))

# esr EC decode: bits[31:26]
ec = (esr_v >> 26) & 0x3F if esr_v is not None else None
if ec == 0x25:
    ecname = 'INSTR-ABORT (fetch fault; PC is ret+4 for PAC-fail)'
elif ec == 0x24 or ec == 0x26:
    ecname = 'DATA-ABORT'
else:
    ecname = 'EC=0x%x' % (ec if ec is not None else -1)

# classify
if 'element modified after free' in ps:
    cls = 'WAF'
    m2 = re.search(r'off:(\d+), val:(0x[0-9a-f]+)', ps)
    extra = ('  off=%s val=%s' % (m2.group(1), m2.group(2))) if m2 else ''
elif 'double free' in ps or 'element freed twice' in ps:
    cls = 'FREE-LIST'
    extra = ''
elif 'zone require failure' in ps or 'element size mismatch' in ps:
    cls = 'GUARD'
    extra = ''
elif 'being freed while still enqueued' in ps:
    cls = 'AIO-ENQUEUED-ON-FREE'
    extra = ''
elif 'data abort' in ps:
    if far_v == 0x58:
        cls = 'UAF-READ-UNRECLAIMED'   # procp=0 -> aio_proc_lock(&p->p_mlock)=0x58
        extra = ''
    elif far_v == 0:
        cls = 'UAF-READ-RECLAIMED-CORRUPT' + ('-MARKER' if marker else '')
        extra = ''
    else:
        cls = 'DATA-ABORT'
        extra = ''
else:
    cls = 'OTHER'
    extra = ''

print('%s\tfar=0x%x\tesr=0x%08x %s\tmarker_regs=%s\t%s' % (
    cls,
    far_v if far_v is not None else -1,
    esr_v if esr_v is not None else -1,
    ecname,
    'yes' if marker else 'no',
    build.split('|')[0].strip()))
if ec == 0x25:
    print('   instr-abort: ret+4 PC pattern; check x23==-1 (TRASHIT) and signed LR')
if extra:
    print('   asserted: %s' % extra.strip())
PYEOF
)
    echo "== $(basename "$f")"
    echo "$out"
done
