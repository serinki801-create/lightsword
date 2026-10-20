import sys, re, json
sys.path.insert(0,'/home/abzal/ios262_lab/spmt/ana')
from sptm import m, INS, func_of, adrp_page, HEX
from capstone import *
import bisect

REFS = {}   # target va -> [(insn_addr, kind, adrp_addr)]
BREAK = {'b','bl','ret','br','blr','cbz','cbnz','tbz','tbnz','b.eq','b.ne','b.hi','b.lo','b.mi',
         'b.pl','b.hs','b.ls','b.ge','b.lt','b.gt','b.le','b.al','svc','b.cond'}
for i, ins in enumerate(INS):
    if ins.mnemonic != 'adrp':
        continue
    page = adrp_page(ins)
    if page is None: continue
    dstreg = ins.op_str.split(',')[0].strip()
    for j in range(i+1, min(i+12, len(INS))):
        i2 = INS[j]
        mn = i2.mnemonic
        if mn == 'add':
            parts = [p.strip() for p in i2.op_str.split(',')]
            if len(parts) == 3 and parts[1] == dstreg:
                mm = HEX.search(parts[2])
                if mm:
                    t = page + int(mm.group(1),16)
                    REFS.setdefault(t, []).append((i2.address, 'add', ins.address))
                    break
        elif mn.startswith('ldr') or mn.startswith('ldur') or mn.startswith('ldrsw') or mn.startswith('ldp'):
            parts = [p.strip() for p in i2.op_str.split(',')]
            if len(parts) >= 2 and ('['+dstreg) in parts[1]:
                mm = re.search(r'#(-?0x[0-9a-f]+|\d+)', parts[1])
                if mm:
                    g = mm.group(1)
                    disp = int(g,16) if g.startswith(('0x','-0x')) else int(g)
                    t = page + disp
                    REFS.setdefault(t, []).append((i2.address, 'mem', ins.address))
                    break
        if mn in BREAK: break

print('resolved targets:', len(REFS), file=sys.stderr)
json.dump({hex(k):v for k,v in REFS.items()}, open('refmap.json','w'))

# strings
cstrs = {}
for seg in m.segments:
    for sec in seg['sections']:
        if sec['name']=='__cstring':
            base=sec['addr']; data=m.d[sec['off']:sec['off']+sec['size']]
            i=0
            while i < len(data):
                j = data.find(b'\0', i)
                if j<0: break
                s = data[i:j].decode('utf-8','replace')
                if len(s)>=3: cstrs[base+i]=s
                i = j+1
ident = re.compile(r'^[a-z_][a-z0-9_]{3,}$')
named = {}
for va, s in cstrs.items():
    if not ident.match(s): continue
    for (a, kind, ad) in REFS.get(va, []):
        f = func_of(a)
        if f is not None and f <= a < f + 0x120:
            named.setdefault(f, s)
            break
json.dump({hex(k):v for k,v in named.items()}, open('func_names.json','w'), indent=0)
print('named functions:', len(named), file=sys.stderr)
for f in sorted(named)[:15]: print(hex(f), named[f])
