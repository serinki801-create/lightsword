import sys, re, struct, bisect
sys.path.insert(0, '/home/abzal/ios262_lab/spmt/ana')
import macho
from capstone import *

MACHO = '/home/abzal/ios262_lab/spmt/sptm.macho'
m = macho.MachO(MACHO)
_sec = [s for seg in m.segments for s in seg['sections'] if s['name'] == '__text'][0]
CODE = m.d[_sec['off']:_sec['off']+_sec['size']]
BASE = _sec['addr']

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.skipdata = True
INS = list(md.disasm(CODE, BASE))
ADDR_OF = {ins.address: i for i, ins in enumerate(INS)}
HEX = re.compile(r'#(0x[0-9a-f]+)')

# ---------- function boundaries (prologue heuristic) ----------
FUNC_STARTS = []
for i, ins in enumerate(INS):
    if ins.mnemonic == 'stp' and ins.op_str.startswith('x29, x30, [sp, #'):
        FUNC_STARTS.append(ins.address)
    elif ins.mnemonic == 'pacibsp':
        FUNC_STARTS.append(ins.address)
    elif ins.mnemonic == 'sub' and ins.op_str.startswith('sp, sp, #'):
        FUNC_STARTS.append(ins.address)
FUNC_STARTS = sorted(set(FUNC_STARTS))

def func_of(addr):
    i = bisect.bisect_right(FUNC_STARTS, addr) - 1
    return FUNC_STARTS[i] if i >= 0 else None

def func_end(addr):
    i = bisect.bisect_right(FUNC_STARTS, addr)
    return FUNC_STARTS[i] if i < len(FUNC_STARTS) else None

# ---------- adrp page table + ref resolution ----------
PAGE = {}   # instr addr -> (reg, page)

def adrp_page(ins):
    mm = HEX.search(ins.op_str)
    return int(mm.group(1), 16) if mm else None

def refs_to(target, win=12):
    """return [(insn_addr, kind, adrp_addr)] referencing `target`"""
    out = []
    for i, ins in enumerate(INS):
        if ins.mnemonic != 'adrp':
            continue
        page = adrp_page(ins)
        if page is None:
            continue
        if not (target & ~0xfff) == page and (page & ~0xfff) != (target & ~0xfff):
            continue
        dstreg = ins.op_str.split(',')[0].strip()
        for j in range(i+1, min(i+win, len(INS))):
            i2 = INS[j]
            if i2.mnemonic == 'add':
                parts = [p.strip() for p in i2.op_str.split(',')]
                if len(parts) == 3 and parts[1] == dstreg:
                    mm = HEX.search(parts[2])
                    if mm and page + int(mm.group(1), 16) == target:
                        out.append((i2.address, 'adrp+add', ins.address))
                        break
            elif i2.mnemonic in ('ldr', 'ldrsw', 'ldrh', 'ldrb', 'ldur', 'ldp', 'ldr x', 'ldrsb'):
                parts = [p.strip() for p in i2.op_str.split(',')]
                if len(parts) >= 2 and '[' + dstreg in parts[1]:
                    mm = re.search(r'#(-?0x[0-9a-f]+|\d+)', parts[1])
                    if mm:
                        disp = int(mm.group(1), 16) if mm.group(1).startswith(('0x','-0x')) else int(mm.group(1))
                        if page + disp == target:
                            out.append((i2.address, 'adrp+mem', ins.address))
                            break
            if i2.mnemonic in ('b','bl','ret','br','blr','cbz','cbnz','tbz','tbnz','b.eq','b.ne',
                               'b.hi','b.lo','b.mi','b.pl','b.hs','b.ls','b.ge','b.lt','b.gt','b.le','b.al','svc'):
                break
    return out

def string_addr(name):
    for s in m.segments:
        for sec in s['sections']:
            if sec['name'] == '__cstring':
                base = sec['addr']; data = m.d[sec['off']:sec['off']+sec['size']]
                idx = data.find(name.encode()+b'\0')
                if idx >= 0:
                    return base+idx
    return None

def dump(addr, maxins=300, until_ret=True):
    i = ADDR_OF.get(addr)
    if i is None: return f'no insn at {addr:#x}'
    out = []
    for ins in INS[i:i+maxins]:
        out.append(f'{ins.address:#x}:\t{ins.mnemonic}\t{ins.op_str}')
        if until_ret and ins.mnemonic == 'ret':
            break
    return '\n'.join(out)

def cstring(addr):
    return m.cstr_at(addr)

if __name__ == '__main__':
    cmd = sys.argv[1]
    if cmd == 'ref':
        arg = sys.argv[2]
        t = int(arg, 16) if arg.startswith('0x') else string_addr(arg)
        if t is None:
            print('not found'); sys.exit(1)
        print(f'[+] {arg} @ {t:#x} = {cstring(t)!r}')
        for (a, kind, ad) in refs_to(t):
            f = func_of(a)
            print(f'  ref {a:#x} ({kind}) func {f and hex(f)} .. {func_end(f) and hex(func_end(f))}')
    elif cmd == 'func':
        a = int(sys.argv[2], 16)
        print(dump(a, int(sys.argv[3]) if len(sys.argv) > 3 else 300))
    elif cmd == 'range':
        lo, hi = int(sys.argv[2], 16), int(sys.argv[3], 16)
        for ins in INS:
            if lo <= ins.address < hi:
                print(f'{ins.address:#x}:\t{ins.mnemonic}\t{ins.op_str}')
    elif cmd == 'str':
        pat = sys.argv[2]
        for s in m.segments:
            for sec in s['sections']:
                if sec['name'] == '__cstring':
                    base = sec['addr']; data = m.d[sec['off']:sec['off']+sec['size']]
                    for mm in re.finditer(pat.encode(), data):
                        print(hex(base+mm.start()), mm.group().decode('utf-8','replace'))
