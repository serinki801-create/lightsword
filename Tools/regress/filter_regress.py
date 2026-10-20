import sys, os, hashlib, re
sys.path.insert(0,'.')
from macho import Image
from regress import func_starts
from removed_checks import inventory, lcp

def classify(old_ctx, new_ctx):
    """OLD: cmp + b.ls/b.hs   NEW: cbz/cbnz  => check weakened"""
    o = ' '.join(old_ctx[:4])
    n = ' '.join(new_ctx[:4])
    old_cmp  = re.search(r'cmp\s+\w+, #(\S+)', o)
    old_br   = re.search(r'\b(b\.(?:ls|hs|hi|lo|eq|ne))', o)
    new_cbz  = re.search(r'\b(cb[zn])\b', n)
    if old_cmp and old_br and new_cbz:
        return f'WEAKENED: old "{o}" -> new "{n}"'
    if old_cmp and old_br and not new_cbz:
        return f'CHECK-DROPPED?: old "{o}" -> new "{n}"'
    return None

for kext in sys.argv[3:]:
    A = inventory(os.path.join(sys.argv[1], kext))
    B = inventory(os.path.join(sys.argv[2], kext))
    gone = [h for h in A if h not in B]
    if not gone: continue
    bitems = list(B.values())
    for h in gone:
        st, en, seq, body = A[h]
        best, bestn = None, 0
        for v in bitems:
            n = lcp(seq, v[2])
            if n > bestn: bestn, best = n, v
        if best is None or bestn < 10: continue
        d = bestn
        oc = [f'{z.mnemonic} {z.op_str}' for z in body[d:d+4]]
        nc = [f'{z.mnemonic} {z.op_str}' for z in best[3][d:d+4]]
        r = classify(oc, nc)
        if r:
            print(f'{kext}  old {st:#x} -> new {best[0]:#x}  @{d}')
            print(f'    {r}')
