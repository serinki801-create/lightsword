"""Find checks that were REMOVED between two builds.

For every code path present in OLD but not NEW, find the NEW function with the
longest common mnemonic prefix and report the divergence point: that is where
the removed check lived. The cmp immediate at the divergence is the bound that
stopped being enforced.
"""
import sys, os, hashlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from macho import Image
from regress import func_starts


def inventory(path):
    I = Image(path)
    ins = I.disasm()
    fs = func_starts(path)
    byaddr = {x.address: i for i, x in enumerate(ins)}
    out = {}
    for k in range(len(fs) - 1):
        st, en = I.text_base + fs[k], I.text_base + fs[k+1]
        i = byaddr.get(st)
        if i is None:
            continue
        seq = []
        body = []
        for m in range(i, len(ins)):
            if ins[m].address >= en:
                break
            seq.append(ins[m].mnemonic)
            body.append(ins[m])
        if len(seq) < 6:
            continue
        h = hashlib.sha1(' '.join(seq).encode()).hexdigest()[:16]
        out[h] = (st, en, seq, body)
    return out


def lcp(a, b):
    n = 0
    while n < min(len(a), len(b)) and a[n] == b[n]:
        n += 1
    return n


def report(kext, old_dir, new_dir, limit=40):
    op = os.path.join(old_dir, kext)
    np = os.path.join(new_dir, kext)
    if not (os.path.exists(op) and os.path.exists(np)):
        return
    A = inventory(op)
    B = inventory(np)
    gone = [h for h in A if h not in B]
    if not gone:
        return
    print(f'\n=== {kext}: {len(gone)} removed code paths ===')
    bitems = list(B.values())
    shown = 0
    for h in gone:
        st, en, seq, body = A[h]
        # best match in NEW by common prefix
        best = None
        bestn = 0
        for v in bitems:
            n = lcp(seq, v[2])
            if n > bestn:
                bestn = n
                best = v
        if best is None or bestn < 8:
            print(f'  [no close match] old {st:#x}..{en:#x} ({en-st} B)')
            continue
        # divergence point in OLD
        d = bestn
        old_ctx = [f'{z.mnemonic} {z.op_str}' for z in body[d:d+8]]
        new_ctx = [f'{z.mnemonic} {z.op_str}' for z in best[3][d:d+8]]
        print(f'  old {st:#x} ({en-st} B)  ->  new {best[0]:#x} ({best[1]-best[0]} B)  diverges at insn #{d}')
        print(f'     OLD: {" | ".join(old_ctx)[:180]}')
        print(f'     NEW: {" | ".join(new_ctx)[:180]}')
        shown += 1
        if shown >= limit:
            break


if __name__ == '__main__':
    old_dir, new_dir = sys.argv[1], sys.argv[2]
    kexts = sys.argv[3:] or ['com.apple.AGXG14P', 'com.apple.kernel']
    for k in kexts:
        try:
            report(k, old_dir, new_dir)
        except Exception as e:
            print(k, 'ERR', e)
