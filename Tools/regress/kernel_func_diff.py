#!/usr/bin/env python3
"""kernel_func_diff.py -- function-level diff of two carved com.apple.kernel images.

WHY THIS TOOL
--------------
The kernel has no symbol table (stripped), so a byte diff of com.apple.kernel
between 26.2 (23C55) and 26.3 (23D127) tells nothing about WHERE the security
fix landed. LC_FUNCTION_STARTS survives stripping, so we can recover function
boundaries and compare functions by content.

ALGORITHM
  1. parse the carved Mach-O: segments (vmaddr/fileoff), LC_FUNCTION_STARTS
     (ULEB deltas accumulate from the __TEXT segment base);
  2. disassemble every function with capstone, build a content signature
     (mnemonic sequence + operand shape);
  3. match OLD<->NEW by signature; identical functions are "unchanged";
  4. for the rest, find the best NEW partner by longest-common-subsequence
     ratio over the mnemonic stream and report the exact divergence point;
  5. classify the change: NEW-CHECK (26.3 adds a compare/branch that 26.2
     did not have), NEW-REF, DELETED, ADDED.

USAGE
  python3 kernel_func_diff.py <old.macho> <new.macho> [report.txt]
    --min-ratio F   similarity required to pair a changed function (0.5)
    --only-checks   print only NEW-CHECK / DELETED / ADDED pairs
"""
import struct
import sys
import difflib

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
except ImportError:
    sys.exit('need capstone: pip install capstone')

LC_SEGMENT_64 = 0x19
LC_FUNCTION_STARTS = 0x26

MD = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
MD.skipdata = True


def uleb(d, off, size):
    out = []
    addr = 0
    end = off + size
    while off < end:
        val = 0
        sh = 0
        while True:
            b = d[off]
            off += 1
            val |= (b & 0x7F) << sh
            if not (b & 0x80):
                break
            sh += 7
        if val == 0:
            break
        addr += val
        out.append(addr)
    return out


class Image:
    def __init__(self, path):
        self.path = path
        self.d = d = open(path, 'rb').read()
        ncmds = struct.unpack_from('<I', d, 16)[0]
        off = 32
        self.segs = []
        self.text_base = None
        fs = None
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from('<II', d, off)
            if cmd == LC_SEGMENT_64:
                name = d[off + 8:off + 24].rstrip(b'\0').decode()
                vmaddr, vmsize, foff, fsize = struct.unpack_from('<4Q', d, off + 24)
                self.segs.append((name, vmaddr, vmsize, foff, fsize))
                if name == '__TEXT':
                    self.text_base = vmaddr
            elif cmd == LC_FUNCTION_STARTS:
                do, ds = struct.unpack_from('<II', d, off + 8)
                fs = (do, ds)
            off += cmdsize
        if fs is None:
            raise SystemExit('%s: no LC_FUNCTION_STARTS' % path)
        # The carved image starts at the kernel image header inside the fileset,
        # so every container-relative file offset must be shifted by kfo.
        # kfo == fileoff of the first segment (__TEXT) == image header position.
        self.kfo = min(fo for _n, _vm, _vs, fo, _fs in self.segs)
        do, ds = fs
        self.starts = [self.text_base + x for x in uleb(d, do - self.kfo, ds)]

    def file_off(self, vaddr):
        for _n, vm, _vs, fo, fs in self.segs:
            if vm <= vaddr < vm + fs:
                return fo + (vaddr - vm) - self.kfo
        return None

    def func_bytes(self, va, size):
        fo = self.file_off(va)
        if fo is None:
            return b''
        return self.d[fo:fo + size]

    def funcs(self):
        """-> list of (addr, size, mnemonics[], operands[], sig)"""
        out = []
        st = self.starts
        for i in range(len(st) - 1):
            a, b = st[i], st[i + 1]
            if b <= a or b - a > 0x20000:
                continue
            code = self.func_bytes(a, b - a)
            if not code:
                continue
            mn = []
            ops = []
            for ins in MD.disasm(code, a):
                mn.append(ins.mnemonic)
                ops.append(ins.op_str)
            if len(mn) < 3:
                continue
            sig = '%s|%s' % (' '.join(mn), ' '.join(ops))
            out.append((a, b - a, mn, ops, sig))
        return out


def classify(old_mn, new_mn):
    """NEW-CHECK: 26.3 adds a compare/branch that 26.2 lacked."""
    def has_check(mn):
        for m in mn:
            if m.startswith('cmp') or m.startswith('tbn') or m in ('cbz', 'cbnz'):
                return True
        return False

    def branches(mn):
        return sum(1 for m in mn if m.startswith('b'))

    kind = []
    if not has_check(old_mn) and has_check(new_mn):
        kind.append('NEW-CHECK')
    if branches(new_mn) > branches(old_mn):
        kind.append('NEW-BRANCH')
    if len(new_mn) > len(old_mn) * 1.10:
        kind.append('GREW')
    if len(new_mn) < len(old_mn) * 0.90:
        kind.append('SHRUNK')
    return kind or ['MODIFIED']


def main():
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    opts = {a: sys.argv[i + 1] for i, a in enumerate(sys.argv) if a.startswith('--') and i + 1 < len(sys.argv)}
    if len(args) < 2:
        sys.exit(__doc__)
    min_ratio = float(opts.get('--min-ratio', 0.5))
    only_checks = '--only-checks' in sys.argv

    old = Image(args[0])
    new = Image(args[1])
    of = old.funcs()
    nf = new.funcs()
    sys.stderr.write('old funcs %d, new funcs %d\n' % (len(of), len(nf)))

    old_by_sig = {}
    for f in of:
        old_by_sig.setdefault(f[4], []).append(f)
    new_by_sig = {}
    for f in nf:
        new_by_sig.setdefault(f[4], []).append(f)

    identical = sum(1 for s in old_by_sig if s in new_by_sig)
    sys.stderr.write('identical signatures: %d\n' % identical)

    changed_old = [f for f in of if f[4] not in new_by_sig]
    added_new = [f for f in nf if f[4] not in old_by_sig]
    sys.stderr.write('changed/deleted in old: %d, added in new: %d\n' % (len(changed_old), len(added_new)))

    # pair changed-old with best new candidate by mnemonic-stream similarity
    new_mn_only = [[f[2], f] for f in added_new]
    pairs = []
    for f in changed_old:
        best = None
        best_r = 0.0
        for mn2, g in new_mn_only:
            if abs(len(mn2) - len(f[2])) > max(64, len(f[2])):
                continue
            r = difflib.SequenceMatcher(None, f[2], mn2, autojunk=False).quick_ratio()
            if r < best_r:
                continue
            r = difflib.SequenceMatcher(None, f[2], mn2, autojunk=False).ratio()
            if r > best_r:
                best_r = r
                best = g
        if best is not None and best_r >= min_ratio:
            pairs.append((f, best, best_r))
            new_mn_only = [(m, g) for (m, g) in new_mn_only if g is not best]
        else:
            pairs.append((f, None, best_r))

    report = []
    for f, g, r in pairs:
        kinds = classify(f[2], g[2]) if g else ['DELETED']
        if only_checks and not (g is None or 'NEW-CHECK' in kinds):
            continue
        report.append('=' * 78)
        report.append('OLD %s len=%d  ->  %s len=%d  ratio=%.2f  %s'
                      % (hex(f[0]), f[1], hex(g[0]) if g else '-', g[1] if g else 0, r, ','.join(kinds)))
        if g:
            sm = difflib.SequenceMatcher(None, f[2], g[2], autojunk=False)
            ops = [op for op in sm.get_opcodes() if op[0] != 'equal']
            for tag, i1, i2, j1, j2 in ops[:6]:
                report.append('  %-8s old[%d:%d] %s' % (tag, i1, i2, ' ; '.join(f[2][i1:i2])[:160]))
                report.append('  %-8s new[%d:%d] %s' % ('', j1, j2, ' ; '.join(g[2][j1:j2])[:160]))

    out = '\n'.join(report)
    if len(args) > 2:
        open(args[2], 'w').write(out)
        sys.stderr.write('report -> %s (%d lines)\n' % (args[2], len(report)))
    else:
        print(out)


if __name__ == '__main__':
    main()
