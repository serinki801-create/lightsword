"""Mach-O helper for iOS kext/kernel binaries: sections, strings, code refs."""
import struct, re
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

MD = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
MD.skipdata = True


class Image:
    def __init__(self, path):
        self.path = path
        self.d = d = open(path, 'rb').read()
        ncmds = struct.unpack_from('<I', d, 16)[0]
        off = 32
        self.segs = {}
        self.text_base = 0
        self.sects = []          # (segname, sectname, vmaddr, size, fileoff)
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from('<II', d, off)
            if cmd == 0x19:      # LC_SEGMENT_64
                segname = d[off+8:off+24].rstrip(b'\0').decode()
                vmaddr, vmsize, foff, fsize = struct.unpack_from('<4Q', d, off+24)
                self.segs[segname] = (vmaddr, vmsize, foff, fsize)
                if segname == '__TEXT':
                    self.text_base = vmaddr
                nsects = struct.unpack_from('<I', d, off+64)[0]
                so = off+72
                for _j in range(nsects):
                    sname = d[so:so+16].rstrip(b'\0').decode()
                    saddr, ssize = struct.unpack_from('<2Q', d, so+32)
                    soff = struct.unpack_from('<I', d, so+48)[0]
                    self.sects.append((segname, sname, saddr, ssize, soff))
                    so += 80
            off += cmdsize

    def section(self, name, seg=None):
        for s, n, va, sz, fo in self.sects:
            if n == name and (seg is None or s == seg):
                return va, self.d[fo:fo+sz]
        return None, None

    def find_str(self, needle):
        for s, n, va, sz, fo in self.sects:
            if n not in ('__cstring', '__os_log', '__assert', '__TEXT'):
                continue
            i = self.d[fo:fo+sz].find(needle.encode())
            if i >= 0:
                return va + i
        return None

    def all_strings(self):
        out = set()
        for s, n, va, sz, fo in self.sects:
            if n in ('__cstring', '__os_log', '__assert'):
                for m in re.finditer(rb'[ -~]{8,}', self.d[fo:fo+sz]):
                    out.add(m.group().decode('utf-8', 'replace'))
        return out

    def code(self):
        va, code = self.section('__text')
        if not code:
            for s, n, _v, _z, fo in self.sects:
                if n in ('__text', '__text_exec'):
                    return _v, self.d[fo:fo+_z]
        return va, code

    def disasm(self):
        va, code = self.code()
        if not code:
            return []
        return list(MD.disasm(code, va))

    def refs_to(self, target_va, insns=None):
        """Return [(insn_addr, adrp_addr)] where adrp+add resolves to target_va."""
        if insns is None:
            insns = self.disasm()
        page = target_va & ~0xfff
        low = target_va & 0xfff
        out = []
        for i, x in enumerate(insns):
            if x.mnemonic != 'adrp':
                continue
            m = re.search(r'#(0x[0-9a-f]+)', x.op_str)
            if not m:
                continue
            p = int(m.group(1), 16)
            if p != page:
                continue
            for j in range(i+1, min(i+7, len(insns))):
                y = insns[j]
                if y.mnemonic == 'add' and '#0x' in y.op_str:
                    imm = int(y.op_str.split('#')[1].split(',')[0], 16)
                    if p + imm == target_va:
                        out.append((y.address, x.address))
                if y.mnemonic in ('b', 'bl', 'ret'):
                    break
        return out

    def func_start(self, addr, insns=None):
        """Walk back to a likely function prologue."""
        if insns is None:
            insns = self.disasm()
        byaddr = {x.address: i for i, x in enumerate(insns)}
        i = byaddr.get(addr)
        if i is None:
            return None
        for k in range(i, max(-1, i-400), -1):
            x = insns[k]
            if x.mnemonic == 'stp' and 'x29, x30' in x.op_str:
                return x.address
            if x.mnemonic == 'sub' and 'sp, sp' in x.op_str:
                return x.address
        return None
