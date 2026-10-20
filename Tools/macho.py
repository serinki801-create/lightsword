import struct, sys

class MachO:
    def __init__(self, path):
        self.d = d = open(path,'rb').read()
        magic, = struct.unpack_from('<I', d, 0)
        assert magic == 0xfeedfacf, hex(magic)
        (self.cputype, self.cpusubtype, self.filetype, self.ncmds,
         self.sizeofcmds, self.flags, self.reserved) = struct.unpack_from('<7I', d, 4)
        self.cmds = []
        off = 32
        for _ in range(self.ncmds):
            cmd, cmdsize = struct.unpack_from('<II', d, off)
            body = d[off+8:off+cmdsize]
            self.cmds.append((cmd, cmdsize, off, body))
            off += cmdsize
        self.segments = []
        self.funcstarts = None
        self.symtab = None
        self.segments = []
        for cmd, cmdsize, off, body in self.cmds:
            if cmd == 0x19:  # LC_SEGMENT_64
                segname = body[0:16].rstrip(b'\0').decode()
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<4Q', body, 16)
                maxprot, initprot, nsects, flags = struct.unpack_from('<4I', body, 48)
                secs = []
                so = 64
                for i in range(nsects):
                    sname = body[so:so+16].rstrip(b'\0').decode()
                    segn  = body[so+16:so+32].rstrip(b'\0').decode()
                    addr, size = struct.unpack_from('<2Q', body, so+32)
                    foff, align, reloff, nreloc, sflags, r1, r2, r3 = struct.unpack_from('<8I', body, so+48)
                    secs.append(dict(name=sname, seg=segn, addr=addr, size=size, off=foff, flags=sflags))
                    so += 80
                self.segments.append(dict(name=segname, vmaddr=vmaddr, vmsize=vmsize,
                                         fileoff=fileoff, filesize=filesize, maxprot=maxprot,
                                         initprot=initprot, sections=secs))
            elif cmd == 0x26:  # LC_FUNCTION_STARTS
                dataoff, datasize = struct.unpack_from('<II', body, 0)
                self.funcstarts = self.uleb(d, dataoff, datasize)
            elif cmd == 0x02:  # LC_SYMTAB
                symoff, nsyms, stroff, strsize = struct.unpack_from('<4I', body, 0)
                self.symtab = self.parse_syms(symoff, nsyms, stroff, strsize)

    def uleb(self, d, off, size):
        out = []
        addr = 0
        end = off + size
        while off < end:
            val = 0; shift = 0
            while True:
                b = d[off]; off += 1
                val |= (b & 0x7f) << shift
                if not (b & 0x80): break
                shift += 7
            if val == 0: break
            addr += val
            out.append(addr)
        return out

    def parse_syms(self, symoff, nsyms, stroff, strsize):
        syms = []
        for i in range(nsyms):
            n_strx, n_type, n_sect, n_desc, n_value = struct.unpack_from('<IBBHQ', self.d, symoff + i*16)
            if n_strx < strsize:
                end = self.d.index(b'\0', stroff+n_strx)
                name = self.d[stroff+n_strx:end].decode('utf-8','replace')
            else:
                name = ''
            syms.append(dict(name=name, type=n_type, sect=n_sect, desc=n_desc, value=n_value))
        return syms

    def cstr_at(self, va):
        for seg in self.segments:
            for s in seg['sections']:
                if s['seg']=='__TEXT' and s['name']=='__cstring':
                    base = s['addr']; data = self.d[s['off']:s['off']+s['size']]
                    if base <= va < base+len(data):
                        i = va-base
                        e = data.index(b'\0', i)
                        return data[i:e].decode('utf-8','replace')
        return None

    def section_of(self, va):
        for seg in self.segments:
            for s in seg['sections']:
                if s['addr'] <= va < s['addr']+s['size']:
                    return s
        return None
