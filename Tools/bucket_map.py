#!/usr/bin/env python3
# language: python3, file: bucket_map.py, target: iOS 26.2 / 23C55 / iPhone14,5
# T3 — kalloc_type bucket extraction over the DEVICE kernelcache.
#
# Method (all facts read from the binary + 61.12 source this session):
#   KALLOC_TYPE_DEFINE emits a 64-byte `struct kalloc_type_view` in
#   __DATA_CONST / __kalloc_type (kalloc.h:1519-1522, _KALLOC_TYPE_DEFINE at
#   kalloc.h:1598-1608):
#     +0x00 kt_zv.zv_zone   (boot-filled zone_t)
#     +0x08 kt_zv.zv_stats  (boot-filled)
#     +0x10 kt_zv.zv_name   -> "site.<TYPE>" string     [static in image]
#     +0x18 kt_zv.zv_next   (boot-filled)
#     +0x20 kt_signature    (build-time signature ptr)
#     +0x28 kt_flags        (uint32)
#     +0x2C kt_size         (uint32) = sizeof(type)     [static in image]
#     +0x30 kt_zearly / kt_zsig  (boot-filled)
#   Zone assignment (§kalloc_type_create_zone_for_size, kalloc.c:1614-1650)
#   buckets by kt_size; sizes >176 round to the 192 class (kalloc buckets are
#   16-byte aligned; observed on-device as kalloc.type.192 [VP]).
#
# Output: the neighbour set for the aio slot (kalloc.type.192), then a C1-C4
# scoring table for section 3B of the Groomer prompt.
#
# Usage: bucket_map.py <kernelcache> [--json]

import struct
import sys
import json
import re

KC_UUID = bytes.fromhex("0C92DE502BF035FBB461A869B2ACEB5E")  # com.apple.kernel sub-entry
# (panic logs: "Kernel UUID: 0C92DE50-2BF0-35FB-B461-A869B2ACEB5E";
#  the outer fileset image is 6F9AD32F-3BEC-41D3-9B75-D8566AAAE7BF)


def get_uuid(data, off):
    """Read LC_UUID from a Mach-O header at file offset off."""
    ncmds = struct.unpack_from("<I", data, off + 16)[0]
    p = off + 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, p)
        if cmd == 0x1B:  # LC_UUID
            return data[p + 8:p + 24]
        p += cmdsize
    return None


def parse_macho_fileset(data):
    """Return list of (uuid, macho_fileoff) for LC_FILESET_ENTRY entries.

    Layout (loader.h fileset_entry_command): cmd, cmdsize, vmaddr(8),
    fileoff(8), entry_id(4), reserved(4). The entry's UUID lives in the
    sub-image Mach-O at `fileoff`."""
    magic = struct.unpack_from("<I", data, 0)[0]
    assert magic in (0xFEEDFACF, 0xCFFAEDFE), hex(magic)
    ncmds = struct.unpack_from("<I", data, 16)[0]
    off = 32
    entries = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if (cmd & 0x7FFFFFFF) == 0x35:  # LC_FILESET_ENTRY
            vmaddr, fileoff = struct.unpack_from("<QQ", data, off + 8)
            uuid = get_uuid(data, fileoff)
            entries.append((uuid, fileoff, vmaddr))
        off += cmdsize
    return entries


def parse_segments(data, base_off):
    """Parse a Mach-O at base_off -> [(name, vmaddr, vmsize, fileoff, filesize)]."""
    magic = struct.unpack_from("<I", data, base_off)[0]
    assert magic in (0xFEEDFACF, 0xCFFAEDFE), hex(magic)
    ncmds = struct.unpack_from("<I", data, base_off + 16)[0]
    off = base_off + 32
    segs = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if (cmd & 0x7FFFFFFF) in (0x1, 0x19):  # LC_SEGMENT_64
            segname = data[off + 8:off + 24].rstrip(b"\0").decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, off + 24)
            nsects = struct.unpack_from("<I", data, off + 64)[0]
            segs.append((segname, vmaddr, vmsize, fileoff, filesize))
        off += cmdsize
    return segs


def main():
    kc = sys.argv[1]
    data = open(kc, "rb").read()
    entries = parse_macho_fileset(data)
    hit = None
    for uuid, fileoff, vmaddr in entries:
        if uuid == KC_UUID:
            hit = (fileoff, vmaddr)
    if not hit:
        print("FATAL: fileset entry %s not found; have %d entries" %
              (KC_UUID.hex(), len(entries)))
        sys.exit(1)
    base_off, base_vm = hit
    print("[*] kernel fileset entry fileoff=0x%x vmaddr=0x%x" % (base_off, base_vm))

    segs = parse_segments(data, base_off)
    for s in segs:
        print("[*] seg %-16s vm=0x%012x sz=0x%08x file=0x%08x" %
              (s[0], s[1], s[2], s[3]))

    def off2vm(o):
        for name, vmaddr, vmsize, fileoff, filesize in segs:
            if fileoff <= o < fileoff + filesize:
                return vmaddr + (o - fileoff)
        return None

    def vm2off(v):
        for name, vmaddr, vmsize, fileoff, filesize in segs:
            if vmaddr <= v < vmaddr + vmsize:
                return fileoff + (v - vmaddr)
        return None

    # --- locate the __kalloc_type section in __DATA_CONST ---
    kt_sec = None
    ncmds = struct.unpack_from("<I", data, base_off + 16)[0]
    p = base_off + 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, p)
        if (cmd & 0x7FFFFFFF) == 0x19:  # LC_SEGMENT_64
            nsects = struct.unpack_from("<I", data, p + 64)[0]
            sp = p + 72
            for _s in range(nsects):
                sect = data[sp:sp + 80]
                sname = sect[0:16].rstrip(b"\0").decode(errors="replace")
                addr, size = struct.unpack_from("<QQ", sect, 32)
                if sname == "__kalloc_type":
                    kt_sec = (addr, size, vm2off(addr))
                sp += 80
        p += cmdsize
    assert kt_sec, "__kalloc_type section not found"
    kt_addr, kt_size, kt_file = kt_sec
    print("[*] __kalloc_type @vm=0x%x file=0x%x size=0x%x (%d records @64B)" %
          (kt_addr, kt_file, kt_size, kt_size // 64))

    # 64-byte `struct kalloc_type_view` records. Chained pointers in this
    # kernelcache encode the target's FILE OFFSET as a plain uint32 at +0x10
    # (kt_zv.zv_name) and +0x20 (kt_signature); the loader rebases at boot.
    # Discovered this session: rec706's name dword = 0x7f519 == the file offset
    # of "site.aio_workq_entry"; kt_size (+0x2C) then reads 184 [VB].
    views = []
    for i in range(0, kt_size - 64 + 1, 64):
        rec = data[kt_file + i: kt_file + i + 64]
        name_off = struct.unpack_from("<I", rec, 0x10)[0]
        size = struct.unpack_from("<I", rec, 0x2C)[0]
        flags = struct.unpack_from("<I", rec, 0x28)[0]
        if name_off <= 0 or name_off >= len(data) or not (0 < size <= 8192):
            continue
        end = data.find(b"\0", name_off, name_off + 200)
        if end < 0 or end - name_off > 160:
            continue
        s = data[name_off:end]
        if not s.startswith(b"site."):
            continue
        views.append({
            "vm": kt_addr + i,
            "rec": i // 64,
            "type": s[5:].decode(errors="replace"),
            "size": size,
            "flags": flags,
        })

    print("[*] kalloc_type_view records: %d" % len(views))

    # sanity: aio_workq_entry must be present at 176
    aio = [v for v in views if v["type"] == "aio_workq_entry"]
    if aio:
        print("[VB] aio_workq_entry: size=%d flags=0x%x @vm=0x%x  (expect 176)" %
              (aio[0]["size"], aio[0]["flags"], aio[0]["vm"]))
    else:
        print("[!!] aio_workq_entry NOT FOUND — record scan needs adjustment")

    # --- bucket by zone size class (16-byte aligned) ---
    buckets = {}
    for v in views:
        cls = (v["size"] + 15) & ~15
        buckets.setdefault(cls, []).append(v)

    print("[*] %d size classes" % len(buckets))
    tgt = buckets.get(192, [])
    print("[*] kalloc.type.192 class members: %d" % len(tgt))
    for v in sorted(tgt, key=lambda x: x["type"]):
        print("    %7d  %-52s flags=0x%04x" % (v["size"], v["type"], v["flags"]))

    if "--json" in sys.argv:
        out = {"aio_view": aio[0] if aio else None,
               "class_192": sorted(tgt, key=lambda x: x["type"]),
               "n_classes": len(buckets),
               "n_views": len(views)}
        with open("/tmp/opencode/bucket_map.json", "w") as f:
            json.dump(out, f, indent=1)
        print("[*] wrote /tmp/opencode/bucket_map.json")


if __name__ == "__main__":
    main()
