# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Predeclared real descriptor and namespace transitions for archive_stamp."""
import struct

REQUEST = b'HRASQ001' + struct.pack('<Q', 1)


def cases():
    yield dict(name='empty-stable', steps=[{}, {}, {}])
    for kind in ('file', 'fifo'):
        yield dict(name='private-directory-type-' + kind, kind=kind, steps=[{}, {}], diagnostic=16)
    for mode in (0o000, 0o100, 0o600, 0o500, 0o701, 0o710, 0o750, 0o777, 0o1700, 0o2700, 0o4700):
        yield dict(name='held-directory-mode-' + oct(mode), steps=[{}, {'mutation':'chmod','mode':mode},
            {'diagnostic':16}, {'mutation':'chmod','mode':0o700}, {}])
    for ns in (-123456789000000001, -1, 0, 999999999, 1700000000123456789):
        yield dict(name='mtime-signed-' + str(ns), steps=[{}, {'mutation':'utime','ns':ns}, {}, {}])
    for name in (b'one', b'\xc3\xa9', b'\xe4\xb8\xad', b'\xff', b'a'*255):
        yield dict(name='membership-' + name.hex(), steps=[{}, {'mutation':'write','name':name.hex(),'data':'616263'}, {},
            {'mutation':'write','name':name.hex(),'data':'6465666768'}, {},
            {'mutation':'unlink','name':name.hex()}, {}, {}])
    yield dict(name='directory-rename-keeps-held-inode', steps=[{}, {'mutation':'rename-root'}, {}, {}, {}])
    yield dict(name='directory-unlink-keeps-held-inode', steps=[{}, {'mutation':'unlink-root'}, {}, {}])
    yield dict(name='mixed-raw-dirents', nodes=[('n'+str(i)).encode().hex() for i in range(96)] +
        [bytes([i]).hex() for i in range(128,256)], steps=[{}, {}, {}])
    invalid = [b'', REQUEST[:7], REQUEST[:15], REQUEST+b'\0', b'WRONG001'+REQUEST[8:]]
    invalid += [b'HRASQ001'+struct.pack('<Q', op) for op in (0,2,101,(1<<64)-1)]
    for number, raw in enumerate(invalid):
        yield dict(name='private-wire-invalid-' + str(number), steps=[{'raw':raw.hex(),'status':0xffffffff}, {}, {}])


def fault_cases():
    def row(name, faults, diagnostic=0, error=0, steps=None):
        return dict(name=name, supervisor=dict(faults=faults), steps=steps or [dict(diagnostic=diagnostic,error=error),{},{}])
    yield row('observed-syscalls', [])
    for error in (2,4,5,9,13,20,22):
        yield row('first-metadata-error-' + str(error), [dict(kind='held_metadata',errno=error)], 23, error)
    yield row('statx-enosys-fstatat', [dict(kind='held_metadata',errno=38)])
    yield row('statx-probe-available', [dict(kind='held_metadata',errno=13),dict(kind='statx_probe',errno=14)],23,13)
    yield row('shared-statx-unavailable-cache', [dict(kind='held_metadata',errno=13),dict(kind='statx_probe',errno=38),dict(kind='statat_probe',errno=38)])
    yield row('fallback-fstat-error', [dict(kind='held_metadata',errno=13),dict(kind='statx_probe',errno=38),
        dict(kind='statat_probe',errno=38),dict(kind='held_metadata',ordinal=2,errno=5)],23,5)
    yield row('statx-and-fstatat-error', [dict(kind='held_metadata',errno=38),dict(kind='held_metadata',ordinal=2,errno=5)],23,5)
    yield row('shared-fallback-across-namespace', [dict(kind='held_metadata',ordinal=2,errno=38)])
    for kind, error in (('events_init',38),('events_init',24),('events_read',5),('pin_duplicate',24),('watch_add',28)):
        yield row('namespace-fallback-' + kind + '-' + str(error), [dict(kind=kind,errno=error)])
    for kind in ('scan_open','scan_flags','scan_metadata','scan_read'):
        for error in ((2,4,5,13) if kind=='scan_read' else (5,13)):
            yield row('fingerprint-' + kind + '-' + str(error), [dict(kind='events_init',errno=38),dict(kind=kind,errno=error)],
                0 if kind=='scan_read' and error==2 else 23, 0 if kind=='scan_read' and error==2 else error)
    yield row('fingerprint-actual-small-getdents', [dict(kind='events_init',errno=38),dict(kind='scan_read',short_limit=64)])
    yield row('fingerprint-zero-entries', [dict(kind='events_init',errno=38),dict(kind='scan_read',zero=True)])
    yield row('fingerprint-scan-close-error-ignored', [dict(kind='events_init',errno=38),dict(kind='scan_close',errno=5)])
    yield row('metadata-cache-known-error-no-probe', [dict(kind='held_metadata',ordinal=3,errno=13)],
        steps=[{},dict(diagnostic=23,error=13),{}])
    yield row('watch-events-interrupted', [dict(kind='events_read',errno=4)])


if __name__ == '__main__':
    import json
    ordinary=list(cases());faults=list(fault_cases())
    print(json.dumps(dict(ordinary=len(ordinary),kernel=len(faults),requests=sum(sum('mutation' not in s for s in r['steps']) for r in ordinary+faults),
        controls=sum(len(r['supervisor']['faults']) for r in faults))))
