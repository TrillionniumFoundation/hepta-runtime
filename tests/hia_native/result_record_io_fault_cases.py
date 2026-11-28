# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Selected owned kernel faults, actual short writes and interrupted publication."""
import errno
from result_record_io_cases import NAME, TEMP, record, regular, encoded, request, case


def cases():
    save = [request(2, record()), request(1)]
    read = [request(1), request(1)]
    replace = [request(3, record()), request(1)]
    def fault(name, files, operations, kind, **rule):
        return case(name, files, operations, supervisor={'faults': [dict(kind=kind, **rule)]})
    for kind in ('open_temporary', 'stat_directory', 'stat_temporary', 'write_temporary', 'sync_temporary',
                 'link_temporary', 'unlink_temporary', 'sync_directory'):
        for error in (errno.EIO, errno.EINTR):
            options = dict(errno=error)
            if kind == 'open_temporary':options['ordinal'] = 2
            yield fault(kind + '-' + str(error), {}, save, kind, **options)
    for kind in ('open_record', 'stat_record', 'read_record'):
        for error in (errno.EIO, errno.EINTR):
            yield fault(kind + '-' + str(error), {NAME: regular(encoded(record()))}, read, kind, errno=error)
    for kind in ('rename_temporary',):
        for error in (errno.EIO, errno.EINTR):
            yield fault(kind + '-' + str(error), {NAME: regular(encoded(record('unknown')))}, replace, kind, errno=error)
    for kind in ('open_temporary', 'stat_temporary', 'unlink_temporary', 'sync_directory'):
        yield fault('cleanup-' + kind, {TEMP: regular(b'interrupted')}, [request(4), request(4)], kind, errno=errno.EIO)
    yield fault('write-zero', {}, save, 'write_temporary', zero_write=True)
    for count in (1, 7, 31, 127):
        yield case('actual-short-write-' + str(count), {}, save, supervisor={'file_size_limit': count})
    yield fault('grow-after-stat', {NAME: regular(encoded(record()))}, read, 'read_record', mutation={'action': 'grow_record'})
    yield fault('pathname-replacement-retains-open-inode', {NAME: regular(encoded(record()))}, read, 'read_record', mutation={'action': 'replace_record'})
    yield fault('target-arrives-before-link', {}, save, 'link_temporary', mutation={'action': 'create_target'})
    yield fault('stage-arrives-before-exclusive-create', {}, save, 'open_temporary', ordinal=2, mutation={'action': 'create_stage'})
    for kind in ('write_temporary', 'link_temporary', 'unlink_temporary'):
        row = fault('death-before-' + kind, {}, [request(2, record())], kind, kill=True)
        row['recovery'] = [request(4).hex(), request(1).hex(), request(2, record()).hex(), request(1).hex()]
        yield row
