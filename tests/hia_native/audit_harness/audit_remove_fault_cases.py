"""Owned errors and races around exact-record removal and its read recovery."""
import errno
from audit_remove_cases import NAME, STAGE, OLD_STAGE, file, link, row, request


def fault(name, files, kind, ordinal=1, **rule):
    return row(name, files, [request(), request(), request()],
        supervisor={'faults': [dict(kind=kind, ordinal=ordinal, **rule)]})


def cases():
    for kind, ordinal in (('open_temporary', 1), ('open_record', 1), ('stat_record', 1),
            ('stat_record', 2), ('read_record', 1), ('unlink_record', 1), ('sync_directory', 1)):
        for error in (errno.EIO, errno.EINTR):
            yield fault(f'plain-{kind}-{ordinal}-{error}', {NAME: file()}, kind, ordinal, errno=error)
    for kind in ('stat_temporary', 'unlink_temporary', 'sync_directory'):
        for error in (errno.EIO, errno.EINTR):
            yield fault('recovery-' + kind + '-' + str(error),
                {NAME: file(), STAGE: link(NAME)}, kind, errno=error)
    for error in (errno.EIO, errno.EINTR):
        yield fault('random-scan-' + str(error), {NAME: file(), OLD_STAGE: link(NAME)},
            'getdents_directory', errno=error)
    yield fault('target-replaced-after-validation', {NAME: file()}, 'unlink_record', mutation={'action': 'replace_record'})
    yield fault('target-removed-after-validation', {NAME: file()}, 'unlink_record', mutation={'action': 'unlink_record'})
    yield fault('record-grows-during-read', {NAME: file()}, 'read_record', mutation={'action': 'grow_record'})
    yield fault('path-replaced-during-read', {NAME: file()}, 'read_record', mutation={'action': 'replace_record'})
    yield row('no-directory-barrier', operations=[request(sync=False)], supervisor={'faults': []}, forbid_directory_sync=True)


def edge_cases():
    for kind in ('unlink_record', 'sync_directory'):
        value = row('death-before-' + kind, operations=[request()],
            supervisor={'faults': [dict(kind=kind, kill=True)]})
        value['recovery'] = [request().hex(), request().hex()]
        yield value
