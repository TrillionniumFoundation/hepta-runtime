"""Owned syscall failures and mutations at collection and recovery boundaries."""
import errno
from audit_entries_cases import NAME, STAGE, OLD_STAGE, file, link, row, request, stages


def fault(name, files, kind, ordinal=1, **rule):
    return row(name, files, [request()] * 3,
        supervisor={'faults': [dict(kind=kind, ordinal=ordinal, **rule)]})


def cases():
    for kind, ordinal in (('open_scan', 1), ('duplicate_directory', 1), ('flags_directory', 1),
            ('stat_directory', 1), ('getdents_directory', 1), ('getdents_directory', 2),
            ('open_temporary', 1), ('open_record', 1), ('stat_record', 1), ('read_record', 1)):
        for error in (errno.EIO, errno.EINTR):
            yield fault(f'plain-{kind}-{ordinal}-{error}', {NAME: file()}, kind, ordinal, errno=error)
    yield fault('directory-ENOENT-means-EOF', {NAME: file()}, 'getdents_directory', errno=errno.ENOENT)
    for kind in ('open_temporary', 'stat_temporary', 'unlink_temporary', 'sync_directory'):
        for error in (errno.EIO, errno.EINTR):
            yield fault('staging-' + kind + '-' + str(error), {NAME: file(), STAGE: link(NAME)}, kind, errno=error)
    for action in ('add_record', 'add_unlisted_stage', 'add_unlisted_bad_stage', 'unlink_record'):
        yield fault('after-name-collection-' + action, {NAME: file()}, 'close_directory',
            mutation={'action': action})
    for action in ('grow_record', 'replace_record'):
        yield fault('record-read-' + action, {NAME: file()}, 'read_record', mutation={'action': action})
    yield row('clean-directory-does-not-fsync', supervisor={'faults': []}, forbid_directory_sync=True)


def edge_cases():
    for kind, ordinal in (('getdents_directory', 2), ('close_directory', 1),
            ('unlink_temporary', 1), ('unlink_temporary', 2), ('read_record', 1)):
        values = {NAME: file(), **stages(2)}
        value = row(f'death-before-{kind}-{ordinal}', values, [request()],
            supervisor={'faults': [dict(kind=kind, ordinal=ordinal, kill=True)]})
        value['recovery'] = [request().hex(), request().hex()]
        yield value
