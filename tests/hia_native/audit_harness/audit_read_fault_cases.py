"""Real error and owned-namespace races for full audit reads and recovery."""
import errno
from audit_read_cases import NAME, STAGE, OLD_STAGE, file, link, row, request


def cases():
    def fault(name, files, kind, ordinal=1, operations=None, **rule):
        return row(name, files, operations, supervisor={'faults': [dict(kind=kind, ordinal=ordinal, **rule)]})
    simple = {NAME: file()}
    linked = {NAME: file(), STAGE: link(NAME)}
    random = {NAME: file(), OLD_STAGE: link(NAME)}
    for kind, ordinal in (('open_temporary', 1), ('open_record', 1), ('stat_record', 1),
            ('stat_record', 2), ('read_record', 1)):
        for error in (errno.EIO, errno.EINTR):
            yield fault(f'simple-{kind}-{ordinal}-{error}', simple, kind, ordinal, errno=error)
    for kind, ordinal in (('open_temporary', 2), ('stat_temporary', 1), ('open_record', 1),
            ('stat_record', 1), ('unlink_temporary', 1), ('sync_directory', 1)):
        for error in (errno.EIO, errno.EINTR):
            yield fault(f'deterministic-{kind}-{ordinal}-{error}', linked, kind, ordinal, errno=error)
    for kind, ordinal in (('open_scan', 1), ('duplicate_directory', 1), ('flags_directory', 1),
            ('stat_directory', 1), ('getdents_directory', 1), ('open_temporary', 2),
            ('stat_temporary', 1), ('open_record', 2), ('stat_record', 2),
            ('unlink_temporary', 1), ('sync_directory', 1)):
        for error in (errno.EIO, errno.EINTR):
            yield fault(f'random-{kind}-{ordinal}-{error}', random, kind, ordinal, errno=error)
    yield fault('getdents-ENOENT-is-EOF', random, 'getdents_directory', errno=errno.ENOENT)
    yield fault('grow-after-metadata', simple, 'read_record', mutation={'action': 'grow_record'})
    yield fault('replace-path-keeps-open-file', simple, 'read_record', mutation={'action': 'replace_record'})
    yield fault('remove-stage-before-unlink', random, 'unlink_temporary', mutation={'action': 'unlink_stage'})
    yield fault('random-stage-arrives-before-scan', {NAME: file(), 'alias': link(NAME)},
        'getdents_directory', mutation={'action': 'stage_arrives'})
    for kind in ('stat_temporary', 'unlink_temporary', 'sync_directory'):
        yield fault('explicit-cleanup-' + kind, {OLD_STAGE: file()}, kind,
            operations=[request(2, OLD_STAGE)] * 3, errno=errno.EIO)
    yield row('no-injection-random-scan', random, supervisor={'faults': []})
