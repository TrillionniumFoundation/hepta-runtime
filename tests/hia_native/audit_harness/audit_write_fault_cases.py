"""Owned kernel errors, real short writes and interrupted audit publication."""
import errno
from audit_write_cases import NAME, STAGE, record, file, link, row, request


def fault(name, files, operations, kind, ordinal=1, **rule):
    return row(name, files, operations, supervisor={'faults': [dict(kind=kind, ordinal=ordinal, **rule)]})


def cases():
    create = [request(), request(record(state='completed', elapsed_ms=2), 2), request()]
    replace = [request(record(state='completed', elapsed_ms=2), 2), request(operation=2), request()]
    for kind in ('stat_directory', 'open_temporary', 'stat_temporary', 'write_temporary',
            'sync_temporary', 'link_temporary', 'unlink_temporary', 'sync_directory'):
        for error in (errno.EIO, errno.EINTR):
            yield fault('create-' + kind + '-' + str(error), {}, create, kind, errno=error)
    for kind, ordinal in (('stat_directory', 1), ('open_temporary', 1), ('open_temporary', 2),
            ('open_record', 1), ('stat_record', 1), ('stat_record', 2), ('read_record', 1),
            ('stat_temporary', 1), ('write_temporary', 1), ('sync_temporary', 1),
            ('rename_temporary', 1), ('sync_directory', 1)):
        for error in (errno.EIO, errno.EINTR):
            yield fault(f'replace-{kind}-{ordinal}-{error}', {NAME: file()}, replace,
                kind, ordinal, errno=error)
    for kind in ('stat_temporary', 'unlink_temporary', 'sync_directory'):
        for error in (errno.EIO, errno.EINTR):
            yield fault('replace-cleanup-' + kind + '-' + str(error),
                {NAME: file(), STAGE: link(NAME)}, replace, kind, errno=error)
    for replacing in (False, True):
        files = {NAME: file()} if replacing else {}
        operations = replace if replacing else create
        yield fault('zero-write-' + str(replacing), files, operations, 'write_temporary', zero_write=True)
        yield row('failed-cleanup-keeps-first-error-' + str(replacing), files, operations,
            supervisor={'faults': [dict(kind='sync_temporary', errno=errno.EIO),
                dict(kind='unlink_temporary', errno=errno.EPERM)]})
        yield row('no-directory-sync-' + str(replacing), files,
            [request(operation=2 if replacing else 1, sync=False)],
            supervisor={'faults': []}, forbid_directory_sync=True)
    yield fault('target-arrives-before-link', {}, create, 'link_temporary', mutation={'action': 'create_target'})
    yield fault('stage-arrives-before-exclusive-create', {}, create, 'open_temporary', mutation={'action': 'create_stage'})
    yield fault('stage-disappears-before-link', {}, create, 'link_temporary', mutation={'action': 'unlink_stage'})
    yield fault('stage-mode-changes-before-validation', {}, create, 'stat_temporary', mutation={'action': 'chmod_stage'})
    yield fault('stage-link-before-validation', {}, create, 'stat_temporary', mutation={'action': 'link_stage'})
    yield fault('directory-mode-before-validation', {}, create, 'stat_directory', mutation={'action': 'chmod_directory'})
    yield fault('published-path-replaced-before-rename', {NAME: file()}, replace, 'rename_temporary', mutation={'action': 'replace_record'})
    yield fault('existing-record-grows-after-metadata', {NAME: file()}, replace, 'read_record', mutation={'action': 'grow_record'})
    yield fault('existing-path-replaced-while-read-held', {NAME: file()}, replace, 'read_record', mutation={'action': 'replace_record'})


def edge_cases():
    for replacing in (False, True):
        files = {NAME: file()} if replacing else {}
        for count in (1, 7, 31, 127):
            yield row(f'actual-short-write-{replacing}-{count}', files,
                [request(operation=2 if replacing else 1)], supervisor={'file_size_limit': count})
        kinds = ('write_temporary', 'sync_temporary', 'rename_temporary') if replacing else (
            'write_temporary', 'sync_temporary', 'link_temporary', 'unlink_temporary')
        for kind in kinds:
            value = fault(f'death-{replacing}-before-{kind}', files,
                [request(operation=2 if replacing else 1)], kind, kill=True)
            value['recovery'] = [request().hex(), request(operation=2).hex(),
                request().hex(), request(record(state='completed', elapsed_ms=2), 2).hex()]
            yield value
