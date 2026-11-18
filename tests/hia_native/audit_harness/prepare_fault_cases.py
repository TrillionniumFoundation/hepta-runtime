"""Kernel failures, held-root lifetime checks, and controlled changes between root walks."""
import errno
from prepare_cases import request

def cases():
    def row(name, kind, diagnostic, error=errno.EIO, ordinal=1, initialized=False):
        return dict(name=name, initialized=initialized, operations=[request(), request()],
            supervisor=dict(faults=[dict(kind=kind, ordinal=ordinal, errno=error)]),
            expected_diagnostics=[diagnostic])
    yield dict(name='creation-root-dropped-before-verification', initialized=False,
        operations=[request(), request()], expected_diagnostics=[0, 0],
        supervisor=dict(faults=[], expected_root_lifetimes=[True, False, False]))
    yield dict(name='existing-root-dropped-before-verification', initialized=True,
        operations=[request(), request()], expected_diagnostics=[0, 0],
        supervisor=dict(faults=[], expected_root_lifetimes=[False, False]))
    for kind in ('open_root', 'mkdir_legacy', 'sync_root', 'open_legacy', 'stat_legacy',
            'mkdir_store', 'open_store', 'stat_store', 'mkdir_archive', 'sync_store',
            'open_archive', 'stat_archive', 'mkdir_shard_00', 'sync_archive', 'open_shard_00', 'stat_shard_00'):
        yield row('create-eio-' + kind, kind, 23)
    yield row('second-root-open-eio', 'open_root', 23, ordinal=2)
    yield row('anchor-reread-eio', 'open_anchor', 23, ordinal=3)
    yield row('reopen-archive-eio', 'open_archive', 23, ordinal=2)
    for kind in ('mkdir_legacy', 'open_legacy', 'stat_legacy', 'open_root'):
        yield row('entry-eintr-' + kind, kind, 23, error=errno.EINTR)
    for kind in ('sync_root', 'sync_store', 'sync_archive'):
        yield row('creation-eintr-' + kind, kind, 0, error=errno.EINTR)
    for kind in ('open_shard_80', 'stat_shard_80'):
        yield row('verification-eio-' + kind, kind, 23, initialized=True)
    yield dict(name='initialization-reread-observes-completed-anchor', initialized=False,
        operations=[request(), request()], expected_diagnostics=[0, 0], anchor_origin='controlled_external_writer',
        supervisor=dict(faults=[dict(kind='open_anchor', ordinal=3,
            mutation=dict(action='initialize', marker=False))], expected_root_lifetimes=[False, False]))
    yield dict(name='second-root-walk-sees-new-root-with-held-old-legacy', initialized=False,
        operations=[request(), request()], expected_diagnostics=[0, 23],
        created_legacy_path='retired-root/request-results',
        supervisor=dict(faults=[dict(kind='open_root', ordinal=2,
            mutation=dict(action='rename_root_create'))], expected_root_lifetimes=[True, False]))

if __name__ == '__main__':
    rows=list(cases());print(dict(cases=len(rows),requests=sum(len(row['operations']) for row in rows)))
