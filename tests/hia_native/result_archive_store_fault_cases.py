# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Selected kernel failures and initialization races in the archive-store call graph."""
import errno
from result_archive_store_cases import request, identity


def cases():
    def opened(initialized):
        operation = request(1, 0 if initialized else 1)
        return [operation, request(5, lease=1), operation, request(5, lease=1), request(5, lease=2), operation]
    def row(name, kind, error, diagnostic, initialized=False, ordinal=1):
        return dict(name=name, initialized=initialized, operations=opened(initialized),
            supervisor=dict(faults=[dict(kind=kind, ordinal=ordinal, errno=error)]),
            expected_response_index=0, expected_first_diagnostic=diagnostic)
    for kind in ('open_anchor', 'open_marker', 'probe_store', 'mkdir_store', 'sync_root', 'open_store',
            'stat_store', 'mkdir_archive', 'sync_store', 'open_archive', 'stat_archive',
            'mkdir_shard_00', 'sync_archive', 'open_shard_00', 'stat_shard_00', 'stat_root', 'stat_legacy'):
        yield row('create-eio-' + kind, kind, errno.EIO, 23)
    for kind in ('mkdir_store', 'open_store', 'stat_store', 'mkdir_shard_7f', 'stat_shard_7f'):
        yield row('create-eintr-' + kind, kind, errno.EINTR, 23)
    for kind in ('sync_root', 'sync_store', 'sync_archive'):
        yield row('create-eintr-' + kind, kind, errno.EINTR, 0)
    for kind in ('open_store', 'open_archive'):
        yield row('reopen-eio-' + kind, kind, errno.EIO, 23, ordinal=2)
    for ordinal in (2, 3):
        yield row('identity-eio-shard-ff-' + str(ordinal), 'stat_shard_ff', errno.EIO, 23, ordinal=ordinal)
    for kind in ('stat_root', 'stat_legacy', 'stat_store', 'stat_archive'):
        yield row('binding-eio-' + kind, kind, errno.EIO, 23, initialized=True)
    yield dict(name='initialization-reread-observes-completed-anchor', initialized=False,
        operations=opened(False), expected_response_index=0, expected_first_diagnostic=0,
        supervisor=dict(faults=[dict(kind='open_anchor', ordinal=2, mutation=dict(action='initialize', marker=False))]))
    yield dict(name='initialization-observes-other-marker-history', initialized=False,
        operations=opened(False), expected_response_index=0, expected_first_diagnostic=31,
        supervisor=dict(faults=[dict(kind='open_marker', mutation=dict(action='marker', digest='a1' * 32))]))
    for kind in ('open_shard_80', 'stat_shard_80'):
        yield dict(name='lookup-eio-' + kind, initialized=True,
            operations=[request(1), request(2, lease=1, payload=identity(128)), request(2, lease=1, payload=identity(128)),
                request(4, lease=1), request(5, lease=1)],
            supervisor=dict(faults=[dict(kind=kind, errno=errno.EIO)]),
            expected_response_index=1, expected_first_diagnostic=23)


if __name__ == '__main__':
    rows = list(cases())
    print(dict(cases=len(rows), requests=sum(len(row['operations']) for row in rows)))
