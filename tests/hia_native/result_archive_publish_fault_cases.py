# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Owned publication failures, races, short writes and process-death boundaries."""
import errno
from result_archive_publish_cases import frame
from result_archive_metadata_cases import anchor, encoded


def cases():
    publish = frame(1, encoded(anchor())).hex()
    marker = frame(2, b'a1' * 32).hex()
    def row(name, operation, fault, diagnostic, **extra):
        return dict(name=name, files={}, operations=[operation, operation],
            supervisor=dict(faults=[fault]), expected_first_diagnostic=diagnostic, **extra)
    for kind in ('open_random', 'read_random', 'open_temporary', 'write_temporary', 'sync_temporary',
                 'link_temporary', 'unlink_temporary', 'sync_directory'):
        yield row('publish-eio-' + kind, publish, dict(kind=kind, errno=errno.EIO), 23)
    for kind in ('open_random', 'read_random', 'write_temporary', 'sync_temporary', 'sync_directory'):
        yield row('publish-eintr-' + kind, publish, dict(kind=kind, errno=errno.EINTR), 0)
    yield row('publish-open-eintr', publish, dict(kind='open_temporary', errno=errno.EINTR), 23)
    yield row('publish-random-eof', publish, dict(kind='read_random', zero_read=True), 27)
    yield row('publish-write-zero', publish, dict(kind='write_temporary', zero_write=True), 28)
    failure = row('publish-cleanup-fails', publish, dict(kind='write_temporary', errno=errno.EIO), 23)
    failure['supervisor']['faults'].append(dict(kind='unlink_temporary', errno=errno.EIO))
    yield failure
    for action, kind in (('create_temporary', 'open_temporary'), ('create_anchor', 'link_temporary'),
                         ('remove_temporary', 'link_temporary')):
        yield row('publish-race-' + action, publish, dict(kind=kind, mutation=dict(action=action)), 23)
    for limit in (1, 7, 31, 127):
        yield dict(name='publish-real-short-write-' + str(limit), files={}, operations=[publish],
            supervisor=dict(file_size_limit=limit, faults=[]), expected_first_diagnostic=23,
            actual_short_write_limit=limit, canonical_written_bytes=encoded(anchor()).hex())
    for kind in ('write_temporary', 'link_temporary', 'unlink_temporary', 'sync_directory'):
        yield dict(name='publish-death-before-' + kind, files={}, operations=[publish], recovery=[publish],
            supervisor=dict(faults=[dict(kind=kind, kill=True)]))
    yield row('marker-create-eio', marker, dict(kind='open_record', ordinal=3, errno=errno.EIO), 23)
    yield row('marker-create-eintr', marker, dict(kind='open_record', ordinal=3, errno=errno.EINTR), 23)
    for kind in ('write_record', 'sync_record', 'sync_directory'):
        yield row('marker-eio-' + kind, marker, dict(kind=kind, errno=errno.EIO), 23)
        yield row('marker-eintr-' + kind, marker, dict(kind=kind, errno=errno.EINTR), 0)
    yield row('marker-write-zero', marker, dict(kind='write_record', zero_write=True), 28)
    for ordinal in (2, 3):
        for binding in ('a1' * 32, 'b2' * 32):
            yield row('marker-race-' + str(ordinal) + '-' + binding[:2], marker,
                dict(kind='open_record', ordinal=ordinal, mutation=dict(action='create_marker', binding=binding)),
                23 if ordinal == 3 else 0 if binding.startswith('a1') else 29)
    for limit in (1, 7, 31):
        yield dict(name='marker-real-short-write-' + str(limit), files={}, operations=[marker],
            supervisor=dict(file_size_limit=limit, faults=[]), expected_first_diagnostic=23,
            actual_short_write_limit=limit, canonical_written_bytes=encoded(dict(schema=2, anchor_sha256='a1' * 32)).hex())
    yield dict(name='marker-death-before-write', files={}, operations=[marker], recovery=[marker],
        supervisor=dict(faults=[dict(kind='write_record', kill=True)]))
