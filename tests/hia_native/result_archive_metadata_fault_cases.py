# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Selected read-time metadata changes and real owned syscall failures."""
import errno
from result_archive_metadata_cases import ANCHOR, MARKER, anchor, encoded, regular, frame


def cases():
    for operation in (1, 2):
        name = ANCHOR if operation == 1 else MARKER
        raw = encoded(anchor()) if operation == 1 else encoded(dict(schema=2, anchor_sha256='a1' * 32))
        def row(label, fault, expected):
            return dict(name=f'{operation}-{label}', files={name: regular(raw)},
                operations=[frame(operation).hex(), frame(operation).hex()],
                supervisor=dict(faults=[fault]), expected_first_diagnostic=expected)
        for kind in ('open_record', 'stat_record', 'read_record'):
            yield row(kind + '-eio', dict(kind=kind, errno=errno.EIO), 23)
        yield row('read-retry-eintr', dict(kind='read_record', errno=errno.EINTR), 0)
        yield row('grow-before-read', dict(kind='read_record', mutation=dict(action='grow', operation=operation)), 17 if operation == 1 else 24)
        for action in ('rewrite', 'replace', 'unlink', 'chmod'):
            yield row(action + '-before-read', dict(kind='read_record', mutation=dict(action=action, operation=operation)),
                18 if operation == 1 else 0)
        yield row('chmod-before-validation', dict(kind='stat_record', mutation=dict(action='chmod', operation=operation)), 16)
        if operation == 1:
            for ordinal in (2, 3):
                yield row('metadata-eio-' + str(ordinal), dict(kind='stat_record', ordinal=ordinal, errno=errno.EIO), 23)
            yield row('rewrite-before-after-stat', dict(kind='stat_record', ordinal=3,
                mutation=dict(action='rewrite', operation=operation)), 18)
