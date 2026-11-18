"""Owned audit-directory EIO/EINTR failures and in-flight descriptor races."""
from audit_directory_cases import row, request


def sequence(op, first_success):
    second = 2 if first_success else 1
    return [request(op, b'@ROOT@'), request(3, lease=1), request(4, lease=1),
        request(op, b'@ROOT@'), request(3, lease=second, private=1), request(4, lease=second)]


def cases():
    for op, targets in (
        (1, [('open_root', 1), ('stat_root', 1), ('stat_root', 2)]),
        (2, [('open_root', 1), ('stat_root', 1), ('mkdir_hot', 1), ('sync_root', 1),
             ('open_hot', 1), ('stat_hot', 1), ('stat_hot', 2)]),
    ):
        for kind, ordinal in targets:
            for error in (5, 4):
                retried = kind == 'sync_root' and error == 4
                yield row(f'kernel-{op}-{kind}-{ordinal}-{error}', {}, sequence(op, retried),
                    kernel=dict(faults=[dict(kind=kind, ordinal=ordinal, errno=error)]),
                    expected_first_diagnostic=0 if retried else 23)
    yield row('kernel-positive-control', {}, sequence(2, True),
        kernel=dict(faults=[]), expected_first_diagnostic=0)
    for kind in ('sync_root', 'open_hot'):
        yield row('kernel-held-root-renamed-before-' + kind, {}, sequence(2, True),
            kernel=dict(faults=[dict(kind=kind, mutation=dict(action='rename_root'))]),
            expected_first_diagnostic=0)
