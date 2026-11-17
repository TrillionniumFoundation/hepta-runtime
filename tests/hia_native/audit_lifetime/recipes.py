"""Source-owned process commands; readers use the same immutable command list."""
from pathlib import Path


def recipes(source, producer, python, rust, compiler, sync_source, domain):
    source, producer, rust = Path(source), Path(producer), Path(rust)
    reference = source / 'reference'
    result = [
        ('format', [str(rust / 'rustfmt'), '--check', '--edition', '2021', '--config', 'hard_tabs=true,max_width=100',
                    *[str(reference / name) for name in ('original.rs', 'native.rs', 'cases.rs')]]),
        ('compiler-version', [str(rust / 'rustc'), '--version', '--verbose']),
        ('native-build', [python, '-B', str(source / 'build.py'), '--hepta', str(compiler),
                          '--sync-source', str(sync_source), '--output', str(producer / 'build')]),
        ('emit-sync', [python, '-B', str(producer / 'build/sync-source/emit.py'), '--manifest',
                       str(producer / 'build/modules/audit-native-sync/manifest.json'), '--output', str(producer / 'sync-emission')]),
        ('emit-lifetime', [python, '-B', str(source / 'emit.py'), '--build', str(producer / 'build'),
                           '--sync', str(producer / 'sync-emission/boundary.bin'), '--output', str(producer / 'lifetime-emission')]),
        ('observer-free', [python, '-B', str(source / 'observer_free.py'), '--callable',
                           str(producer / 'lifetime-emission/callable/image.bin'), '--refs',
                           str(producer / 'lifetime-emission/refs/image.bin'), '--output', str(producer / 'observer-free')]),
    ]
    for implementation in ('original', 'native'):
        binary = producer / 'threads' / (implementation + '-tests')
        build_name = 'native-test-build' if implementation == 'native' else 'original-build'
        result.append((build_name, [str(rust / 'rustc'), *domain['rust_profile'],
                      '--crate-name', 'audit_lifetime_' + implementation, '--target', 'x86_64-unknown-linux-gnu',
                      str(reference / (implementation + '.rs')), '-o', str(binary)]))
    for case in domain['cases']:
        for implementation in ('original', 'native'):
            result.append((implementation + '-' + case.replace('_', '-'),
                           [str(producer / 'threads' / (implementation + '-tests')), case]))
    return [(name, [str(value) for value in argv]) for name, argv in result]
