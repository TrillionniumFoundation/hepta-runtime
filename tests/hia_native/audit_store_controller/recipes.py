"""The source-owned actual process recipes, shared by producer and inert reader."""
from pathlib import Path


def recipes(source, producer, python, rust, compiler, sync_source, domain):
    source, producer, rust = Path(source), Path(producer), Path(rust)
    references = source / 'reference'
    original = str(producer / 'threads/original-tests')
    native = str(producer / 'threads/native-tests')
    return [
        ('format', [str(rust / 'rustfmt'), '--check', '--edition', '2021', '--config',
                    'hard_tabs=true,max_width=100',
                    *[str(references / name) for name in ('controller_host.rs', 'native_tests.rs',
                      'original_tests.rs', 'controller_extra_tests.rs.txt')]]),
        ('compiler-version', [str(rust / 'rustc'), '--version', '--verbose']),
        ('native-build', [python, '-B', str(source / 'build.py'), '--hepta', str(compiler),
                          '--sync-source', str(sync_source), '--output', str(producer / 'build')]),
        ('emit-boundary', [python, '-B', str(producer / 'build/sync-source/emit.py'), '--manifest',
                          str(producer / 'build/modules/audit-native-sync/manifest.json'), '--output',
                          str(producer / 'emission')]),
        ('emit-callable', [python, '-B', str(source / 'emit_callable.py'), '--manifest',
                           str(producer / 'build/modules/audit-controller-callable/manifest.json'),
                           '--controller', str(producer / 'build/modules/audit-store-controller/module.image.bin'),
                           '--synchronization', str(producer / 'emission/boundary.bin'),
                           '--output', str(producer / 'callable-emission')]),
        ('observer-free-native', [python, '-B', str(source / 'qualify_callable.py'), '--image',
                                 str(producer / 'callable-emission/callable.bin'),
                                 '--output', str(producer / 'observer-free')]),
        ('original-build', [str(rust / 'rustc'), *domain['rust_profile'], '--crate-name',
                            'audit_store_original_tests', '--target', 'x86_64-unknown-linux-gnu',
                            str(references / 'original_tests.rs'), '-o', original]),
        ('native-test-build', [str(rust / 'rustc'), *domain['rust_profile'], '--crate-name',
                               'audit_store_native_tests', '--target', 'x86_64-unknown-linux-gnu',
                               str(references / 'native_tests.rs'), '-o', native]),
        ('original-threads', [original, '--test-threads=1', '--nocapture']),
        ('native-threads', [native, '--test-threads=1', '--nocapture']),
    ]
