"""Source-bound adapters for the unchanged ordinary body corpus.

Only fixture/build admission is adapted. run_pair, run_case, every request and
both complete state decoders retain their previously qualified source bytes.
"""
from __future__ import annotations
from pathlib import Path
import hashlib
import json
import math
import os
import stat
import sys

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
FOLDER = 'tests/hia_native/local_text_body'
sys.path.insert(0, str(ROOT / 'scripts'))
from hia_native_local_text_body_build import decode, verify_build, require, PIN, SHA

RELOCATE = None
PROCESS_NAMES = ('body-rust-version', 'body-cargo-version', 'body-cargo-metadata', 'body-rust-build')


def regular(root, name):
    require(type(name) is str and name and not Path(name).is_absolute()
            and all(part not in ('', '.', '..') for part in name.split('/')),
            'body evidence path is not an admitted relative name')
    path = Path(root) / name
    require(path.resolve() == path.absolute(), 'body evidence path traverses a symlink')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as handle:
        before = os.fstat(handle.fileno())
        require(stat.S_ISREG(before.st_mode), 'body evidence is not a regular file')
        raw = handle.read()
        after = os.fstat(handle.fileno())
        fields = lambda row: (row.st_dev, row.st_ino, row.st_size, row.st_mode, row.st_mtime_ns, row.st_ctime_ns)
        require(fields(before) == fields(after), 'body evidence changed while reading')
    return raw


def source_evidence(root=ROOT):
    root = Path(root).resolve(strict=True)
    manifest = regular(root, FOLDER + '/source_files.json')
    pins = decode(manifest)
    require(pins['schema'] == 'hepta.runtime.local-text-body-install-source.v1'
            and pins['scope'] == dict(full_body_async_qualified=False, public_handler_qualified=False,
                whole_runtime_replaced=False, old_stack_removal_qualified=False), 'body source scope differs')
    files = pins['files']
    require(type(files) is dict and files, 'body source closure is empty')
    for name, expected in files.items():
        require(PIN(regular(root, name)) == expected, 'body source identity differs: ' + name)
    return dict(files={**files, FOLDER + '/source_files.json': PIN(manifest)}, scope=pins['scope'])


def fixture_files(_folder):
    require(Path(_folder).resolve() == HERE, 'body fixture source directory differs')
    files = source_evidence()['files']
    return {name.removeprefix(FOLDER + '/') if name.startswith(FOLDER + '/') else '@support/' + name: row
            for name, row in files.items()}


def relocated(path):
    path = Path(path).absolute()
    if RELOCATE is None:
        return path
    old, new = RELOCATE
    require(path.is_relative_to(old), 'body evidence producer path escaped its captured output')
    return new / path.relative_to(old)


def original_build(path):
    import verify_reference
    verified = verify_reference.verify(HERE)
    producer_path = Path(path).absolute()
    path = relocated(producer_path)
    raw = regular(path.parent, path.name)
    report = decode(raw)
    require(report['schema'] == 'hepta.runtime.local-text-body-reference-development.v1'
            and report['status'] == 'FRESH_LOCAL_TEXT_BODY_REFERENCE_BUILD_PASS'
            and report['source_verification'] == verified
            and report['fresh_target_directory'] is True and report['fresh_locked_builds'] == 1
            and report['source_unchanged'] is True
            and report['compiler_after'] == report['compiler_before']
            and [row['name'] for row in report['processes']] == list(PROCESS_NAMES),
            'body fresh original source/compiler/process set differs')
    require(report['support_files'] == {name: PIN(regular(ROOT, 'scripts/' + name)) for name in (
                'hia_native_local_create_async_qualification.py', 'hia_native_local_create_qualification.py')},
            'body original environment/identity helper source differs')
    artifacts = {path.name: PIN(raw)}
    for name, identity in verified['files'].items():
        retained = 'source/' + name.removeprefix('reference/')
        value = regular(path.parent, retained)
        require(PIN(value) == {k: identity[k] for k in ('bytes', 'sha256')},
                'body fresh build project source differs')
        artifacts[retained] = PIN(value)
    selected = report['environment_binding']['selected']
    rustc = report['compiler_before']['rustc']['resolved_path']
    cargo = report['compiler_before']['cargo']['resolved_path']
    require(selected == dict(RUSTC=rustc, CARGO_ENCODED_RUSTFLAGS='', RUSTC_WRAPPER='',
                             RUSTC_WORKSPACE_WRAPPER=''), 'body compiler environment differs')
    project = producer_path.parent / 'source'
    target = producer_path.parent / 'target'
    config = ['--config', 'build.rustc=' + json.dumps(rustc)]
    commands = [
        [rustc, '--version', '--verbose'], [cargo, '--version'],
        [cargo, *config, 'metadata', '--locked', '--format-version=1', '--filter-platform',
            'x86_64-unknown-linux-gnu', '--manifest-path', str(project / 'Cargo.toml')],
        [cargo, *config, 'build', '--locked', '--release', '--target', 'x86_64-unknown-linux-gnu',
            '--manifest-path', str(project / 'Cargo.toml'), '--target-dir', str(target)],
    ]
    pids = set()
    for row, command in zip(report['processes'], commands, strict=True):
        require(row['command'] == command and row['deadline_seconds'] == 180
                and row['exit_code'] == 0 and row['timed_out'] is False and row['process_reaped'] is True
                and type(row['pid']) is int and row['pid'] > 0 and row['pid'] not in pids
                and row['process_group'] == row['pid'] and row['environment_binding'] == report['environment_binding']
                and type(row['elapsed_seconds']) in (int, float) and math.isfinite(row['elapsed_seconds'])
                and 0 <= row['elapsed_seconds'] <= 180, 'body fresh original process custody differs')
        pids.add(row['pid'])
        for label in ('stdout', 'stderr'):
            name = row['name'] + '.' + label
            value = regular(path.parent, name)
            require(PIN(value) == row[label], 'body complete fresh build stream differs')
            artifacts[name] = PIN(value)
    version = regular(path.parent, PROCESS_NAMES[0] + '.stdout').decode('utf8')
    require(version.startswith('rustc 1.95.0 ') and '\nhost: x86_64-unknown-linux-gnu\n' in version,
            'body selected Rust version/host differs')
    metadata = decode(regular(path.parent, PROCESS_NAMES[2] + '.stdout'))
    packages = {row['id']: row for row in metadata['packages']}
    require(len(packages) == len(metadata['packages']) == 5, 'body original registry package count differs')
    import tomllib
    locked = tomllib.loads(regular(HERE, 'reference/Cargo.lock').decode())['package']
    expected = {(row['name'], row['version'], row.get('source')) for row in locked}
    require({(row['name'], row['version'], row.get('source')) for row in packages.values()} == expected,
            'body actual locked registry versions differ')
    features = {packages[row['id']]['name']: row['features'] for row in metadata['resolve']['nodes']}
    require(features == report['features'] == {'anyhow': ['default', 'std'], 'bytes': ['default', 'std'],
        'pin-project-lite': [], 'tokio': ['bytes', 'default', 'fs', 'io-util', 'rt', 'sync'],
        'hepta-local-text-body-original-oracle': []}, 'body actual original features differ')
    binary = target / 'x86_64-unknown-linux-gnu/release/hepta-local-text-body-original-oracle'
    require(report['executable']['path'] == str(binary), 'body fresh binary path differs')
    actual = relocated(binary)
    identity = PIN(regular(actual.parent, actual.name))
    require(identity == {k: report['executable'][k] for k in ('bytes', 'sha256')},
            'body actual fresh executable identity differs')
    artifacts[str(binary.relative_to(producer_path.parent))] = identity
    return binary, dict(receipt=PIN(raw), executable=identity, source_verification=verified,
                        artifact_sha256={name: row['sha256'] for name, row in artifacts.items()})


def native_build(path):
    producer = Path(path).absolute()
    checked = verify_build(relocated(producer), source_root=ROOT)
    return producer.parent / 'local-text-body.elf', checked


def configure(*, relocation=None):
    global RELOCATE
    RELOCATE = relocation
    import run_paired
    run_paired.files = fixture_files
    run_paired.original_build = original_build
    run_paired.native_build = native_build
    return run_paired
