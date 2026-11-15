# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Bind diagnostic-owner evidence to the aggregate's actual processes."""
from pathlib import Path
import sys
import hia_native_serde_error_qualification as q
import hia_native_serde_error_reference as reference

TESTS = ('test_serde_error.py', 'test_serde_error_resources.py', 'test_serde_error_evidence.py')
PHASES = dict(zip(TESTS, ('base', 'resources', 'controls'), strict=True))
NATIVE, ORIGINAL = 'serde-error-native', 'serde-error-original'


def paths(root, output, report):
    root, output = Path(root), Path(output)
    item = report['modules']['serde_error'];manifest = output / item['manifest']
    q.require(q.digest(q.read(manifest)) == item['sha256'] and item['source'] == 'native/serde_error.hepta',
        'registered diagnostic module differs')
    return root, output, Path(report['compiler_checkout']), manifest


def sources(root):
    return (*q.SOURCE_FILES, 'scripts/hia_native_serde_error_pipeline.py')


def test_commands(root, output, report):
    root, output, hepta, manifest = paths(root, output, report)
    return {name: [sys.executable, '-I', '-B', str(root / 'scripts/hia_native_serde_error_qualification.py'),
        '--root', str(root), '--hepta', str(hepta), '--manifest', str(manifest),
        '--output', str(output / NATIVE), '--phase', phase] for name, phase in PHASES.items()}


def complete(root, output, report, name, command, completed):
    row, summary = completed(output, report, name)
    q.require(row['command'] == command and row['timeout_seconds'] == 180
        and row['exit_code'] == 0 and row['timed_out'] is False and not row.get('start_error')
        and 0 <= row['elapsed_seconds'] <= 180, 'actual aggregate diagnostic process differs')
    q.require(not q.read(output / (name + '.stderr')), 'unexpected aggregate diagnostic stderr')
    return row, summary


def keep(output, paths):
    output = Path(output).resolve(strict=True);result = {}
    for path in paths:
        path = Path(path)
        q.require(not path.is_symlink() and path.resolve(strict=True).is_relative_to(output),
            'diagnostic artifact escapes its qualification root')
        result[path.relative_to(output).as_posix()] = q.digest(q.read(path))
    return result


def native_evidence(root, output, report, completed):
    root, output, hepta, manifest = paths(root, output, report)
    observed = q.qualification_evidence(root, hepta, manifest, output / NATIVE)
    commands = test_commands(root, output, report);receipts = {}
    for name, phase in PHASES.items():
        row, summary = complete(root, output, report, name, commands[name], completed)
        q.same(summary, q.object_at(output / NATIVE / (phase + '-process/stdout')),
            'aggregate diagnostic summary differs from its executed suite')
        receipts[name] = row
    artifacts = [manifest.parents[2] / name for name in observed['build']['build_artifacts']]
    artifacts.extend(output / (name + suffix) for name in TESTS for suffix in ('.stdout', '.stderr'))
    corpus = [path for path in (output / NATIVE).rglob('*') if path.is_file()]
    return {'schema': 'hepta.runtime.serde-error-pipeline-native.v1', 'status': 'PASS',
        'owner_evidence': observed, 'completed_processes': receipts,
        'artifact_sha256': keep(output, artifacts), 'corpus_sha256': keep(output, corpus),
        'new_native_executions_by_admission': 0, 'new_original_executions_by_admission': 0,
        'generic_value_serialization_closed': False, 'whole_runtime_closed': False}


def original_commands(root, output, report, rustc):
    root, output, hepta, manifest = paths(root, output, report)
    common = [sys.executable, '-I', '-B', str(root / 'scripts/hia_native_serde_error_reference.py'),
        '--root', str(root), '--hepta', str(hepta), '--manifest', str(manifest),
        '--native-output', str(output / NATIVE), '--output', str(output / ORIGINAL)]
    return {'serde-error-rust-build': common + ['--rust-bin', str(Path(rustc).absolute().parent), '--phase', 'build'],
        'serde-error-rust-replay': common + ['--phase', 'replay']}


def original_evidence(root, output, report, completed):
    root, output, hepta, manifest = paths(root, output, report)
    observed = reference.original_evidence(root, hepta, manifest, output / NATIVE, output / ORIGINAL)
    commands = original_commands(root, output, report, Path(report['rust_compiler']['invocation_path']))
    expected = {
        'serde-error-rust-build': {'status': 'PASS', 'actual_build_processes': 4,
            'original_owner_calls': 0, 'fresh_rust_build': True},
        'serde-error-rust-replay': {'status': 'PASS', 'actual_replay_processes': 2,
            'original_owner_calls': 98701, 'native_cases_added_by_replay': 0},
    }
    receipts = {}
    for name, command in commands.items():
        row, summary = complete(root, output, report, name, command, completed)
        q.same(summary, expected[name], 'actual aggregate original diagnostic summary differs')
        receipts[name] = row
    artifacts = [path for path in (output / ORIGINAL).rglob('*') if path.is_file()]
    artifacts.extend(output / (name + suffix) for name in commands for suffix in ('.stdout', '.stderr'))
    return {'schema': 'hepta.runtime.serde-error-pipeline-original.v1', 'status': 'PASS',
        'owner_evidence': observed, 'completed_processes': receipts, 'artifact_sha256': keep(output, artifacts),
        'new_native_executions_by_admission': 0, 'new_original_executions_by_admission': 0,
        'generic_value_serialization_closed': False, 'whole_runtime_closed': False}
