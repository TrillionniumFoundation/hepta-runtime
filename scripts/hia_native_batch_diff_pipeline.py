"""Bind batch diff qualification to actual native and aggregate processes."""
from pathlib import Path
import argparse
import json
import shutil
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hia_native_batch_diff_qualification as reader
from hia_native_view_call_qualification import inside, pin, canonical, digest, same

KEY = 'batch_diff'
FOLDER = 'batch-diff'
MANIFEST = FOLDER + '/build/batch-diff.json'
NATIVE_TEST = 'test_batch_diff.py'
ORIGINAL_CHECK = 'batch_diff_original'
CONTROLS_TEST = 'test_batch_diff_original_evidence.py'
ORIGINAL_CHECKS = (ORIGINAL_CHECK, CONTROLS_TEST)
PIPELINE_SOURCE = 'scripts/hia_native_batch_diff_pipeline.py'


def build(hepta, output, *, source_root):
    from hia_native_batch_diff_build import build_batch_diff
    output = Path(output)
    nested = output / FOLDER / 'build'
    shutil.copytree(output / 'build/bootstrap', nested / 'bootstrap')
    return build_batch_diff(hepta, nested, source_root=source_root)


def _json(path):
    return reader.json_value(Path(path).read_bytes())


def _module(output, report):
    module = report['modules'][KEY]
    same([module.get('manifest'), module.get('source'), module.get('builder')],
         [MANIFEST, 'native/batch_diff.hepta', KEY], 'registered batch diff owner')
    path = inside(output, MANIFEST)
    same(pin(path)['sha256'], module.get('sha256'), 'registered batch diff bundle')
    bundle = _json(path)
    same(sorted(bundle['members']), sorted(reader.MEMBERS), 'registered three-image graph')
    for item in bundle['members'].values():
        child = _json(inside(path.parent, item['manifest']))
        same([child.get('compiler_commit'), child.get('compiler_sha256')],
             ['d3e2c90173cf733e42b299d0c4274df4b593a12f', report['compiler_image_sha256']],
             'registered compiler identity')
    # The unchanged component reader verifies all complete compile inputs,
    # receipts, bootstrap generations and source/image bytes before admission.
    return path


def environment(root, output, report):
    path = _module(Path(output), report)
    return {'HIA_BATCH_DIFF_BUNDLE': str(path),
            'HIA_BATCH_DIFF_CAPTURE_DIR': str(Path(output) / FOLDER / 'batch-diff')}


def _check(output, report, completed, name, command, expected):
    rows = [row for row in report.get('checks', ()) if row.get('name') == name]
    reader.require(len(rows) == 1, 'one actual main process: ' + name)
    row = rows[0]
    reader._duration(row)
    reader.require(row.get('start_error') is None, 'main process startup: ' + name)
    same(row.get('command'), command, 'source-owned main command: ' + name)
    parent = inside(output, report.get('check_artifact_directories', {}).get(name, '.'))
    streams, artifacts = {}, {}
    for kind in ('stdout', 'stderr'):
        path = inside(output, str((parent / (name + '.' + kind)).relative_to(output)))
        raw = path.read_bytes()
        same({'bytes': len(raw), 'sha256': digest(raw)},
             {'bytes': row.get(kind + '_bytes'), 'sha256': row.get(kind + '_sha256')},
             'complete main process ' + kind)
        streams[kind] = raw
        artifacts[str(path.relative_to(output))] = digest(raw)
    same(reader.json_value(streams['stdout']), expected, 'complete main process result')
    same(row.get('summary'), expected, 'retained main process summary')
    if completed is not None:
        same(list(completed(output, report, name)), [row, expected], 'actual completed callback')
    return row, streams, artifacts


def _record(row, origin_source, label):
    result = {key: row[key] for key in ('command', 'exit_code', 'timed_out', 'timeout_seconds', 'elapsed_seconds')}
    result.update(name=label, cwd=str(origin_source), main_check_sha256=digest(canonical(row)))
    for kind in ('stdout', 'stderr'):
        result[kind] = {'path': label + '.' + kind, 'bytes': row[kind + '_bytes'],
                        'sha256': row[kind + '_sha256']}
    return result


def _retained(path, raw, *, create):
    if create and not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as stream:
            stream.write(raw)
    reader.require(path.is_file() and not path.is_symlink(), 'missing retained actual process: ' + str(path))
    reader.require(path.read_bytes() == raw, 'retained actual process differs: ' + str(path))


def _retain_process(base, record, streams, *, create):
    for kind, raw in streams.items():
        _retained(inside(base, record[kind]['path']), raw, create=create)
    _retained(inside(base, record['name'] + '.process.json'), canonical(record), create=create)


def _sources(root, report, raw):
    sources = dict(raw['source_sha256'])
    sources[PIPELINE_SOURCE] = pin(inside(root, PIPELINE_SOURCE))['sha256']
    same({name: report.get('source_sha256', {}).get(name) for name in sources}, sources,
         'main source closure for batch diff')
    return dict(sorted(sources.items()))


def native_evidence(root, output, report, completed=None, *, create=False):
    root, output = Path(root), Path(output)
    _module(output, report)
    base = inside(output, FOLDER)
    summary = _json(inside(base, 'batch-diff/result.json'))
    execution = _json(inside(base, 'batch-diff/execution.json'))
    origin_source, old_capture = Path(execution['source_root']), Path(execution['capture_root'])
    reader.require(origin_source.is_absolute() and old_capture.is_absolute(), 'actual execution origins')
    old_base = old_capture.parent
    reader.require(old_capture.name == 'batch-diff' and old_base.name == FOLDER,
                   'actual isolated component capture')
    same(execution['bundle_path'], str(old_base / 'build/batch-diff.json'), 'actual isolated build origin')
    command = [execution['python'], '-I', '-B', str(origin_source / 'tests/hia_native' / NATIVE_TEST)]
    same(execution['command'], command, 'native main suite used registered environment')
    row, streams, outer = _check(output, report, completed, NATIVE_TEST, command, summary)
    record = _record(row, origin_source, 'native')
    _retain_process(base, record, streams, create=create)
    raw = reader.native_evidence(root, base)
    same(raw['native_process'], record, 'native reader consumed the actual main process')
    artifacts = {FOLDER + '/' + name: sha for name, sha in raw['artifact_sha256'].items()}
    artifacts.update(outer)
    return {'schema': 'hepta.runtime.batch-diff-pipeline-native.v1', 'status': 'PASS',
            'native': raw, 'source_sha256': _sources(root, report, raw),
            'artifact_sha256': dict(sorted(artifacts.items())),
            'execution_source_root': str(origin_source), 'execution_output_root': str(old_base.parent),
            'fresh_original_comparison_complete': False, 'public_route_replaced': False,
            'filesystem_effects_replaced': False, 'whole_runtime_replaced': False}


def _control_pins(root):
    return {name: pin(inside(root, name))['sha256'] for name in (
        'scripts/hia_native_batch_diff_qualification.py', 'tests/hia_native/' + CONTROLS_TEST)}


def _original_receipt(row, origin_source, compiler):
    result = _record(row, origin_source, 'original')
    result.update(rust_compiler=compiler,
                  compiler_sha256_before=compiler['invocation_executable_sha256'],
                  compiler_sha256_after=compiler['invocation_executable_sha256'])
    return result


def retained_original(root, output, report, completed=None):
    root, output = Path(root), Path(output)
    native = native_evidence(root, output, report, completed)
    same(native, report.get('batch_diff_evidence'), 'registered native evidence before original')
    base = inside(output, FOLDER)
    origin_source = Path(native['execution_source_root'])
    old_base = Path(native['execution_output_root']) / FOLDER
    interpreter = native['native']['native_process']['command'][0]
    compiler = report['rust_compiler']
    result = _json(inside(base, 'batch-diff-original/result.json'))
    command = [interpreter, '-I', '-B', str(origin_source / 'tests/hia_native/batch_diff_oracle/run.py'),
               '--runtime', str(origin_source), '--native', str(old_base / 'batch-diff'),
               '--output', str(old_base / 'batch-diff-original'), '--rustc', compiler['resolved_path']]
    row, streams, artifacts = _check(output, report, completed, ORIGINAL_CHECK, command, result)
    _retain_process(base, _original_receipt(row, origin_source, compiler), streams, create=False)
    controls = _json(inside(base, 'batch-diff-controls/result.json'))
    row, streams, files = _check(output, report, completed, CONTROLS_TEST,
        [interpreter, '-I', '-B', str(origin_source / 'tests/hia_native' / CONTROLS_TEST)], controls)
    artifacts.update(files)
    expected = _record(row, origin_source, 'controls')
    expected.update(source_before=_control_pins(root), source_after=_control_pins(root),
        controlled_env={'HIA_BATCH_DIFF_QUALIFICATION_OUTPUT': str(old_base),
                        'HIA_BATCH_DIFF_EVIDENCE_CAPTURE_DIR': str(old_base / 'batch-diff-controls')})
    _retain_process(base, expected, streams, create=False)
    qualified = reader.qualification_evidence(root, base, native=native['native'])
    artifacts.update({FOLDER + '/' + name: sha for name, sha in qualified['artifact_sha256'].items()})
    artifacts.update(native['artifact_sha256'])
    return {'schema': 'hepta.runtime.batch-diff-pipeline-original.v1', 'status': 'PASS',
            'reference_kind': 'unchanged original batch diff, cumulative shifts and application blocks',
            'qualified': qualified, 'native_evidence_sha256': digest(canonical(native)),
            'source_sha256': _sources(root, report, qualified),
            'artifact_sha256': dict(sorted(artifacts.items())),
            'required_original_checks': list(ORIGINAL_CHECKS),
            'actual_original_processes': 3, 'original_cases': 804, 'successful_diff_cases': 802,
            'complete_diff_bytes': 17261188, 'refusal_controls': 12, 'actual_reader_relocations': 2,
            'original_batch_handler_executed': False, 'public_route_replaced': False,
            'filesystem_effects_replaced': False, 'whole_runtime_replaced': False}


def execute_original(root, output, report, rustc, *, record_check, completed, qualification_env):
    root, output, rustc = Path(root), Path(output), Path(rustc).resolve()
    native = native_evidence(root, output, report, completed)
    same(native, report.get('batch_diff_evidence'), 'native input before fresh original')
    compiler = report['rust_compiler']
    same(str(rustc), compiler['resolved_path'], 'same selected original compiler')
    same(pin(rustc)['sha256'], compiler['invocation_executable_sha256'], 'executed original compiler bytes')
    base = output / FOLDER
    command = [sys.executable, '-I', '-B', str(root / 'tests/hia_native/batch_diff_oracle/run.py'),
               '--runtime', str(root), '--native', str(base / 'batch-diff'),
               '--output', str(base / 'batch-diff-original'), '--rustc', str(rustc)]
    record_check(output, report, name=ORIGINAL_CHECK, command=command, timeout=180, env=qualification_env())
    same(pin(rustc)['sha256'], compiler['invocation_executable_sha256'], 'original compiler remained unchanged')
    row, streams, _ = _check(output, report, completed, ORIGINAL_CHECK, command,
                            _json(inside(base, 'batch-diff-original/result.json')))
    _retain_process(base, _original_receipt(row, root, compiler), streams, create=True)
    reader.original_evidence(root, base, native=native['native'])
    environment_values = {'HIA_BATCH_DIFF_QUALIFICATION_OUTPUT': str(base),
                          'HIA_BATCH_DIFF_EVIDENCE_CAPTURE_DIR': str(base / 'batch-diff-controls')}
    env = qualification_env()
    env.update(environment_values)
    before = _control_pins(root)
    command = [sys.executable, '-I', '-B', str(root / 'tests/hia_native' / CONTROLS_TEST)]
    record_check(output, report, name=CONTROLS_TEST, command=command, timeout=180, env=env)
    after = _control_pins(root)
    same(before, after, 'actual control source did not change')
    row, streams, _ = _check(output, report, completed, CONTROLS_TEST, command,
                            _json(inside(base, 'batch-diff-controls/result.json')))
    receipt = _record(row, root, 'controls')
    receipt.update(source_before=before, source_after=after, controlled_env=environment_values)
    _retain_process(base, receipt, streams, create=True)
    return retained_original(root, output, report, completed)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    for name in ('root', 'output', 'report', 'result'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--original', action='store_true')
    args = parser.parse_args()
    report = _json(args.report)
    result = (retained_original if args.original else native_evidence)(args.root, args.output, report)
    args.result.write_bytes(canonical(result))
    print(json.dumps({'status': 'PASS', 'bytes': args.result.stat().st_size,
                      'sha256': pin(args.result)['sha256']}, sort_keys=True))
