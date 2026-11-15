"""Register complete batch parameter captures and fresh original qualification."""
from pathlib import Path
import argparse
import json
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hia_native_batch_edit_params_qualification as reader
from hia_native_view_call_qualification import inside, pin, canonical, digest, same

KEY = 'batch_edit_params'
FOLDER = 'batch-edit-params'
MANIFEST = FOLDER + '/build/batch-edit-params.json'
NATIVE_TEST = 'test_batch_edit_params.py'
ORIGINAL_CHECK = 'batch-edit-params-original'
CONTROLS_TEST = 'test_batch_edit_params_original_evidence.py'
PIPELINE_SOURCE = 'scripts/hia_native_batch_edit_params_pipeline.py'


def _json(path):
    return reader.json_value(Path(path).read_bytes())


def _module(output, report):
    module = report['modules'][KEY]
    same([module.get('manifest'), module.get('source'), module.get('builder')],
         [MANIFEST, 'native/batch_edit_params.hepta', KEY], 'registered batch params owner')
    path = inside(output, MANIFEST)
    same(pin(path)['sha256'], module.get('sha256'), 'registered batch params bundle')
    bundle = _json(path)
    same([bundle.get('compiler_commit'), bundle.get('compiler_sha256')],
         ['d3e2c90173cf733e42b299d0c4274df4b593a12f', report['compiler_image_sha256']],
         'registered compiler identity')
    return path, bundle


def environment(root, output, report):
    path, bundle = _module(Path(output), report)
    return {
        'HIA_BATCH_EDIT_PARAMS_MANIFEST': str(inside(path.parent, bundle['members']['projection']['manifest'])),
        'HIA_BATCH_EDIT_PARAMS_VALUE_MANIFEST': str(inside(path.parent, bundle['members']['value']['manifest'])),
        'HIA_BATCH_EDIT_PARAMS_CAPTURE_DIR': str(Path(output) / FOLDER / 'native'),
    }


def _check(output, report, completed, name, command, expected):
    rows = [row for row in report.get('checks', ()) if row.get('name') == name]
    reader.require(len(rows) == 1, 'one actual main process: ' + name)
    row = rows[0]
    reader._duration(row)
    reader.require(not row.get('start_error'), 'main process startup: ' + name)
    same(row.get('command'), command, 'source-owned main command: ' + name)
    streams = {}
    folder = report.get('check_artifact_directories', {}).get(name, '.')
    parent = inside(output, folder)
    artifacts = {}
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


def _sources(root, report, raw):
    sources = dict(raw['source_sha256'])
    sources[PIPELINE_SOURCE] = pin(inside(root, PIPELINE_SOURCE))['sha256']
    same({name: report.get('source_sha256', {}).get(name) for name in sources}, sources,
         'main source closure for batch params')
    return dict(sorted(sources.items()))


def native_evidence(root, output, report, completed=None, *, create=False):
    root, output = Path(root), Path(output)
    _module(output, report)
    base = inside(output, FOLDER)
    summary = _json(inside(base, 'native/result.json'))
    origin_output = Path(summary['manifest']).parents[3]
    reader.require(origin_output.is_absolute() and origin_output.name == FOLDER,
                   'actual isolated component output')
    rows = [row for row in report.get('checks', ()) if row.get('name') == NATIVE_TEST]
    reader.require(len(rows) == 1, 'one native batch params process')
    command = rows[0].get('command')
    reader.require(type(command) is list and len(command) == 4, 'actual native suite invocation')
    origin_source = Path(command[3]).parent.parent.parent
    reader.require(origin_source.is_absolute(), 'actual source origin')
    expected = {**summary, 'skipped': 0, 'errors': 0, 'failures': 0}
    row, streams, outer = _check(output, report, completed, NATIVE_TEST,
        [summary['python'], '-I', '-B', str(origin_source / 'tests/hia_native' / NATIVE_TEST)], expected)
    record = _record(row, origin_source, 'native')
    for kind, raw in streams.items():
        _retained(inside(base, record[kind]['path']), raw, create=create)
    _retained(inside(base, 'processes.json'), canonical([record]), create=create)
    raw = reader.native_evidence(root, base)
    same(raw['native_process'], record, 'native reader consumed the actual main process')
    artifacts = {FOLDER + '/' + name: sha for name, sha in raw['artifact_sha256'].items()}
    artifacts[FOLDER + '/processes.json'] = pin(inside(base, 'processes.json'))['sha256']
    artifacts.update(outer)
    return {
        'schema': 'hepta.runtime.batch-edit-params-pipeline-native.v1', 'status': 'PASS',
        'native': raw, 'source_sha256': _sources(root, report, raw),
        'artifact_sha256': dict(sorted(artifacts.items())),
        'execution_source_root': str(origin_source), 'execution_output_root': str(origin_output.parent),
        'fresh_original_comparison_complete': False, 'public_route_replaced': False,
        'whole_runtime_replaced': False,
    }


def _control_pins(root):
    return {name: pin(inside(root, name))['sha256'] for name in (
        'scripts/hia_native_batch_edit_params_qualification.py',
        'tests/hia_native/' + CONTROLS_TEST)}


def retained_original(root, output, report, completed=None):
    root, output = Path(root), Path(output)
    native = native_evidence(root, output, report, completed)
    same(native, report.get('batch_edit_params_evidence'), 'registered native evidence before original')
    base = inside(output, FOLDER)
    origin_source = Path(native['execution_source_root'])
    origin_output = Path(native['execution_output_root'])
    old_base = origin_output / FOLDER
    interpreter = native['native']['native_process']['command'][0]
    rustc = report['rust_compiler']
    result = _json(inside(base, 'original/result.json'))
    selected = Path(rustc['resolved_path'])
    same(result['toolchain']['rustc']['path'], str(selected), 'same selected original compiler')
    same(result['toolchain']['rustc']['sha256'], rustc['invocation_executable_sha256'],
         'same executed compiler bytes')
    command = [interpreter, '-I', '-B',
               str(origin_source / 'tests/hia_native/batch_edit_params_oracle/run.py'),
               '--runtime', str(origin_source), '--output', str(old_base / 'original'),
               '--rust-bin', str(selected.parent)]
    _, _, artifacts = _check(output, report, completed, ORIGINAL_CHECK, command, result)
    controls = _json(inside(base, 'controls/result.json'))
    row, streams, files = _check(output, report, completed, CONTROLS_TEST,
        [interpreter, '-I', '-B', str(origin_source / 'tests/hia_native' / CONTROLS_TEST)], controls)
    artifacts.update(files)
    recorded = _json(inside(base, 'controls.process.json'))
    expected = _record(row, origin_source, 'controls')
    expected.update(source_before=_control_pins(root), source_after=_control_pins(root),
        controlled_env={
            'HIA_BATCH_EDIT_PARAMS_QUALIFICATION_OUTPUT': str(old_base),
            'HIA_BATCH_EDIT_PARAMS_EVIDENCE_CAPTURE_DIR': str(old_base / 'controls'),
        })
    same(recorded, expected, 'actual control process and source binding')
    for kind, raw in streams.items():
        reader.require(inside(base, expected[kind]['path']).read_bytes() == raw,
                       'complete actual control stream copy')
    qualified = reader.qualification_evidence(root, base, native=native['native'])
    artifacts.update({FOLDER + '/' + name: sha for name, sha in qualified['artifact_sha256'].items()})
    artifacts[FOLDER + '/processes.json'] = pin(inside(base, 'processes.json'))['sha256']
    artifacts.update(native['artifact_sha256'])
    return {
        'schema': 'hepta.runtime.batch-edit-params-pipeline-original.v1', 'status': 'PASS',
        'reference_kind': 'unchanged original BatchEditParams and actual SDK extraction',
        'qualified': qualified, 'native_evidence_sha256': digest(canonical(native)),
        'source_sha256': _sources(root, report, qualified),
        'artifact_sha256': dict(sorted(artifacts.items())),
        'actual_original_processes': 3, 'typed_cases': 417, 'sdk_cases': 22,
        'refusal_controls': 12, 'actual_reader_relocations': 2,
        'original_batch_handler_executed': False, 'public_route_replaced': False,
        'whole_runtime_replaced': False,
    }


def execute_original(root, output, report, rustc, *, record_check, completed, qualification_env):
    root, output, rustc = Path(root), Path(output), Path(rustc).resolve()
    native = native_evidence(root, output, report, completed)
    same(native, report.get('batch_edit_params_evidence'), 'native input before fresh original')
    base = output / FOLDER
    command = [sys.executable, '-I', '-B', str(root / 'tests/hia_native/batch_edit_params_oracle/run.py'),
               '--runtime', str(root), '--output', str(base / 'original'),
               '--rust-bin', str(rustc.parent)]
    record_check(output, report, name=ORIGINAL_CHECK, command=command, timeout=180, env=qualification_env())
    reader.original_evidence(root, base, native=native['native'])
    environment_values = {
        'HIA_BATCH_EDIT_PARAMS_QUALIFICATION_OUTPUT': str(base),
        'HIA_BATCH_EDIT_PARAMS_EVIDENCE_CAPTURE_DIR': str(base / 'controls'),
    }
    env = qualification_env()
    env.update(environment_values)
    before = _control_pins(root)
    record_check(output, report, name=CONTROLS_TEST,
        command=[sys.executable, '-I', '-B', str(root / 'tests/hia_native' / CONTROLS_TEST)],
        timeout=180, env=env)
    after = _control_pins(root)
    same(before, after, 'actual control source did not change')
    row, streams, _ = _check(output, report, completed, CONTROLS_TEST,
        [sys.executable, '-I', '-B', str(root / 'tests/hia_native' / CONTROLS_TEST)],
        _json(inside(base, 'controls/result.json')))
    receipt = _record(row, root, 'controls')
    receipt.update(source_before=before, source_after=after, controlled_env=environment_values)
    for kind, raw in streams.items():
        _retained(inside(base, receipt[kind]['path']), raw, create=True)
    _retained(inside(base, 'controls.process.json'), canonical(receipt), create=True)
    return retained_original(root, output, report, completed)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--result', type=Path, required=True)
    parser.add_argument('--original', action='store_true')
    args = parser.parse_args()
    report = _json(args.report)
    result = (retained_original if args.original else native_evidence)(args.root, args.output, report)
    args.result.write_bytes(canonical(result))
    print(json.dumps({'status': 'PASS', 'bytes': args.result.stat().st_size,
                      'sha256': pin(args.result)['sha256']}, sort_keys=True))
