"""Main-pipeline registration for native batch Planner input and original parity."""
from pathlib import Path
import argparse
import json
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hia_native_batch_plan_input_qualification as reader
from hia_native_view_call_qualification import inside, pin, canonical, digest

KEY = 'batch_plan_input'
FOLDER = 'batch-plan-input'
MANIFEST = FOLDER + '/build/members.json'
NATIVE_TEST = 'test_batch_plan_input.py'
ORIGINAL_CHECK = 'batch-plan-input-original'
CONTROLS_TEST = 'test_batch_plan_input_original_evidence.py'
PIPELINE_SOURCE = 'scripts/hia_native_batch_plan_input_pipeline.py'


def _json(path):
    return reader.json_value(Path(path).read_bytes())


def _module(output, report):
    module = report['modules'][KEY]
    reader.same([module.get('manifest'), module.get('source'), module.get('builder')],
                [MANIFEST, 'native/batch_plan_input.hepta', KEY], 'registered batch input owner')
    path = inside(output, MANIFEST)
    reader.same(pin(path)['sha256'], module.get('sha256'), 'registered batch input bundle')
    bundle = _json(path)
    reader.same([bundle.get('compiler_commit'), bundle.get('compiler_sha256')],
                [reader.COMMIT, report['compiler_image_sha256']], 'registered compiler identity')
    return path, bundle


def environment(root, output, report):
    path, _ = _module(Path(output), report)
    return {'HIA_BATCH_PLAN_INPUT_MEMBERS': str(path),
            'HIA_BATCH_PLAN_INPUT_CAPTURE_DIR': str(Path(output) / FOLDER / 'native')}


def _check(output, report, completed, name, command, expected):
    rows = [row for row in report.get('checks', ()) if row.get('name') == name]
    reader.need(len(rows) == 1, 'one actual main process: ' + name)
    row = rows[0]
    reader.duration(row)
    reader.need(not row.get('start_error'), 'main process startup: ' + name)
    reader.same(row.get('command'), command, 'source-owned main command: ' + name)
    reader.same(row.get('cwd'), str(Path(command[3]).parents[2]) if name != ORIGINAL_CHECK
                else str(Path(command[3]).parents[3]), 'actual main process cwd')
    streams, artifacts = {}, {}
    parent = inside(output, report.get('check_artifact_directories', {}).get(name, '.'))
    for kind in ('stdout', 'stderr'):
        path = inside(output, str((parent / (name + '.' + kind)).relative_to(output)))
        raw = path.read_bytes()
        reader.same({'bytes': len(raw), 'sha256': digest(raw)},
                    {'bytes': row.get(kind + '_bytes'), 'sha256': row.get(kind + '_sha256')},
                    'complete main process ' + kind)
        streams[kind] = raw
        artifacts[str(path.relative_to(output))] = digest(raw)
    reader.same(reader.json_value(streams['stdout']), expected, 'complete main process result')
    reader.same(row.get('summary'), expected, 'retained main process summary')
    if completed is not None:
        reader.same(list(completed(output, report, name)), [row, expected], 'actual completed callback')
    return row, streams, artifacts


def _record(row, origin_source, label):
    result = {key: row[key] for key in ('command', 'pid', 'exit_code', 'timed_out', 'timeout_seconds', 'elapsed_seconds')}
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
    reader.need(path.is_file() and not path.is_symlink(), 'missing retained actual process: ' + str(path))
    reader.need(path.read_bytes() == raw, 'retained actual process differs: ' + str(path))


def _retain_phase(base, row, streams, source, label, *, create):
    record = _record(row, source, label)
    for kind, raw in streams.items():
        _retained(inside(base, record[kind]['path']), raw, create=create)
    _retained(inside(base, label + '.process.json'), canonical(record), create=create)
    return record


def _sources(root, report, raw):
    sources = dict(raw['source_sha256'])
    for name in (PIPELINE_SOURCE, 'scripts/qualify_hia_runtime_native.py',
                 'scripts/compare_hia_runtime_rust.py', 'scripts/hia_native_pipeline.py'):
        sources[name] = pin(inside(root, name))['sha256']
    reader.same({name: report.get('source_sha256', {}).get(name) for name in sources}, sources,
                'main source closure for batch input')
    return dict(sorted(sources.items()))


def native_evidence(root, output, report, completed=None, *, create=False):
    root, output = Path(root), Path(output)
    _module(output, report)
    base = inside(output, FOLDER)
    summary = _json(inside(base, 'native/result.json'))
    origin_source = Path(summary['execution_source_root'])
    origin_output = Path(summary['execution_output_root'])
    reader.need(origin_source.is_absolute() and origin_output.is_absolute() and origin_output.name == FOLDER,
                'actual isolated source/component output')
    expected = {**summary, 'skipped': 0, 'errors': 0, 'failures': 0}
    command = [summary['python'], '-I', '-B', str(origin_source / 'tests/hia_native' / NATIVE_TEST)]
    row, streams, outer = _check(output, report, completed, NATIVE_TEST, command, expected)
    record = _retain_phase(base, row, streams, origin_source, 'native', create=create)
    raw = reader.native_evidence(root, base)
    reader.same(raw['native_process'], record, 'native reader consumed the actual main process')
    artifacts = {FOLDER + '/' + name: sha for name, sha in raw['artifact_sha256'].items()}
    artifacts.update(outer)
    return {'schema': 'hepta.runtime.batch-plan-input-pipeline-native.v1', 'status': 'PASS',
            'native': raw, 'source_sha256': _sources(root, report, raw),
            'artifact_sha256': dict(sorted(artifacts.items())),
            'execution_source_root': str(origin_source), 'execution_output_root': str(origin_output.parent),
            'fresh_original_comparison_complete': False, 'public_route_replaced': False,
            'whole_runtime_replaced': False}


def _control_pins(root):
    return {name: pin(inside(root, name))['sha256'] for name in (
        'scripts/hia_native_batch_plan_input_qualification.py', 'tests/hia_native/' + CONTROLS_TEST)}


def _original_command(interpreter, source, base, rustc):
    return [interpreter, '-I', '-B', str(source / 'tests/hia_native/batch_plan_input_oracle/run.py'),
            '--runtime', str(source), '--output', str(base / 'original'),
            '--native', str(base / 'native'), '--rust-bin', str(rustc.parent)]


def retained_original(root, output, report, completed=None):
    root, output = Path(root), Path(output)
    native = native_evidence(root, output, report, completed)
    reader.same(native, report.get('batch_plan_input_evidence'), 'sealed native evidence after original')
    base = inside(output, FOLDER)
    origin_source = Path(native['execution_source_root'])
    old_base = Path(native['execution_output_root']) / FOLDER
    interpreter = native['native']['native_process']['command'][0]
    rustc = report['rust_compiler']; selected = Path(rustc['resolved_path'])
    result = _json(inside(base, 'original/result.json'))
    reader.same(result['toolchain_before_and_after']['rustc']['path'], str(selected), 'same selected original compiler')
    reader.same(result['toolchain_before_and_after']['rustc']['sha256'], rustc['invocation_executable_sha256'],
                'same executed compiler bytes')
    command = _original_command(interpreter, origin_source, old_base, selected)
    row, streams, artifacts = _check(output, report, completed, ORIGINAL_CHECK, command, result)
    _retain_phase(base, row, streams, origin_source, 'original', create=False)
    controls = _json(inside(base, 'controls/result.json'))
    row, streams, files = _check(output, report, completed, CONTROLS_TEST,
        [interpreter, '-I', '-B', str(origin_source / 'tests/hia_native' / CONTROLS_TEST)], controls)
    artifacts.update(files)
    expected = _record(row, origin_source, 'controls')
    expected.update(source_before=_control_pins(root), source_after=_control_pins(root),
        controlled_env={'HIA_BATCH_PLAN_INPUT_QUALIFICATION_OUTPUT': str(old_base),
                        'HIA_BATCH_PLAN_INPUT_EVIDENCE_CAPTURE_DIR': str(old_base / 'controls')})
    reader.same(_json(inside(base, 'controls.process.json')), expected, 'actual control source and process binding')
    for kind, raw in streams.items():
        reader.need(inside(base, expected[kind]['path']).read_bytes() == raw, 'complete actual control stream copy')
    qualified = reader.qualification_evidence(root, base, native=native['native'])
    artifacts.update({FOLDER + '/' + name: sha for name, sha in qualified['artifact_sha256'].items()})
    artifacts.update(native['artifact_sha256'])
    return {'schema': 'hepta.runtime.batch-plan-input-pipeline-original.v1', 'status': 'PASS',
            'reference_kind': 'unchanged original BatchEditParams, EditableContent, Value and Rust str.lines',
            'qualified': qualified, 'native_evidence_sha256': digest(canonical(native)),
            'source_sha256': _sources(root, report, qualified), 'artifact_sha256': dict(sorted(artifacts.items())),
            'actual_original_processes': 4, 'semantic_inputs': 463, 'semantic_records': 926,
            'refusal_controls': 12, 'actual_reader_relocations': 2,
            'original_batch_handler_executed': False, 'effects_executed': False,
            'public_route_replaced': False, 'whole_runtime_replaced': False}


def execute_original(root, output, report, rustc, *, record_check, completed, qualification_env):
    root, output, rustc = Path(root), Path(output), Path(rustc).resolve()
    native = native_evidence(root, output, report, completed)
    reader.same(native, report.get('batch_plan_input_evidence'), 'native input before fresh original')
    base = output / FOLDER
    command = _original_command(sys.executable, root, base, rustc)
    record_check(output, report, name=ORIGINAL_CHECK, command=command, timeout=180,
                 env=qualification_env(), record_identity=True)
    row, streams, _ = _check(output, report, completed, ORIGINAL_CHECK, command, _json(base / 'original/result.json'))
    _retain_phase(base, row, streams, root, 'original', create=True)
    reader.native_evidence(root, base, original=True)
    values = {'HIA_BATCH_PLAN_INPUT_QUALIFICATION_OUTPUT': str(base),
              'HIA_BATCH_PLAN_INPUT_EVIDENCE_CAPTURE_DIR': str(base / 'controls')}
    env = qualification_env(); env.update(values)
    before = _control_pins(root)
    command = [sys.executable, '-I', '-B', str(root / 'tests/hia_native' / CONTROLS_TEST)]
    record_check(output, report, name=CONTROLS_TEST, command=command, timeout=180, env=env, record_identity=True)
    after = _control_pins(root)
    reader.same(before, after, 'actual control sources did not change')
    row, streams, _ = _check(output, report, completed, CONTROLS_TEST, command, _json(base / 'controls/result.json'))
    receipt = _record(row, root, 'controls')
    receipt.update(source_before=before, source_after=after, controlled_env=values)
    for kind, raw in streams.items():
        _retained(inside(base, receipt[kind]['path']), raw, create=True)
    _retained(inside(base, 'controls.process.json'), canonical(receipt), create=True)
    return retained_original(root, output, report, completed)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    for flag in ('root', 'output', 'report', 'result'):
        parser.add_argument('--' + flag, type=Path, required=True)
    parser.add_argument('--original', action='store_true'); args = parser.parse_args()
    report = _json(args.report)
    result = (retained_original if args.original else native_evidence)(args.root, args.output, report)
    args.result.write_bytes(canonical(result))
    print(json.dumps({'status': 'PASS', 'bytes': args.result.stat().st_size,
                      'sha256': pin(args.result)['sha256']}, sort_keys=True))
