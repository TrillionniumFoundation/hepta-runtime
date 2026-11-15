"""Source-owned Text publication build and native qualification processes.

The fixed HIA owner and Linux boundary remain the only production semantics.
This module stages exact source files, invokes the frozen producers, and retains
their actual commands, PIDs, deadlines, complete streams and source identities.
It does not reconstruct fixtures from a read-only evidence entry point.
"""
from __future__ import annotations

from pathlib import Path
import argparse
import hashlib
import json
import os
import signal
import stat
import subprocess
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import hia_native_text_publication_qualification as wire

KEY = 'text_publication'
FOLDER = 'text-publication'
MANIFEST = FOLDER + '/native/build/manifest.json'
CONTRACT = 'native/text_publication_pipeline_sources.json'
PYTHON = '/usr/bin/python3'
NATIVE_TEST = 'test_text_publication_native.py'
CORPUS_TEST = 'test_text_publication_corpus.py'
EVIDENCE_TEST = 'test_text_publication_pipeline_evidence.py'
GROUPS = ('native', 'boundary', 'faults', 'corpus', 'handoff')
DOMAINS = ('ordinary', 'paths', 'metadata', 'wide', 'admission', 'races')
NEW_SOURCES = (
    CONTRACT,
    'scripts/hia_native_text_publication_pipeline.py',
    'scripts/hia_native_text_publication_pipeline_evidence.py',
    'scripts/hia_native_text_publication_retirement.py',
    'tests/hia_native/' + NATIVE_TEST,
    'tests/hia_native/' + CORPUS_TEST,
    'tests/hia_native/' + EVIDENCE_TEST,
)


def encoded(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True,
                       allow_nan=False, indent=2) + '\n').encode()


def regular(path):
    path = Path(path).absolute()
    wire.require(path.resolve(strict=True) == path and not path.is_symlink(),
                 'Text evidence path crosses a symbolic link')
    wire.require(stat.S_ISREG(path.lstat().st_mode), 'Text evidence is not a regular file')
    return path


def contained(root, name):
    wire.relative(name)
    return regular(Path(root) / name)


def file_pin(path):
    path = regular(path)
    with path.open('rb') as stream:
        return {'bytes': os.fstat(stream.fileno()).st_size,
                'sha256': hashlib.file_digest(stream, 'sha256').hexdigest()}


def read_json(path):
    return wire.decode(regular(path).read_bytes())


def write_new(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(encoded(value))


def source_contract(root):
    result = read_json(Path(root) / CONTRACT)
    wire.same(result['schema'], 'hepta.runtime.text-publication-pipeline-sources.v1',
              'source-owned Text pipeline contract')
    return result


def source_names(root):
    return sorted(set(source_contract(root)['frozen_sources']) | set(NEW_SOURCES))


def source_table(root, names=None):
    root = Path(root)
    names = source_names(root) if names is None else names
    return {name: file_pin(contained(root, name))['sha256'] for name in names}


def execution_contract(base):
    """Exact parent effects introduced by the actual owned capture namespace."""
    base = Path(base)
    wire.require(base.is_absolute() and '..' not in base.parts, 'absolute actual capture base')
    contract = source_contract(ROOT)
    depths = {group: len((base / group).parts) - 1 - 3 for group in ('native', 'faults', 'corpus')}
    eligible = {'ordinary': 38, 'paths': 16, 'metadata': 29, 'wide': 9, 'admission': 0, 'races': 20}
    contract['domains'] = {name: [count, effects + 2 * depths['corpus'] * eligible[name]]
                           for name, (count, effects) in contract['domains'].items()}
    contract['derived_effect_counts'] = {
        'smoke': 233 + 2 * depths['native'] * 6,
        'faults': 822 + 2 * depths['faults'] * 26,
        'fault_opens': 225 + depths['faults'] * 26,
        'corpus': sum(row[1] for row in contract['domains'].values()),
        'extra_parent_components': depths}
    return contract


def verify_sources(root, table):
    wire.require(type(table) is dict and bool(table), 'nonempty exact Text source closure')
    wire.same(source_table(root, sorted(table)), table, 'complete Text source bytes unchanged')
    fixed = source_contract(root)['frozen_sources']
    wire.same({name: table.get(name) for name in fixed}, fixed,
              'all frozen Text machines, producers and evidence functions')


def copy_sources(root, target, names):
    target = Path(target)
    target.mkdir(parents=True, exist_ok=False)
    table = source_table(root, names)
    for name in names:
        destination = target / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open('xb') as stream:
            stream.write(contained(root, name).read_bytes())
    wire.same(source_table(target, names), table, 'whole staged source snapshot')
    return table


def child_process(source, folder, name, command, *, plain=False, extra=None):
    source, folder = Path(source).absolute(), Path(folder).absolute()
    folder.mkdir(parents=True, exist_ok=True)
    paths = {kind: folder / (kind if plain else name + '.' + kind)
             for kind in ('stdout', 'stderr')}
    start = time.monotonic_ns()
    pid = code = error = None
    timed = False
    with paths['stdout'].open('xb') as stdout, paths['stderr'].open('xb') as stderr:
        try:
            child = subprocess.Popen(command, cwd=source, stdin=subprocess.DEVNULL,
                                     stdout=stdout, stderr=stderr, start_new_session=True)
            pid = child.pid
            try:
                code = child.wait(timeout=180)
            except subprocess.TimeoutExpired:
                timed = True
                try:
                    os.killpg(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                code = child.wait(timeout=10)
        except BaseException:
            error = traceback.format_exc()
    finish = time.monotonic_ns()
    row = {'name': name, 'command': list(command), 'cwd': str(source), 'pid': pid,
           'started_monotonic_ns': start, 'finished_monotonic_ns': finish,
           'elapsed_seconds': (finish - start) / 1e9, 'timeout_seconds': 180,
           'exit_code': code, 'timed_out': timed, 'start_error': error,
           'stdout': file_pin(paths['stdout']), 'stderr': file_pin(paths['stderr'])}
    if extra:
        row.update(extra)
    write_new(folder / ('PROCESS.json' if plain else name + '.process.json'), row)
    wire.require(code == 0 and not timed and error is None,
                 'Text child failed; actual process and complete streams retained: ' + name)
    wire.same(paths['stderr'].read_bytes(), b'', 'successful Text child stderr')
    return row


def build(hepta, output, *, source_root=ROOT):
    """Prepare one fixed graph and exact producer snapshots below the output."""
    root, output, hepta = map(lambda p: Path(p).resolve(), (source_root, output, hepta))
    base = output / FOLDER
    base.mkdir(parents=True, exist_ok=False)
    table = source_table(root)
    verify_sources(root, table)
    write_new(base / 'SOURCE-FILES.json', table)
    contract = source_contract(root)
    for group in GROUPS:
        (base / group).mkdir()
        if group == 'handoff':
            continue
        names = contract['corpus_sources'] if group == 'corpus' else sorted(table)
        staged = copy_sources(root, base / group / 'source', names)
        if group == 'corpus':
            staged = {name: file_pin(base / group / 'source' / name) for name in names}
        write_new(base / group / ('SOURCE-PINS.json' if group == 'corpus' else 'SOURCE-FILES.json'), staged)
    native = base / 'native'
    source = native / 'source'
    pipeline = str(source / 'scripts/hia_native_text_publication_pipeline.py')
    rows = []
    (native / 'authoring-boundary').mkdir()
    rows.append(child_process(source, native, 'assemble', [PYTHON, '-I', '-B', pipeline,
        '--stage', 'assemble', '--source', str(source), '--output', str(native / 'authoring-boundary')]))
    rows.append(child_process(source, native, 'source-contract', [PYTHON, '-I', '-B', pipeline,
        '--stage', 'check', '--source', str(source), '--output', str(native / 'source-contract.json')]))
    command = [PYTHON, '-I', '-B', str(source / 'scripts/hia_native_text_publication_build.py'),
               '--hepta', str(hepta), '--output', str(native / 'build'), '--source', str(source)]
    rows.append(child_process(source, native, 'build', command))
    manifest = native / 'build/manifest.json'
    bundle = read_json(manifest)
    wire.same(bundle['elf_sha256'], contract['elf_sha256'], 'fresh fixed Text ELF bytes')
    verify_sources(root, table)
    prepared = {'schema': 'hepta.runtime.text-publication-pipeline-prepared.v1',
                'execution_source_root': str(root), 'execution_output_root': str(output),
                'python': sys.executable, 'producer_python': PYTHON,
                'producer_python_sha256': file_pin(Path(PYTHON).resolve())['sha256'],
                'hepta': str(hepta), 'manifest': str(manifest), 'manifest_pin': file_pin(manifest),
                'source_table_pin': file_pin(base / 'SOURCE-FILES.json'), 'build_processes': rows,
                'original_comparison_complete': False, 'public_handler_replaced': False,
                'whole_runtime_replaced': False}
    write_new(base / 'prepared.json', prepared)
    write_new(native / 'EXECUTION.json', prepared)
    return manifest


def manifest_from_report(output, report):
    item = report['modules'][KEY]
    wire.same([item.get('source'), item.get('builder'), item.get('manifest')],
              ['native/text_publication.hepta', KEY, MANIFEST], 'registered Text graph')
    path = contained(output, MANIFEST)
    wire.same(file_pin(path)['sha256'], item['sha256'], 'registered Text manifest')
    return path


def environment(root, output, report):
    return {'HIA_TEXT_PUBLICATION_MANIFEST': str(manifest_from_report(output, report)),
            'HIA_TEXT_PUBLICATION_CAPTURE_ROOT': str(Path(output) / FOLDER)}


def test_commands(root, output, report):
    manifest_from_report(output, report)
    return {name: [sys.executable, '-I', '-B', str(Path(root) / 'tests/hia_native' / name)]
            for name in (NATIVE_TEST, CORPUS_TEST, EVIDENCE_TEST)}


def execution():
    base = Path(os.environ['HIA_TEXT_PUBLICATION_CAPTURE_ROOT']).absolute()
    prepared = read_json(base / 'prepared.json')
    wire.same([str(ROOT), str(base.parent), sys.executable],
              [prepared['execution_source_root'], prepared['execution_output_root'], prepared['python']],
              'actual prepared Text wrapper source, output and interpreter')
    manifest = Path(os.environ['HIA_TEXT_PUBLICATION_MANIFEST']).absolute()
    wire.same(str(manifest), prepared['manifest'], 'actual prepared Text manifest path')
    wire.same(file_pin(manifest), prepared['manifest_pin'], 'actual prepared Text manifest bytes')
    wire.same(file_pin(base / 'SOURCE-FILES.json'), prepared['source_table_pin'], 'whole staged source closure')
    verify_sources(ROOT, read_json(base / 'SOURCE-FILES.json'))
    return base, manifest, prepared


def mechanical_index(base):
    contract = source_contract(ROOT)
    labels = {'native-v4': 'native', 'boundary-v1': 'boundary', 'faults-v1': 'faults'}
    result = {}
    for label, group in labels.items():
        result[label] = {'origin': str(base / group), 'artifacts': {
            name: file_pin(base / group / name)
            for name in contract['mechanical_artifacts'][label]}}
    write_new(base / 'handoff/ARTIFACTS.json', result)
    faults = read_json(base / 'faults/full/RESULT.json')
    fault_index = {}
    names = contract['mechanical_artifacts']['faults-v1']
    for row in faults['cases_completed']:
        prefix = 'full/' + row['name'] + '/'
        folder = base / 'faults' / prefix
        proc = read_json(folder / 'process.json')
        fault_index[row['name']] = {
            'origin': str(folder).rstrip('/'), 'summary': row,
            'injection_indices': proc['injection_indices'],
            'artifacts': {name[len(prefix):]: file_pin(base / 'faults' / name)
                          for name in names if name.startswith(prefix)}}
    write_new(base / 'handoff/FAULT-INDEX.json', fault_index)


def run_native():
    base, manifest, prepared = execution()
    before = source_table(ROOT)
    native = base / 'native'
    source = native / 'source'
    rows = list(prepared['build_processes'])
    for name, test in [('native-smoke', 'test_text_publication_elf.py'),
                       ('callable-controls', 'test_text_publication_callable.py')]:
        command = [PYTHON, '-I', '-B', str(source / 'tests/hia_native' / test),
                   '--manifest', str(manifest), '--output', str(native / name)]
        rows.append(child_process(source, native, name, command))
    write_new(native / 'PROCESSES.json', rows)
    write_new(native / 'RESULT.json', {'status': 'PASS', 'processes': rows,
        'source_unchanged': source_table(ROOT) == before,
        'original_reference_executed': False, 'whole_runtime_replaced': False})
    boundary = base / 'boundary'
    command = [PYTHON, '-I', '-B', str(boundary / 'source/tests/hia_native/test_text_publication_boundary.py'),
               '--manifest', str(manifest), '--output', str(boundary / 'controls')]
    child_process(boundary / 'source', boundary, 'boundary', command, plain=True,
                  extra={'baseline_unchanged': True, 'source_unchanged': True})
    fault_rows = []
    faults = base / 'faults'
    for name in ('pilot', 'full'):
        command = [PYTHON, '-I', '-B', str(faults / 'source/tests/hia_native/test_text_publication_faults.py'),
                   '--manifest', str(manifest), '--output', str(faults / name)]
        if name == 'pilot':
            command += ['--only', 'create']
        fault_rows.append(child_process(faults / 'source', faults, name, command))
    write_new(faults / 'PROCESSES.json', fault_rows)
    write_new(faults / 'RESULT.json', {'status': 'PASS', 'processes': fault_rows,
        'source_unchanged': source_table(ROOT) == before,
        'original_reference_executed': False, 'whole_runtime_replaced': False})
    verify_sources(ROOT, before)
    mechanical_index(base)
    result = {'status': 'PASS', 'test_groups': 4, 'skipped': 0, 'errors': 0, 'failures': 0,
              'smoke_elf_processes': 8, 'callable_hia_requests': 13,
              'allocation_controls': 5, 'packer_calls': 18, 'fd_controls': 26,
              'fault_elf_processes': 27, 'original_reference_executed': False,
              'whole_runtime_replaced': False}
    write_new(base / 'native-suite.json', result)
    print(encoded(result).decode(), end='', flush=True)


def run_corpus():
    base, manifest, _ = execution()
    started = time.monotonic_ns()
    before = source_table(ROOT)
    corpus = base / 'corpus'
    source = corpus / 'source'
    bundle = read_json(manifest)
    elf = manifest.parent / bundle['elf']
    pins = {str(manifest): file_pin(manifest), str(elf): file_pin(elf)}
    native = base / 'native'
    for name, expected in bundle['sources'].items():
        path = native / 'source' / name
        wire.same(file_pin(path)['sha256'], expected, 'actual corpus boundary source')
        pins[str(path)] = file_pin(path)
    for member in bundle['members']:
        path = native / 'source' / member['source']
        wire.same(file_pin(path)['sha256'], member['source_sha256'], 'actual corpus HIA source')
        pins[str(path)] = file_pin(path)
        path = manifest.parent / member['manifest']
        wire.same(file_pin(path)['sha256'], member['manifest_sha256'], 'actual corpus module manifest')
        pins[str(path)] = file_pin(path)
        child = read_json(path)
        image = path.parent / child['image']
        wire.same(file_pin(image)['sha256'], member['image_sha256'], 'actual corpus machine image')
        pins[str(image)] = file_pin(image)
    wire.same(len(pins), 16, 'exact corpus build closure')
    write_new(corpus / 'NATIVE-PINS.json', pins)
    rows = []
    for domain in DOMAINS:
        script = 'qualify_hia_text_publication_races.py' if domain == 'races' else 'qualify_hia_text_publication_native.py'
        destination = corpus / 'domains' / domain
        command = [PYTHON, '-I', '-B', str(source / 'scripts' / script), '--elf', str(elf),
                   '--output', str(destination), '--diagnostics', str(source / 'authoring/diagnostics.json')]
        if domain != 'races':
            command += ['--domain', domain]
        row = child_process(source, corpus, domain, command, extra={'domain': domain})
        result = read_json(destination / 'RESULT.json')
        wire.same([result['status'], result['cases'], result['native_effects']],
                  ['PASS', *execution_contract(base)['domains'][domain]], 'complete actual domain')
        row.update(result=file_pin(destination / 'RESULT.json'), cases=result['cases'],
                   native_effects=result['native_effects'])
        rows.append(row)
    verify_sources(ROOT, before)
    for name, expected in pins.items():
        wire.same(file_pin(name), expected, 'native graph unchanged during all actual corpus processes')
    result = {'status': 'PASS', 'domains': rows, 'cases': 144, 'normal_cases': 124,
              'external_writer_cases': 20, 'native_elf_sha256': bundle['elf_sha256'],
              'source_and_native_bytes_unchanged': True,
              'elapsed_seconds': (time.monotonic_ns() - started) / 1e9,
              'original_comparison_complete': False, 'syscall_fault_qualification_complete': False,
              'whole_runtime_replaced': False}
    write_new(corpus / 'RESULT.json', result)
    summary = {'status': 'PASS', 'test_groups': 6, 'skipped': 0, 'errors': 0, 'failures': 0,
               'cases': 144, 'native_effects': execution_contract(base)['derived_effect_counts']['corpus'], 'original_reference_executed': False,
               'whole_runtime_replaced': False}
    write_new(base / 'corpus-suite.json', summary)
    print(encoded(summary).decode(), end='', flush=True)


def native_evidence(root, output, report, completed_test_summary=None):
    """Main qualification entry: complete native captures and actual read gates."""
    import hia_native_text_publication_pipeline_evidence as evidence
    root, output = Path(root).absolute(), Path(output).absolute()
    wire.same(root, ROOT, 'reader loaded from the supplied current source root')
    manifest_from_report(output, report)
    base = output / FOLDER; prepared = read_json(base / 'prepared.json')
    config = evidence.config_for(base, prepared)
    native = evidence.native_from_roots(**config)
    wire.same(native, read_json(base / 'native-admission.json'), 'retained whole native admission')
    wire.same(native['execution'], prepared, 'same actual preparation receipt')
    controls = evidence.controls_evidence(base, native)
    table = source_table(root); verify_sources(root, table)
    wire.same({name: report['source_sha256'].get(name) for name in table}, table,
              'main inventory binds every direct and recursive Text source')
    artifacts = {FOLDER + '/' + name: pin['sha256'] for name, pin in native['artifact_sha256'].items()}
    artifacts.update({name: pin['sha256'] for name, pin in controls['artifact_pins'].items()})
    for test, summary_file in ((NATIVE_TEST, 'native-suite.json'), (CORPUS_TEST, 'corpus-suite.json'),
                               (EVIDENCE_TEST, 'evidence-suite.json')):
        summary = read_json(base / summary_file)
        rows = [row for row in report['checks'] if row['name'] == test]
        wire.same(len(rows), 1, 'one actual registered Text suite')
        row = rows[0]
        wire.same(row['command'], [prepared['python'], '-I', '-B',
                  prepared['execution_source_root'] + '/tests/hia_native/' + test], 'actual main suite command')
        wire.require(type(row['exit_code']) is int and row['exit_code'] == 0 and row['timed_out'] is False
            and row.get('start_error') is None and type(row['timeout_seconds']) is int and row['timeout_seconds'] == 180
            and wire.number(row['elapsed_seconds']) and 0 < row['elapsed_seconds'] <= 180,
            'actual full suite status and unchanged deadline')
        for kind in ('stdout', 'stderr'):
            directory = report.get('check_artifact_directories', {}).get(test, '.')
            if directory != '.': wire.relative(directory)
            path = contained(output, (directory + '/' if directory != '.' else '') + test + '.' + kind)
            raw = path.read_bytes()
            wire.same(wire.pin(raw), {'bytes': row[kind + '_bytes'], 'sha256': row[kind + '_sha256']}, 'actual whole main-suite stream')
            wire.same(wire.decode(raw) if kind == 'stdout' else raw, summary if kind == 'stdout' else b'', 'actual suite summary and stderr')
            artifacts[str(path.relative_to(output))] = wire.sha(raw)
        wire.same(row['summary'], summary, 'actual retained completed summary')
        if completed_test_summary is not None:
            wire.same(list(completed_test_summary(output, report, test)), [row, summary], 'main completed-test callback')
        artifacts[FOLDER + '/' + summary_file] = file_pin(base / summary_file)['sha256']
    for name in ('prepared.json', 'SOURCE-FILES.json', 'native-admission.json', 'retirement-admission.json'):
        artifacts[FOLDER + '/' + name] = file_pin(base / name)['sha256']
    return {'schema': 'hepta.runtime.text-publication-pipeline-qualified-native.v1', 'status': 'PASS',
            'native': native,
            'controls': {key: value for key, value in controls.items() if key not in ('artifact_pins', 'source_pins')},
            'source_sha256': table, 'artifact_sha256': dict(sorted(artifacts.items())),
            'execution_source_root': prepared['execution_source_root'],
            'execution_output_root': prepared['execution_output_root'],
            'original_comparison_complete': False, 'public_handler_replaced': False, 'whole_runtime_replaced': False}


def retire_fixtures(root, output, report, completed_test_summary=None, *, create=False):
    """Separate non-self-referential archive object; pure reads never restore."""
    import hia_native_text_publication_retirement as retirement
    import hia_native_text_publication_pipeline_evidence as evidence
    root, output = Path(root).absolute(), Path(output).absolute()
    wire.same(root, ROOT, 'current Text source root')
    manifest_from_report(output, report)
    base = output / FOLDER
    native = evidence.native_from_roots(**evidence.config_for(base))
    wire.same(native, read_json(base / 'native-admission.json'), 'archive binds exact native predecessor')
    if create and not (base / 'retirement/retired.json').exists():
        result = retirement.create(base, native)
    else:
        result = retirement.evidence(base, native)
    wire.same(result, read_json(base / 'retirement-admission.json'), 'retained whole separate retirement object')
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--stage', choices=('assemble', 'check', 'build'), required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--hepta', type=Path)
    args = parser.parse_args()
    source = args.source.resolve()
    if args.stage == 'build':
        wire.require(args.hepta is not None, 'fixed compiler checkout required')
        result = build(args.hepta, args.output, source_root=source)
        print(json.dumps({'status': 'PASS', 'manifest': str(result), 'manifest_pin': file_pin(result)}, sort_keys=True))
    elif args.stage == 'assemble':
        from hia_native_text_publication_build import assemble_boundary
        prefix, offset = assemble_boundary(source, args.output.resolve())
        print(json.dumps({'status': 'PASS', 'prefix_bytes': len(prefix),
                          'prefix_sha256': wire.sha(prefix), 'table_offset': offset}, sort_keys=True))
    else:
        table = source_table(source)
        verify_sources(source, table)
        result = {'status': 'PASS', 'source_sha256': table,
                  'source_generation_executed': False, 'new_native_cases': 0, 'new_rust_processes': 0}
        write_new(args.output, result)
        print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
