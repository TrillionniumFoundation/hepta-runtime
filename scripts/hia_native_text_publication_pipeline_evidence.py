"""Read the source-owned Text graph and complete captures without live I/O.

Recorded execution origins are immutable. ``origins`` maps them explicitly to
retained regular files; it never authorizes a fallback or fixture restoration.
The frozen wire reader owns all ABI/effect/FD/private-buffer interpretation.
"""
from pathlib import Path
import argparse
import ast
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import hia_native_text_publication_pipeline as p
import hia_native_text_publication_qualification as q


def path_bound_reader(name, replacements, occurrences):
    """Bind historical aggregate constants to the source-owned actual origin.

    All remaining verifier AST nodes stay exact. Every raw effect, syscall,
    descriptor and completion is still read by the original verifier.
    """
    module = ast.parse(Path(q.__file__).read_bytes())
    functions = [node for node in module.body if isinstance(node, ast.FunctionDef) and node.name == name]
    q.same(len(functions), 1, 'one frozen verification function')
    seen = {key: 0 for key in replacements}
    class Counts(ast.NodeTransformer):
        def visit_Constant(self, node):
            if type(node.value) is int and node.value in replacements:
                seen[node.value] += 1
                return ast.copy_location(ast.Constant(value=replacements[node.value]), node)
            return node
    function = Counts().visit(functions[0])
    q.same(seen, occurrences, 'only declared historical count constants replaced')
    program = ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[]))
    namespace = dict(vars(q)); exec(compile(program, q.__file__ + ':path-bound', 'exec'), namespace)
    return namespace[name]


def parent_prefix(wire, events, prefix):
    """Bind every parent open/close to input bytes, private spans and FD serials."""
    if not events: return []
    q.require(wire[:8] == b'HTXTQ001' and q.q(wire, 8) == 1, 'effectful source-owned publication request')
    path = wire[64:64 + q.q(wire, 24)]
    prefix = prefix.encode()
    if not path.startswith(prefix + b'/'): return []
    components = prefix.split(b'/')[1:]
    q.require(all(part and part not in (b'.', b'..') and b'\0' not in part for part in components), 'exact absolute parent components')
    root = events[0]
    q.same([root['kind'], root['phase'], root['args'], root['errno']],
           [1, 2, [1, 720896, 0, 0, 0, 0], 0], 'actual root directory open')
    capacity = 1024
    while capacity <= len(wire): capacity *= 2
    parent, serial, fd = 1, root['sequence'], root['raw_linux_return']
    checks = []
    for index, component in enumerate(components):
        opened, closed = events[1 + 2 * index:3 + 2 * index]
        child = 2 if parent == 1 else 1
        q.same([opened['kind'], opened['phase'], opened['args'], opened['errno']],
               [2, 4, [parent, child, 4096 + capacity, len(component), 720896, 0], 0], 'actual ordered parent openat and exact input-name span')
        q.same([closed['kind'], closed['phase'], closed['args'], closed['errno'], closed['raw_linux_return']],
               [3, 5, [parent, serial, 0, 0, 0, 0], 0, 0], 'actual preceding-parent close and opening serial')
        q.same(opened['slots'][parent - 1], {'slot': parent, 'fd': fd, 'opening_sequence': serial}, 'openat borrows exact parent FD')
        q.same(closed['slots'][parent - 1], {'slot': parent, 'fd': -1, 'opening_sequence': 0}, 'parent close actually clears private ownership')
        checks.append({'input_component_hex': component.hex(), 'open_sequence': opened['sequence'],
                       'close_sequence': closed['sequence'], 'parent_fd': fd, 'child_fd': opened['raw_linux_return'],
                       'name_workspace_offset': 4096 + capacity, 'name_bytes': len(component)})
        parent, serial, fd = child, opened['sequence'], opened['raw_linux_return']
    return checks


def checked(f, group, row, command, folder, *, plain=False):
    q.same(row['command'], command, 'actual source-owned Text producer command')
    q.same(row['cwd'], f.absolute(group, 'source'), 'actual source-owned producer cwd')
    q.clocks(row, 180)
    q.require('started_monotonic_ns' in row and 'finished_monotonic_ns' in row,
              'actual producer monotonic start and finish')
    if plain:
        streams = {kind: f.read(group, kind, row[kind]) for kind in ('stdout', 'stderr')}
    else:
        streams = q.process_streams(f, group, folder, row, outer=True)
    q.same(streams['stderr'], b'', 'successful producer complete stderr')
    return streams


def native_from_roots(*, native, boundary, faults, corpus, handoff, origins=None):
    f = q.Files(dict(native=native, boundary=boundary, faults=faults, corpus=corpus, handoff=handoff), origins)
    contract = p.execution_contract(Path(native).parent)
    expected = p.source_table(ROOT)
    p.verify_sources(ROOT, expected)
    sources = {}
    for group in ('native', 'boundary', 'faults', 'corpus'):
        table = f.obj(group, 'SOURCE-PINS.json' if group == 'corpus' else 'SOURCE-FILES.json')
        if group == 'corpus':
            want = {name: p.file_pin(ROOT / name) for name in contract['corpus_sources']}
            q.same(table, want, 'complete frozen corpus source set')
            sources[group] = {name: item['sha256'] for name, item in table.items()}
        else:
            q.same(table, expected, 'complete actual staged producer source closure')
            sources[group] = table
        for name, value in table.items():
            f.read(group, 'source/' + name, value, source=True)
    execution = f.obj('native', 'EXECUTION.json')
    q.same(execution['schema'], 'hepta.runtime.text-publication-pipeline-prepared.v1', 'actual preparation schema')
    parent = str(Path(f.roots['native']).parent)
    q.same(f.roots, {group: parent + '/' + group for group in p.GROUPS}, 'one exact finite Text capture graph')
    q.same(execution['execution_output_root'], str(Path(parent).parent), 'prepared original output root')
    q.same(execution['manifest'], f.absolute('native', 'build/manifest.json'), 'same actual prepared manifest')
    q.same(execution['producer_python'], '/usr/bin/python3', 'fixed producer interpreter command')
    q.require(type(execution['python']) is str and execution['python'].startswith('/'), 'actual outer interpreter')
    q.require(type(execution['producer_python_sha256']) is str and len(execution['producer_python_sha256']) == 64,
              'actual executable identity')
    for field in ('original_comparison_complete', 'public_handler_replaced', 'whole_runtime_replaced'):
        q.same(execution[field], False, 'native preparation scope')
    q.same(q.pin(f.read('native', 'SOURCE-FILES.json')), execution['source_table_pin'], 'prepared entire source table pin')
    q.same(q.pin(f.read('native', 'build/manifest.json')), execution['manifest_pin'], 'prepared actual graph pin')
    artifacts = f.obj('handoff', 'ARTIFACTS.json')
    labels = {'native-v4': 'native', 'boundary-v1': 'boundary', 'faults-v1': 'faults'}
    q.same(set(artifacts), set(labels), 'complete three mechanical artifact indices')
    mechanical_count = 0
    for label, group in labels.items():
        item = artifacts[label]
        q.same(set(item), {'origin', 'artifacts'}, 'exact mechanical index fields')
        q.same(item['origin'], f.roots[group], 'actual mechanical origin')
        q.same(sorted(item['artifacts']), contract['mechanical_artifacts'][label], 'complete fixed mechanical artifact paths')
        for name, pin in item['artifacts'].items():
            f.read(group, name, pin)
            mechanical_count += 1
    m = q.native_build(f, contract, sources)
    q.same(m['elf_sha256'], contract['elf_sha256'], 'unchanged frozen Text machine graph')
    rows = f.obj('native', 'PROCESSES.json')
    names = ['assemble', 'source-contract', 'build', 'native-smoke', 'callable-controls']
    q.same([row['name'] for row in rows], names, 'actual complete build and mechanical processes')
    native_root, source = f.roots['native'], f.absolute('native', 'source')
    script = source + '/scripts/hia_native_text_publication_pipeline.py'
    manifest = f.absolute('native', 'build/manifest.json')
    commands = [
        ['/usr/bin/python3', '-I', '-B', script, '--stage', 'assemble', '--source', source,
         '--output', native_root + '/authoring-boundary'],
        ['/usr/bin/python3', '-I', '-B', script, '--stage', 'check', '--source', source,
         '--output', native_root + '/source-contract.json'],
        ['/usr/bin/python3', '-I', '-B', source + '/scripts/hia_native_text_publication_build.py',
         '--hepta', execution['hepta'], '--output', native_root + '/build', '--source', source],
    ]
    for name, test in [('native-smoke', 'test_text_publication_elf.py'),
                       ('callable-controls', 'test_text_publication_callable.py')]:
        commands.append(['/usr/bin/python3', '-I', '-B', source + '/tests/hia_native/' + test,
                         '--manifest', manifest, '--output', native_root + '/' + name])
    for row, name, command in zip(rows, names, commands):
        q.same(f.obj('native', name + '.process.json'), row, 'actual per-process complete receipt')
        checked(f, 'native', row, command, name)
    q.same(execution['build_processes'], rows[:3], 'prepared actual fresh graph processes')
    proof = f.obj('native', 'source-contract.json')
    q.same(proof, {'status': 'PASS', 'source_sha256': expected, 'source_generation_executed': False,
                  'new_native_cases': 0, 'new_rust_processes': 0}, 'exact source-owned graph input proof')
    q.same(q.decode(f.read('native', 'source-contract.stdout')), proof, 'actual source proof stdout')
    for folder in ('build', 'authoring-boundary'):
        base = native_root + '/' + folder
        q.assembly_processes(f, 'native', folder, [
            ['as', '--64', '-o', base + '/boundary.o', base + '/combined.S'],
            ['readelf', '-r', base + '/boundary.o'],
            ['objcopy', '-O', 'binary', '-j', '.text', base + '/boundary.o', base + '/boundary.bin'],
            ['nm', '-n', base + '/boundary.o']])
    boundary_row = f.obj('boundary', 'PROCESS.json')
    checked(f, 'boundary', boundary_row, ['/usr/bin/python3', '-I', '-B',
        f.absolute('boundary', 'source/tests/hia_native/test_text_publication_boundary.py'),
        '--manifest', manifest, '--output', f.absolute('boundary', 'controls')], '', plain=True)
    q.same(boundary_row['name'], 'boundary', 'actual boundary process')
    for field in ('source_unchanged', 'baseline_unchanged'):
        q.same(boundary_row[field], True, 'boundary source and actual baseline unchanged')
    fault_rows = f.obj('faults', 'PROCESSES.json')
    q.same([row['name'] for row in fault_rows], ['pilot', 'full'], 'both complete fault processes')
    for row in fault_rows:
        name = row['name']
        command = ['/usr/bin/python3', '-I', '-B', f.absolute('faults', 'source/tests/hia_native/test_text_publication_faults.py'),
                   '--manifest', manifest, '--output', f.absolute('faults', name)]
        if name == 'pilot':
            command += ['--only', 'create']
        q.same(f.obj('faults', name + '.process.json'), row, 'complete actual fault wrapper receipt')
        checked(f, 'faults', row, command, name)
    counts = contract['derived_effect_counts']
    smoke = path_bound_reader('smoke_evidence', {233: counts['smoke']}, {233: 3})(f, m)
    callable_result = q.callable_controls(f, m)
    boundary_result = q.boundary_controls(f, m)
    faults_result = path_bound_reader('faults_evidence', {822: counts['faults'], 225: counts['fault_opens']}, {822: 1, 225: 1})(f, m)
    corpus_result = path_bound_reader('corpus_evidence', {3675: counts['corpus']}, {3675: 1})(f, contract, m, q.load_generators(f))
    parent_checks = {}
    for domain in p.DOMAINS:
        folder = 'domains/' + domain
        events = q.receipt_records(f.read('corpus', folder + '/process/stderr.bin'))
        for row in f.obj('corpus', folder + '/RESULT.json')['rows']:
            wire = f.read('corpus', folder + '/cases/' + row['name'] + '/input.bin')
            response = q.result_record(f.read('corpus', folder + '/cases/' + row['name'] + '/record.bin'))
            selected = [event for event in events if event['generation'] == response['generation']] if row['effects'] else []
            parent_checks['corpus/' + domain + '/' + row['name']] = parent_prefix(wire, selected, f.roots['corpus'])
    for domain in ('pilot', 'full'):
        for row in f.obj('faults', domain + '/RESULT.json')['cases_completed']:
            folder = domain + '/' + row['name']
            wire = q.framed(f.read('faults', folder + '/stdin.bin'))[0]
            events = q.receipt_records(f.read('faults', folder + '/stderr.bin'))
            parent_checks['faults/' + folder] = parent_prefix(wire, events, f.roots['faults'])
    for name in ('chain', 'sha-windows', 'errno-child', 'race'):
        folder = 'native-smoke/' + name
        stream = f.read('native', folder + '/stdin.bin')
        requests = [stream[8:8 + q.q(stream)]] if name == 'race' else q.framed(stream)
        events = q.receipt_records(f.read('native', folder + '/stderr.bin'))
        generation = 0
        for request in requests:
            if q.q(request, 8) != 1: continue
            generation += 1
            selected = [event for event in events if event['generation'] == generation]
            parent_checks['smoke/' + name + '/' + str(generation)] = parent_prefix(request, selected, f.roots['native'])
    return {'schema': 'hepta.runtime.text-publication-pipeline-native.v1', 'status': 'PASS',
        'cases': 144, 'ordinary_original_eligible_cases': 99, 'private_frame_cases': 25,
        'actual_external_writer_cases': 20, 'corpus_effects': counts['corpus'],
        'path_bound_count_derivation': counts, 'complete_parent_walks': parent_checks,
        'mechanical_artifacts': mechanical_count, 'smoke': smoke, 'callable': callable_result,
        'boundary': boundary_result, 'faults': faults_result, 'domains': corpus_result,
        'elf_sha256': m['elf_sha256'], 'execution': execution,
        'sources': dict(sorted(f.sources.items())), 'artifact_sha256': dict(sorted(f.artifacts.items())),
        'artifacts': sorted(f.artifacts), 'reader_sources': {
            name: p.file_pin(ROOT / name) for name in p.source_names(ROOT)},
        'native_processes_executed_by_reader': 0, 'rust_processes_executed_by_reader': 0,
        'live_fixtures_read': False, 'fixtures_restored_by_reader': False,
        'original_reference_executed': False,
        'original_reference_status': 'PENDING_SEPARATE_ORIGINAL_ADMISSION',
        'public_handler_replaced': False, 'whole_runtime_replaced': False}


def config_for(base, execution=None):
    base = Path(base).absolute()
    if execution is None:
        execution = p.read_json(base / 'prepared.json')
    original = str(Path(execution['execution_output_root']) / p.FOLDER)
    return dict({group: original + '/' + group for group in p.GROUPS},
                origins={original: str(base)})


def controls_evidence(base, native):
    """Admit the actual 33+6 refusals and two complete absent-origin reads."""
    import hia_native_text_publication_retirement as retirement
    base = Path(base).absolute(); folder = base.parent / 'text-publication-controls'
    result = p.read_json(folder / 'RESULT.json'); artifacts = {}; sources = {}
    def read(relative, expected=None):
        path = p.contained(folder, relative); raw = path.read_bytes(); item = q.pin(raw)
        if expected is not None: q.same(item, expected, 'complete read-control artifact pin')
        artifacts['text-publication-controls/' + relative] = item
        return raw
    def obj(relative, expected=None): return q.decode(read(relative, expected))
    q.same(obj('BASELINE.json', result['baseline']), native, 'complete native refusal baseline')
    execution = native['execution']; old_base = str(Path(execution['execution_output_root']) / p.FOLDER)
    old_controls = str(Path(execution['execution_output_root']) / 'text-publication-controls')
    q.same(obj('CONFIG.json'), config_for(Path(old_base), execution), 'actual original read-control configuration')
    q.same(result['schema'], 'hepta.runtime.text-publication-pipeline-read-controls.v1', 'read-control schema')
    for key, expected in [('status', 'PASS'), ('test_groups', 8), ('native_refusals', 33),
                          ('archive_refusals', 6), ('positive_relocations', 2), ('native_execution', 0),
                          ('rust_execution', 0), ('skipped', 0), ('errors', 0), ('failures', 0),
                          ('original_reference_executed', False), ('public_handler_replaced', False),
                          ('whole_runtime_replaced', False)]: q.same(result[key], expected, 'complete native read-control outcome')
    q.require(q.number(result['elapsed_seconds']) and result['elapsed_seconds'] <= 180, 'unchanged native evidence suite deadline')
    q.same(result['sources'], p.source_table(ROOT), 'actual read-control source closure')
    expected = [(g, name, resigned) for g, name, _, resigned in
                q.pure_function((ROOT / 'tests/hia_native/test_text_publication_evidence.py').read_bytes(), 'controls')()]
    q.same(len(result['native_controls']), len(expected), 'complete native refusal set')
    for index, (row, (group, name, resigned)) in enumerate(zip(result['native_controls'], expected), 1):
        q.same([row['index'], row['group'], row['name'], row['resigned_surrounding_indices']],
               [index, group, name, resigned], 'source-owned refusal identity')
        case = 'cases/' + ('%02d-' % index) + name
        q.same(obj(case + '/result.json'), row, 'physical native refusal receipt')
        q.same(row['status'], 'PASS', 'actual rejection'); q.same(row['native_cases_added'], 0, 'no native replay')
        q.same(row['rust_cases_added'], 0, 'no original replay')
        q.require(q.number(row['elapsed_seconds']) and row['elapsed_seconds'] <= 180, 'actual refusal duration')
        rejection = row['rejection']
        q.require(type(rejection) is dict and type(rejection.get('type')) is str and bool(rejection.get('message')), 'actual refusal detail')
        changes = row['actual_physical_changes']; q.require(type(changes) is dict and changes, 'retained physical mutations')
        different = False
        for name, item in changes.items():
            q.relative(name); q.same(item['before'], native['artifact_sha256'].get(name), 'mutation exact admitted preimage')
            if item['after'] is None: q.same(item['file'], None, 'missing artifact control')
            else:
                q.same(item['file'], 'changed/' + name, 'exact private changed artifact')
                read(case + '/' + item['file'], item['after'])
            different = different or item['before'] != item['after']
        q.require(different, 'actual byte mutation or removal')
    retained = retirement.evidence(base, native)
    q.same(result['retirement'], retained, 'complete separate retirement evidence')
    artifacts.update(retained['artifact_pins'])
    archive_names = ('changed-complete-blob', 'omitted-permission-grant-resigned', 'open-hardlink-group-resigned',
                     'changed-raw-symlink-resigned', 'duplicate-archive-root-resigned', 'same-bytes-outside-symlink')
    q.same(len(result['archive_controls']), len(archive_names), 'complete archive refusal set')
    for index, (row, name) in enumerate(zip(result['archive_controls'], archive_names), 1):
        q.same([row['index'], row['name'], row['status'], row['native_execution'], row['rust_execution']],
               [index, name, 'PASS', 0, 0], 'actual archive refusal identity')
        q.require(type(row['rejection']) is dict and row['rejection'].get('message'), 'actual archive rejection')
        case = 'archive-cases/' + ('%02d-' % index) + name
        q.same(obj(case + '/result.json'), row, 'whole archive refusal receipt')
        for name, item in row['physical_changes'].items():
            q.relative(name)
            q.same(item['before'], retained['artifact_pins'][p.FOLDER + '/' + name], 'archive mutation exact original bytes')
            if 'symlink_target' in item:
                q.same(item['symlink_target'], old_controls + '/' + case + '/outside.json', 'actual private outside-symlink control')
                read(case + '/outside.json', item['before'])
            else:
                q.same(item['file'], 'changed/' + name, 'private physical archive mutation')
                read(case + '/' + item['file'], item['after'])
        q.require(any(item.get('symlink_target') or item['before'] != item['after'] for item in row['physical_changes'].values()), 'nonempty physical archive mutation')
    reloc = result['relocations']
    q.same(reloc['identity_before'], reloc['identity_restored'], 'same actual original root restored')
    q.same(set(reloc['identity_before']), {'dev', 'ino', 'mode', 'uid', 'gid'}, 'actual complete original directory identity')
    q.same(len(reloc['reads']), 2, 'two actual absent-origin children')
    for number, row in enumerate(reloc['reads'], 1):
        prefix = 'new-root-' + str(number); origin = old_controls + '/' + prefix
        q.same(obj(prefix + '/RESULT.json'), row, 'complete actual relocation receipt')
        q.same([row['source'], row['output']], [origin + '/source', origin + '/output'], 'independent actual read roots')
        for key in ('original_component_output_absent', 'original_producer_sources_absent', 'previous_read_root_absent',
                    'no_live_fixture_dependency', 'complete_object_equal'): q.same(row[key], True, 'actual absence and equality observation')
        q.same(row['repository_root_moved'], False, 'only owned component namespace moved')
        q.same(row['native_execution'], 0, 'no relocated native execution'); q.same(row['rust_execution'], 0, 'no relocated Rust')
        process = obj(prefix + '/read/PROCESS.json'); q.same(process, row['process'], 'actual relocated reader process')
        q.clocks(process, 180)
        q.same(process['command'], ['/usr/bin/python3', '-I', '-B', origin + '/source/scripts/hia_native_text_publication_pipeline_evidence.py',
            '--config', origin + '/CONFIG.json', '--output', origin + '/read/EVIDENCE.json', '--retirement', origin + '/output'], 'exact real relocated reader argv')
        q.same(process['cwd'], origin + '/source', 'actual relocated reader cwd')
        q.same(read(prefix + '/read/stderr', process['stderr']), b'', 'complete actual relocated stderr')
        summary = q.decode(read(prefix + '/read/stdout', process['stdout']))
        q.same(summary, {'status': 'PASS', 'cases': 144, 'artifacts': len(native['artifacts']),
                         'native_executed': 0, 'rust_executed': 0, 'output': row['evidence']}, 'actual relocated stdout')
        q.same(obj(prefix + '/read/EVIDENCE.json', row['evidence']), {'native': native, 'retirement': retained}, 'whole positive moved object')
        q.same(obj(prefix + '/CONFIG.json'), dict({group: old_base + '/' + group for group in p.GROUPS},
                                                origins={old_base: origin + '/output'}), 'complete explicit original-to-new mapping')
        for name, pin in native['reader_sources'].items():
            read(prefix + '/source/' + name, pin); sources['text-publication-controls/' + prefix + '/source/' + name] = pin
        for name, pin in native['artifact_sha256'].items(): read(prefix + '/output/' + name, pin)
        for name, pin in retained['artifact_pins'].items(): read(prefix + '/output/' + name.removeprefix(p.FOLDER + '/'), pin)
    read('RESULT.json')
    return {'status': 'PASS', 'native_refusals': 33, 'archive_refusals': 6, 'positive_relocations': 2,
            'artifact_pins': artifacts, 'source_pins': sources, 'native_execution': 0, 'rust_execution': 0}


def main():
    parser = argparse.ArgumentParser()
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--config', type=Path)
    choice.add_argument('--main-report', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--retirement', type=Path)
    parser.add_argument('--capture-root', type=Path)
    args = parser.parse_args()
    if args.main_report:
        q.require(args.capture_root is not None and args.retirement is None, 'explicit main capture root')
        report = p.read_json(args.main_report)
        result = {'native': p.native_evidence(ROOT, args.capture_root, report),
                  'retirement': p.retire_fixtures(ROOT, args.capture_root, report)}
    else:
        result = native_from_roots(**p.read_json(args.config))
    if args.retirement and not args.main_report:
        import hia_native_text_publication_retirement as retirement
        result = {'native': result, 'retirement': retirement.evidence(args.retirement, result)}
    p.write_new(args.output, result)
    native = result['native'] if args.retirement or args.main_report else result
    print(json.dumps({'status': 'PASS', 'cases': 144, 'artifacts': len(native.get('artifacts', native['artifact_sha256'])),
                      'native_executed': 0, 'rust_executed': 0,
                      'output': p.file_pin(args.output)}, sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
