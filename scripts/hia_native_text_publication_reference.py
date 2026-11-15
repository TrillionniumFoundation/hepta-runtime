"""Run the unchanged Text original only after the complete native admission.

Recorded execution paths remain immutable. Retained readers use explicit source
and output mappings, consume full process streams, and never restore fixtures.
"""
from pathlib import Path
import importlib.util
import ast
import copy
import math
import os
import stat
import shutil
import sys

import hia_native_text_publication_pipeline as p
import hia_native_text_publication_qualification as q

KEY = 'text_publication'
FOLDER = 'text-publication-original'
ORACLE = 'tests/hia_native/text_publication_oracle'
CONTRACT = 'native/text_publication_original_sources.json'
CHECK = 'text-publication-original'
WRAPPERS = ('scripts/hia_native_text_publication_reference.py',
            'scripts/hia_native_text_publication_original_fixtures.py',
            'tests/hia_native/test_text_publication_original_pipeline.py')
CONTROLS_TEST = 'test_text_publication_original_pipeline.py'
CONTROLS_CHECK = 'text-publication-original-pipeline'


def source_pins(root, report):
    root = Path(root).absolute()
    contract = p.read_json(root / CONTRACT)
    q.same(contract['schema'], 'hepta.runtime.text-publication-original-sources.v1', 'original source contract')
    q.same(contract['root'], ORACLE, 'one original source namespace')
    q.same(len(contract['files']), 24, 'complete frozen original source set')
    names = [CONTRACT, *WRAPPERS, *(ORACLE + '/' + name for name in contract['files'])]
    result = {}
    for name in names:
        actual = p.file_pin(p.contained(root, name))
        q.same(actual['sha256'], report['source_sha256'].get(name), 'main inventory binds original source ' + name)
        if name.startswith(ORACLE + '/'):
            q.same(actual, contract['files'][name[len(ORACLE) + 1:]], 'unchanged complete original source ' + name)
        result[name] = actual['sha256']
    for copied, owner in [('ordinary/original/text_file_write.rs', 'src/mcp/fs/text_file_write.rs'),
                          ('ordinary/original/Cargo.lock', 'Cargo.lock')]:
        q.same(p.contained(root, ORACLE + '/' + copied).read_bytes(), p.contained(root, owner).read_bytes(),
               'full original owner remains byte-identical')
        result[owner] = p.file_pin(root / owner)['sha256']
        q.same(result[owner], report['source_sha256'].get(owner), 'original whole owner inventory')
    return dict(sorted(result.items()))


def load_api(root):
    path = p.contained(root, ORACLE + '/api.py')
    spec = importlib.util.spec_from_file_location('_text_publication_registered_original', path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return module.load(Path(root) / ORACLE)


def admitted(root, output, report, completed):
    native = p.native_evidence(root, output, report, completed)
    retirement = p.retire_fixtures(root, output, report, completed)
    q.same(native, report.get('text_publication_evidence'), 'same complete native predecessor')
    q.same(retirement, report.get('text_publication_fixture_retirement'), 'same complete native fixture retirement')
    return native, retirement


def mappings(root, output, binding, native):
    pairs = {}
    for origin, current in ((binding['execution_source_root'], root),
                            (binding['execution_output_root'], output),
                            (native['execution_output_root'], output)):
        origin, current = Path(origin), Path(current).absolute()
        q.require(origin.is_absolute() and '..' not in origin.parts, 'normalized recorded source/output root')
        q.require(current.resolve(strict=True) == current, 'current root without followed links')
        if str(origin) in pairs: q.same(pairs[str(origin)], str(current), 'consistent overlapping origin')
        pairs[str(origin)] = str(current)
    q.require(len(set(pairs.values())) == 2, 'independent source and output roots')
    return [[a, b] for a, b in sorted(pairs.items())]


def select(path, origins, root, output):
    origin = Path(path)
    q.require(origin.is_absolute() and '..' not in origin.parts, 'absolute retained origin')
    chosen = [(Path(a), Path(b)) for a, b in origins if origin == Path(a) or Path(a) in origin.parents]
    q.require(chosen, 'no unbound original path fallback')
    old, current = max(chosen, key=lambda pair: len(pair[0].parts))
    target = current / origin.relative_to(old)
    owner = 'output' if current == Path(output) else 'source'
    q.same(current, Path(output) if owner == 'output' else Path(root), 'owned mapped root')
    name = target.relative_to(current).as_posix()
    return p.contained(current, name), owner, name


def command(binding, native):
    old_root, old_output = Path(binding['execution_source_root']), Path(binding['execution_output_root'])
    native_base = Path(native['execution_output_root']) / p.FOLDER
    return [binding['python'], '-I', '-B', str(old_root / ORACLE / 'run_group.py'),
            '--source', str(old_root / ORACLE), '--output', str(old_output / FOLDER / 'group'),
            '--native-root', str(native_base / 'corpus'),
            '--native-source', str(native_base / 'native/source'),
            '--native-build', str(native_base / 'native/build'),
            '--native-origins', str(old_output / FOLDER / 'native-origins.json'),
            '--cargo', binding['tools']['cargo']['path'], '--rustc', binding['tools']['rustc']['path'],
            '--strace', binding['tools']['strace']['path']]


def _read(root, output, report, completed):
    root, output = Path(root).absolute(), Path(output).absolute()
    native, retired = admitted(root, output, report, completed)
    pins = source_pins(root, report)
    binding = p.read_json(p.contained(output, FOLDER + '/INPUT.json'))
    q.same(set(binding), {'schema', 'execution_source_root', 'execution_output_root',
        'python', 'tools', 'source_sha256', 'native_evidence', 'native_retirement'},
        'complete original invocation binding')
    q.same(binding['schema'], 'hepta.runtime.text-publication-original-input.v1', 'original binding schema')
    q.same(binding['source_sha256'], pins, 'actual original producer source closure')
    q.same(binding['native_evidence'], q.pin(p.encoded(native)), 'complete native-first evidence')
    q.same(binding['native_retirement'], q.pin(p.encoded(retired)), 'native retirement before original')
    q.same(set(binding['tools']), {'cargo', 'rustc', 'strace'}, 'all original tools')
    q.require(Path(binding['python']).is_absolute(), 'actual absolute Python executable')
    origins = mappings(root, output, binding, native)
    old_root, old_output = Path(binding['execution_source_root']), Path(binding['execution_output_root'])
    source, group = old_root / ORACLE, old_output / FOLDER / 'group'
    current = output / FOLDER / 'group'
    artifacts = {FOLDER + '/INPUT.json': p.file_pin(output / FOLDER / 'INPUT.json')}

    def raw(name):
        path = p.contained(output, FOLDER + '/group/' + name)
        artifacts[FOLDER + '/group/' + name] = p.file_pin(path)
        return path.read_bytes()

    def obj(name):
        return q.decode(raw(name))

    native_maps = [[native['execution_output_root'], binding['execution_output_root']]]
    mapping_path = p.contained(output, FOLDER + '/native-origins.json')
    q.same(p.read_json(mapping_path), native_maps, 'recorded native relocation selection')
    q.same(raw('NATIVE-ORIGINS.json'), mapping_path.read_bytes(), 'unchanged native selection bytes')
    artifacts[FOLDER + '/native-origins.json'] = p.file_pin(mapping_path)
    execution_origins = native_maps + [[str(source), str(source)], [str(group), str(group)]]
    request = obj('ADMISSION-REQUEST.json')
    expected_request = {'source': str(source), 'ordinary_request': str(group / 'ORDINARY-REQUEST.json'),
        'race_request': str(group / 'RACE-REQUEST.json'),
        'ordinary_controls': str(group / 'ordinary-controls'), 'race_controls': str(group / 'race-controls'),
        'ordinary_receipt': str(group / 'processes/ordinary-controls/PROCESS.json'),
        'race_receipt': str(group / 'processes/race-controls/PROCESS.json'), 'origins': execution_origins}
    q.same(request, expected_request, 'exact source-owned original qualification selection')
    ordinary = obj('ORDINARY-REQUEST.json')
    native_base = Path(native['execution_output_root']) / p.FOLDER
    q.same(ordinary, {'source': str(source / 'ordinary'), 'output': str(group / 'ordinary'),
        'native_root': str(native_base / 'corpus'), 'native_source': str(native_base / 'native/source'),
        'native_build': str(native_base / 'native/build'),
        'outer_receipt': str(group / 'processes/ordinary/PROCESS.json'), 'origins': execution_origins},
        'exact ordinary native-first selection')
    q.same(obj('RACE-REQUEST.json'), {'source': str(source / 'races'), 'output': str(group / 'races'),
        'native_corpus': str(native_base / 'corpus'),
        'outer_receipt': str(group / 'processes/races/PROCESS.json'), 'origins': execution_origins},
        'exact original race selection')
    proof = load_api(root)['qualification_evidence'](**{**request, 'origins': origins})
    q.same(obj('EVIDENCE.json'), proof, 'entire retained original qualification object')
    q.same(obj('RACE-EVIDENCE.json'), proof['original_reference'], 'same complete original race evidence')
    ordinary_proof = proof['original_reference']['ordinary_reference']
    q.same(obj('ORDINARY-EVIDENCE.json'), ordinary_proof, 'same complete ordinary reference')
    q.same(obj('SOURCE-FILES.json'), p.read_json(root / CONTRACT)['files'], 'all and only actual 24 original inputs')

    checks = [row for row in report['checks'] if row['name'] == CHECK]
    q.same(len(checks), 1, 'one actual original group invocation')
    check = checks[0]
    q.same(check['command'], command(binding, native), 'exact original group command')
    q.same(check.get('cwd'), str(old_root), 'actual main original working directory')
    q.require(q.integer(check.get('pid'), 1), 'actual original group PID')
    q.same(check['timeout_seconds'], 180, 'unchanged original group deadline')
    q.same(check['exit_code'], 0, 'actual original group exit')
    q.same(check['timed_out'], False, 'no original group timeout')
    q.require(not check.get('start_error'), 'no original process start error')
    q.require(q.number(check['elapsed_seconds']) and 0 < check['elapsed_seconds'] <= 180,
              'finite actual original group interval')
    streams = {}
    for name in ('stdout', 'stderr'):
        path = p.contained(output, CHECK + '.' + name)
        value = p.file_pin(path)
        q.same(value, {'bytes': check[name + '_bytes'], 'sha256': check[name + '_sha256']},
               'entire real original group ' + name)
        artifacts[CHECK + '.' + name] = value
        streams[name] = path.read_bytes()
    q.same(streams['stderr'], b'', 'successful original group complete stderr')
    runtime = obj('remote-process.json')
    q.same(set(runtime), {'pid', 'cgroup', 'started_monotonic_ns'}, 'actual original group identity record')
    q.same(runtime['pid'], check['pid'], 'group PID is the actual main child')
    q.require(type(runtime['cgroup']) is str and runtime['cgroup'], 'actual group cgroup observation')
    q.require(q.integer(runtime['started_monotonic_ns'], 1), 'actual group start clock')
    processes = obj('PROCESSES.json')
    names = ['ordinary', 'races', 'ordinary-controls', 'race-controls']
    q.same([row['name'] for row in processes], names, 'complete actual Python child order')
    last = runtime['started_monotonic_ns']
    expected_lines = []
    for row in processes:
        name = row['name']
        process = {key: value for key, value in row.items() if key != 'name'}
        q.same(obj(name + '-PROCESS.json'), process, 'exact outer child duplicate receipt')
        q.same(obj('processes/' + name + '/PROCESS.json'), process, 'exact actual child receipt')
        q.clocks(process, 180)
        q.require(process['started_monotonic_ns'] >= last, 'actual original Python children are sequential')
        last = process['finished_monotonic_ns']
        q.same(process['command'][0], binding['python'], 'same actual Python executable')
        for stream in ('stdout', 'stderr'):
            data = raw('processes/' + name + '/' + stream)
            q.same(q.pin(data), process[stream], 'full child process stream')
        for part in ('status', 'cmdline', 'cgroup'):
            path = current / 'processes' / name / ('proc-' + part)
            if os.path.lexists(path):
                raw('processes/' + name + '/proc-' + part)
        expected_lines.append({key: row[key] for key in ('name', 'exit_code', 'elapsed_seconds', 'stdout', 'stderr')})
    result = obj('RESULT.json')
    fixed = {'schema': 'hepta.runtime.text-original-portable-group.v1', 'status': 'PASS',
        'ordinary_cases': 99, 'external_writer_cases': 20, 'actual_original_children': 9,
        'fresh_locked_builds': 1, 'version_processes': 3, 'original_replays': 5,
        'actual_python_children': 4, 'ordinary_refusals': 42, 'race_refusals': 36,
        'new_native_calls': 0, 'public_handler_complete': False, 'whole_runtime_replaced': False,
        'evidence': q.pin(raw('EVIDENCE.json')), 'ordinary_evidence': q.pin(raw('ORDINARY-EVIDENCE.json')),
        'race_evidence': q.pin(raw('RACE-EVIDENCE.json')), 'source_files': q.pin(raw('SOURCE-FILES.json'))}
    q.same({key: value for key, value in result.items() if key != 'elapsed_seconds'}, fixed,
           'complete group summary counters and full evidence pins')
    q.require(q.number(result['elapsed_seconds']) and 0 < result['elapsed_seconds'] <= check['elapsed_seconds'],
              'group duration lies inside its actual main process')
    q.require((last - runtime['started_monotonic_ns']) / 1e9 <= check['elapsed_seconds'],
              'all children lie inside the actual parent process')
    q.same([q.decode(line) for line in streams['stdout'].splitlines()], expected_lines + [result],
           'all five actual stdout records without omitted output')

    compiler = report['rust_compiler']
    for name, actual in ordinary_proof['toolchain'].items():
        q.same({key: actual[key] for key in ('path', 'bytes', 'sha256')}, binding['tools'][name],
               'actual retained tool matches selected invocation')
    q.same(binding['tools']['rustc']['path'], compiler['invocation_path'], 'main Rust compiler invocation')
    q.same(binding['tools']['rustc']['sha256'], compiler['invocation_executable_sha256'], 'main Rust executable bytes')
    version = raw('ordinary/processes/rustc-version/stdout')
    q.same(version, compiler['version'].encode(), 'complete actual compiler verbose version')
    for origin, expected in proof['artifact_sha256'].items():
        path, owner, name = select(origin, origins, root, output)
        actual = p.file_pin(path)
        q.same(actual, expected, 'full original source/artifact bytes')
        if owner == 'output':
            if name in artifacts: q.same(artifacts[name], actual, 'stable repeated original artifact')
            artifacts[name] = actual
        else:
            q.same(actual['sha256'], report['source_sha256'].get(name), 'original source in main inventory')
            pins[name] = actual['sha256']
    return native, retired, binding, proof, check, dict(sorted(pins.items())), artifacts


def original_evidence(root, output, report, completed):
    """Read every retained native/original/archive byte; never execute or restore."""
    native, retired, binding, proof, check, pins, artifacts = _read(root, output, report, completed)
    import hia_native_text_publication_original_fixtures as fixtures
    retirement = fixtures.evidence(output, binding, proof, pins)
    for name, value in retirement['artifact_pins'].items():
        if name in artifacts: q.same(artifacts[name], value, 'one complete original artifact')
        artifacts[name] = value
    return {'schema': 'hepta.runtime.text-publication-registered-original.v1', 'status': 'PASS',
        'ordinary_cases': 99, 'external_writer_cases': 20, 'actual_original_child_processes': 9,
        'actual_python_child_processes': 4, 'fresh_locked_builds': 1, 'physical_refusals': 78,
        'source_sha256': pins, 'native_evidence': q.pin(p.encoded(native)),
        'native_retirement': q.pin(p.encoded(retired)), 'original_process': check,
        'original_reference': proof, 'original_fixture_retirement': retirement,
        'artifact_sha256': {name: value['sha256'] for name, value in sorted(artifacts.items())},
        'artifact_pins': dict(sorted(artifacts.items())), 'new_native_calls': 0,
        'new_original_processes': 0, 'public_handler_complete': False, 'whole_runtime_replaced': False}


def retained_original(root, output, report, completed):
    """Original, archive and actual wrapper-refusal evidence, entirely read-only."""
    root, output = Path(root).absolute(), Path(output).absolute()
    base = original_evidence(root, output, report, completed)
    binding = p.read_json(p.contained(output, FOLDER + '/INPUT.json'))
    old_root, old_output = Path(binding['execution_source_root']), Path(binding['execution_output_root'])
    folder = FOLDER + '/pipeline-controls'
    artifacts = dict(base['artifact_pins'])
    def raw(name):
        path = p.contained(output, folder + '/' + name)
        artifacts[folder + '/' + name] = p.file_pin(path)
        return path.read_bytes()
    def obj(name): return q.decode(raw(name))
    result = obj('RESULT.json')
    q.same(obj('BASELINE.json'), base, 'complete native/original baseline for wrapper controls')
    q.same(result['baseline'], q.pin(raw('BASELINE.json')), 'whole wrapper baseline hash')
    expected_source = {name: p.file_pin(root / name) for name in source_pins(root, report)}
    q.same(obj('SOURCE.json'), expected_source, 'complete actual wrapper-control source')
    q.same(result['source'], q.pin(raw('SOURCE.json')), 'whole wrapper-control source hash')
    prior = obj('REPORT.json')
    before_path = p.contained(output, FOLDER + '/pre-controls-report.json')
    q.same(prior, p.read_json(before_path), 'same actual control input report')
    artifacts[FOLDER + '/pre-controls-report.json'] = p.file_pin(before_path)
    q.same(result['report'], q.pin(raw('REPORT.json')), 'entire actual control report pin')
    q.same(prior['source_sha256'], report['source_sha256'], 'same whole main source inventory')
    for key in ('text_publication_evidence', 'text_publication_fixture_retirement', 'rust_compiler'):
        q.same(prior[key], report[key], 'same complete main predecessor ' + key)
    q.same(prior['modules'][KEY], report['modules'][KEY], 'same actual main Text graph')
    q.require(all(row in report['checks'] for row in prior['checks']), 'all original pre-control receipts retained')
    tree = ast.parse(p.contained(root, 'tests/hia_native/' + CONTROLS_TEST).read_bytes())
    values = [ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
              and any(isinstance(t, ast.Name) and t.id == 'CONTROL_NAMES' for t in node.targets)]
    q.same(len(values), 1, 'one source-owned wrapper-refusal set')
    names = values[0]
    q.same(len(names), 12, 'complete physical wrapper domain')
    q.same([row['name'] for row in result['rows']], list(names), 'all physical refusals in source order')
    archive_name = FOLDER + '/fixture-archive/archive.json'
    receipt_name = FOLDER + '/fixture-archive/retired.json'
    baseline_index = p.read_json(output / archive_name)
    baseline_receipt = p.read_json(output / receipt_name)
    baseline_input = p.read_json(output / FOLDER / 'INPUT.json')
    for name in names:
        row = obj(name + '/RESULT.json')
        q.same(row, next(value for value in result['rows'] if value['name'] == name), 'whole physical refusal receipt')
        q.same(row['status'], 'REJECTED', 'actual reader refused changed bytes')
        q.require(row['exception'] in ('ValueError', 'KeyError', 'FileNotFoundError', 'UnicodeDecodeError')
                  and type(row['message']) is str and row['message'], 'actual refusal exception')
        q.require(q.number(row['elapsed_seconds']) and 0 <= row['elapsed_seconds'] < 180, 'real control duration')
        control_report = q.decode(raw(name + '/REPORT.json'))
        q.same(q.pin(raw(name + '/REPORT.json')), row['report'], 'actual per-control complete report')
        wanted_report = copy.deepcopy(prior)
        expected_mutations = {}
        if name == 'group-pid':
            target = next(item for item in wanted_report['checks'] if item['name'] == CHECK)
            target['pid'] += 1
        elif name in ('input-native-binding', 'compiler-binding'):
            value = copy.deepcopy(baseline_input)
            if name == 'input-native-binding': value['native_evidence']['sha256'] = '0' * 64
            else: value['tools']['rustc']['sha256'] = '0' * 64
            expected_mutations[FOLDER + '/INPUT.json'] = p.encoded(value)
        elif name == 'group-stdout':
            expected_mutations[CHECK + '.stdout'] = p.contained(output, CHECK + '.stdout').read_bytes()[:-1]
        elif name in ('resigned-omitted-grant', 'resigned-extra-root', 'resigned-link-target'):
            index = copy.deepcopy(baseline_index)
            if name == 'resigned-omitted-grant':
                next(tree for tree in index['roots'] if tree['permission_grants'])['permission_grants'] = []
            elif name == 'resigned-extra-root':
                index['roots'].append(copy.deepcopy(index['roots'][-1])); index['roots'][-1]['root'] += '-extra'
            else:
                next(node for tree in index['roots'] for node in tree['nodes'] if node['kind'] == 'symlink')['target_base64'] = q.b64(b'other-target')
            expected_mutations[archive_name] = p.encoded(index)
            receipt = copy.deepcopy(baseline_receipt); receipt['archive'] = q.pin(expected_mutations[archive_name])
            expected_mutations[receipt_name] = p.encoded(receipt)
        elif name == 'archive-body':
            node = next(node for tree in baseline_index['roots'] for node in tree['nodes'] if node.get('data', {}).get('bytes', 0) > 0)
            body_name = FOLDER + '/fixture-archive/' + node['data']['file']
            data = p.contained(output, body_name).read_bytes()
            expected_mutations[body_name] = bytes([data[0] ^ 1]) + data[1:]
        elif name == 'duplicate-input-json':
            data = p.contained(output, FOLDER + '/INPUT.json').read_bytes()
            expected_mutations[FOLDER + '/INPUT.json'] = b'{"schema":"duplicate",' + data[1:]
        elif name == 'retained-original-object':
            value = copy.deepcopy(base['original_reference']); value['ordinary_cases'] = 98
            expected_mutations[FOLDER + '/group/EVIDENCE.json'] = p.encoded(value)
        q.same(control_report, wanted_report, 'exact whole source-selected report mutation')
        q.same(set(row['mutations']), set(expected_mutations), 'all and only fixed physical mutation paths')
        q.require(row['mutations'] or row['special'] or name == 'group-pid', 'actual physical mutation or explicit report mutation')
        for changed_name, item in row['mutations'].items():
            q.relative(item['file'])
            q.require(item['file'].startswith(name + '/mutation-'), 'owned complete mutation payload')
            q.same(q.pin(raw(item['file'])), {key: item[key] for key in ('bytes', 'sha256')}, 'full actual mutation bytes')
            q.same(raw(item['file']), expected_mutations[changed_name], 'exact source-selected complete physical mutation')
        if name == 'same-byte-input-symlink':
            q.same(len(row['special']), 1, 'one actual alias corruption')
            special = row['special'][0]
            q.same(set(special), {'path', 'symlink_target', 'identity'}, 'complete actual alias observation')
            q.same(special['path'], FOLDER + '/INPUT.json', 'exact alias path')
            q.same(special['symlink_target'], str(old_output / folder / name / 'same-bytes.json'), 'owned alias target')
            q.require(type(special['identity']) is list and len(special['identity']) == 3
                      and all(q.integer(v, 1) for v in special['identity']) and stat.S_ISLNK(special['identity'][0]),
                      'actual controlled symbolic-link stat')
            q.same(raw(name + '/same-bytes.json'), (output / FOLDER / 'INPUT.json').read_bytes(), 'outside alias had identical bytes')
        elif name == 'live-original-root':
            q.same(len(row['special']), 1, 'one real reappearing private root')
            special = row['special'][0]
            q.same(set(special), {'live_root', 'dev', 'ino'}, 'complete actual private directory identity')
            q.same(special['live_root'], baseline_index['roots'][0]['root'], 'exact owned original root')
            q.require(q.integer(special['dev'], 1) and q.integer(special['ino'], 1), 'actual created private directory inode')
        else: q.same(row['special'], [], 'no unrecorded special-file controls')
    rows = [row for row in report['checks'] if row['name'] == CONTROLS_CHECK]
    q.same(len(rows), 1, 'one actual complete wrapper-control process')
    check = rows[0]
    command = [binding['python'], '-I', '-B', str(old_root / 'tests/hia_native' / CONTROLS_TEST),
        '--repo', str(old_root), '--output', str(old_output),
        '--report', str(old_output / FOLDER / 'pre-controls-report.json'), '--controls', str(old_output / folder)]
    q.same(check['command'], command, 'exact actual wrapper-control invocation')
    q.same(check.get('cwd'), str(old_root), 'actual wrapper-control cwd')
    q.require(q.integer(check.get('pid'), 1), 'actual wrapper-control PID')
    q.same(check['timeout_seconds'], 180, 'unchanged wrapper-control deadline')
    q.same(check['exit_code'], 0, 'complete wrapper-control process exit')
    q.same(check['timed_out'], False, 'wrapper-control timeout')
    q.require(not check.get('start_error'), 'wrapper-control start error')
    q.require(q.number(check['elapsed_seconds']) and 0 < check['elapsed_seconds'] <= 180, 'actual wrapper-control duration')
    for stream in ('stdout', 'stderr'):
        path = p.contained(output, CONTROLS_CHECK + '.' + stream)
        artifacts[CONTROLS_CHECK + '.' + stream] = p.file_pin(path)
        q.same(p.file_pin(path), {'bytes': check[stream + '_bytes'], 'sha256': check[stream + '_sha256']}, 'entire wrapper-control stream')
        if stream == 'stderr': q.same(path.read_bytes(), b'', 'successful control stderr')
        else: q.same(q.decode(path.read_bytes()), {k: v for k, v in result.items() if k not in ('rows', 'read_processes')}, 'actual entire wrapper stdout')
    workspace = old_output.with_name(old_output.name + '-text-original-controls')
    q.same(len(result['read_processes']), 2, 'two actual absent-root read processes')
    for i, process in enumerate(result['read_processes'], 1):
        new_source, new_output = workspace / ('relocation-' + str(i)) / 'source', workspace / ('relocation-' + str(i)) / 'output'
        absent = [old_root, old_output]
        if i == 2: absent += [workspace / 'relocation-1/source', workspace / 'relocation-1/output']
        expected = [binding['python'], '-I', '-B', str(new_source / 'tests/hia_native' / CONTROLS_TEST),
            '--read', '--repo', str(new_source), '--output', str(new_output),
            '--expected', str(workspace / 'BASELINE.json'), '--result', str(workspace / ('read-' + str(i) + '.json'))]
        for path in absent: expected += ['--absent', str(path)]
        q.same(process['command'], expected, 'actual absent-root complete reader command')
        q.same(process['cwd'], str(new_source), 'actual relocated reader source')
        q.clocks(process, 180)
        q.same(obj('relocation-' + str(i) + '.process.json'), process, 'exact actual relocation process receipt')
        for stream in ('stdout', 'stderr'):
            data = raw('relocation-' + str(i) + '.' + stream)
            q.same(q.pin(data), process[stream], 'entire relocation process stream')
            q.same(q.decode(data) if stream == 'stdout' else data,
                   {'status': 'PASS', 'evidence': q.pin(p.encoded(base))} if stream == 'stdout' else b'',
                   'actual absent-root child complete evidence equality')
        q.same(obj('read-' + str(i) + '.json'), {'status': 'PASS', 'evidence': q.pin(p.encoded(base)),
            'actual_absent_paths': [str(path) for path in absent], 'native_calls': 0, 'rust_processes': 0},
            'actual missing-origin readback, including first read root on second pass')
    for key, value in {'status': 'PASS', 'controls': 12, 'actual_absent_root_reads': 2,
                       'private_snapshot_directories_retired': True, 'new_native_calls': 0,
                       'new_rust_processes': 0, 'public_handler_complete': False, 'whole_runtime_replaced': False}.items():
        q.same(result[key], value, 'exact wrapper qualification count/scope ' + key)
    return {**base, 'wrapper_controls': result, 'wrapper_controls_process': check,
        'artifact_sha256': {name: value['sha256'] for name, value in sorted(artifacts.items())},
        'artifact_pins': dict(sorted(artifacts.items()))}


def execute_original(root, output, report, rustc, *, record_check, completed, qualification_env):
    root, output = Path(root).absolute(), Path(output).absolute()
    native, retired = admitted(root, output, report, completed)
    pins = source_pins(root, report)
    rustc = Path(rustc).absolute()
    q.same(str(rustc), report['rust_compiler']['invocation_path'], 'selected actual main compiler')
    tools = {'rustc': rustc, 'cargo': rustc.parent / 'cargo', 'strace': Path(shutil.which('strace') or '')}
    q.require(all(path.is_absolute() for path in tools.values()), 'all required original tools exist')
    folder = output / FOLDER
    folder.mkdir(exist_ok=False)
    binding = {'schema': 'hepta.runtime.text-publication-original-input.v1',
        'execution_source_root': str(root), 'execution_output_root': str(output), 'python': sys.executable,
        'tools': {name: dict(path=str(path), **p.file_pin(path.resolve(strict=True))) for name, path in tools.items()},
        'source_sha256': pins, 'native_evidence': q.pin(p.encoded(native)),
        'native_retirement': q.pin(p.encoded(retired))}
    p.write_new(folder / 'INPUT.json', binding)
    p.write_new(folder / 'native-origins.json', [[native['execution_output_root'], str(output)]])
    record_check(output, report, name=CHECK, command=command(binding, native), timeout=180,
                 env=qualification_env(), record_identity=True)
    _, _, actual_binding, proof, _, actual_pins, _ = _read(root, output, report, completed)
    import hia_native_text_publication_original_fixtures as fixtures
    fixtures.create(output, actual_binding, proof, actual_pins)
    result = original_evidence(root, output, report, completed)
    p.write_new(folder / 'pre-controls-report.json', report)
    record_check(output, report, name=CONTROLS_CHECK,
        command=[sys.executable, '-I', '-B', str(root / 'tests/hia_native' / CONTROLS_TEST),
                 '--repo', str(root), '--output', str(output),
                 '--report', str(folder / 'pre-controls-report.json'), '--controls', str(folder / 'pipeline-controls')],
        timeout=180, env=qualification_env(), record_identity=True)
    result = retained_original(root, output, report, completed)
    q.same(source_pins(root, report), pins, 'original source closure unchanged throughout execution')
    return result
