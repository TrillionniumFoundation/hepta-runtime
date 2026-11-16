"""Read complete frozen evidence without loading or executing native code."""
from collections import Counter, defaultdict
from pathlib import Path
import re
import struct
from common import (ROOT, COMPILER, HEPTA_COMMIT, HEPTA_TREE, envelope, files, loads,
                    pin, read, require, sha, source)


def check_build(root, identity):
    build = root / 'build'
    report = loads(read(build / 'BUILD.json'))
    require(report['schema'] == 'hepta.runtime.audit-native-sync.build.v1'
            and report['source_manifest_sha256'] == identity and report['compiler_sha256'] == COMPILER
            and report['compiler_bootstrap'] == 'fresh pinned B1=B2=B3 on CI', 'fresh B3 build binding')
    dependency = loads(read(ROOT / 'COMPILER_FILES.json'))
    require(dependency['commit'] == HEPTA_COMMIT and dependency['tree'] == HEPTA_TREE
            and len(dependency['files']) == 1080, 'complete pinned compiler source closure')
    retained = files(build / 'compiler-source')
    require(set(retained) == set(dependency['files']), 'complete retained compiler source set')
    for name, row in retained.items():
        require(row['sha256'] == dependency['files'][name], 'retained compiler source: ' + name)
    bootstrap = loads(read(build / 'bootstrap/bootstrap.json'))
    require(bootstrap['dependency'] == dependency and bootstrap['generation_sha256'] == COMPILER,
            'bootstrap compiler/source identity')
    compiler_source = read(build / 'compiler-source/examples/hia_bootstrap/selfhost.hepta')
    require(bootstrap['compiler_source_sha256'] == sha(compiler_source), 'bootstrap source bytes')
    for stage in ('B1', 'B2', 'B3'):
        folder = build / 'bootstrap'
        image = read(folder / (stage + '.image.bin'))
        complete = read(folder / (stage + '.output.bin'))
        receipt = loads(read(folder / (stage + '.receipt.json')))
        require(pin(image) == dict(bytes=673413, sha256=COMPILER), 'fixed-point compiler generation')
        require(read(folder / (stage + '.input.bin')) == compiler_source, 'full compiler input')
        require(len(complete) == 1048576 and complete[:len(image)] == image
                and complete[len(image):] == b'\xa5' * (len(complete) - len(image)), 'full compiler output tail')
        require(receipt['status'] == 'returned' and receipt['source_unchanged'] is True
                and receipt['produced_sha256'] == COMPILER and receipt['output_sha256'] == sha(complete)
                and receipt['result_u64'] == receipt['core_u32'] == len(image)
                and receipt['forbidden_compiler_modules_loaded'] == [], 'actual bootstrap receipt')
    module = build / 'modules/audit-native-sync'
    manifest = loads(read(module / 'manifest.json'))
    raw_source = read(ROOT / 'native/audit_sync_boundary.hepta')
    image = read(module / 'module.image.bin')
    output = read(module / 'module.output.bin')
    receipt = loads(read(module / 'module.receipt.json'))
    require(report['module'] == 'modules/audit-native-sync/manifest.json'
            and report['module_manifest'] == pin(read(module / 'manifest.json')), 'module manifest binding')
    require(manifest['schema'] == 'hepta.runtime.native-module.v1'
            and manifest['name'] == 'audit-native-sync' and manifest['target'] == 'linux-x86_64'
            and manifest['abi'] == 'hepta.runtime.borrowed-bytes.linux-x86_64.v1'
            and manifest['compiler_commit'] == HEPTA_COMMIT and manifest['compiler_sha256'] == COMPILER
            and manifest['source'] == 'audit-native-sync.hepta' and manifest['image'] == 'module.image.bin'
            and manifest['source_sha256'] == sha(raw_source) and manifest['image_sha256'] == sha(image)
            and manifest['standalone'] is None and manifest['buffer_profile'] == 'history.v1', 'native module identity')
    require(read(module / 'audit-native-sync.hepta') == read(module / 'module.input.bin') == raw_source,
            'exact compiler module source')
    require(0 < len(image) < 1048576 and len(output) == 1048576 and output[:len(image)] == image
            and output[len(image):] == b'\xa5' * (len(output) - len(image)), 'complete module output and tail')
    require(receipt['status'] == 'returned' and receipt['source_unchanged'] is True
            and receipt['artifact_sha256'] == receipt['image_sha256'] == COMPILER
            and receipt['input_sha256'] == receipt['source_sha256'] == sha(raw_source)
            and receipt['output_sha256'] == sha(output) and receipt['produced_sha256'] == sha(image)
            and receipt['result_u64'] == receipt['core_u32'] == receipt['produced_bytes'] == len(image)
            and receipt['forbidden_compiler_modules_loaded'] == [], 'actual B3 compilation')
    build_receipt = loads(read(module / 'build.json'))
    require(build_receipt['compile_receipt'] == receipt and build_receipt['compiler_dependency'] == dependency,
            'complete module build receipt')
    return dict(image=pin(image), compiler_files=len(retained))


def check_emission(root, identity):
    folder = root / 'emission'
    report = loads(read(folder / 'EMISSION.json'))
    composition = loads(read(ROOT / 'native/audit_sync_boundary.composition.json'))
    expected_image = composition['emitted_instructions']
    count = expected_image['bytes']
    image = read(folder / 'boundary.bin')
    require(pin(image) == expected_image and report['boundary'] == expected_image, 'exact emitted instruction bytes')
    require(report['schema'] == 'hepta.audit-native-sync.emission.v1'
            and report['source_manifest_sha256'] == identity and report['native_calls'] == 7
            and report['refusals'] == 6 and report['whole_runtime_replaced'] is False, 'emission binding')
    require(report['module_manifest'] == pin(read(root / 'build/modules/audit-native-sync/manifest.json')),
            'actual emitter module binding')
    good = b'HASYPK01' + (1).to_bytes(8, 'little')
    expected = [('valid', good, count + 64, count), ('empty', b'', count + 64, 0xffffffff),
                ('short', good[:-1], count + 64, 0xffffffff), ('long', good + b'\0', count + 64, 0xffffffff),
                ('magic', b'X' + good[1:], count + 64, 0xffffffff),
                ('version', good[:8] + (2).to_bytes(8, 'little'), count + 64, 0xffffffff),
                ('capacity', good, count - 1, 0xfffffffe)]
    require(len(report['calls']) == 7, 'all emitter calls retained')
    physical = 0
    for row, (name, wire, capacity, result) in zip(report['calls'], expected, strict=True):
        require(row['name'] == name and row['returned'] == result and row['output_capacity'] == capacity
                and row['workspace_capacity'] == 64, 'emitter case domain')
        require(set(row['buffers']) == {'input', 'output-before', 'output-after', 'workspace-before', 'workspace-after'},
                'complete physical emitter buffer set')
        raw = {}
        for label, member in row['buffers'].items():
            require(member['file'] == name + '.' + label + '.bin', 'emitter buffer path')
            raw[label] = read(folder / member['file'])
            require(pin(raw[label]) == {k: member[k] for k in ('bytes', 'sha256')}, 'emitter physical buffer identity')
            physical += len(raw[label])
        require(raw['input'] == wire and raw['output-before'] == b'\xa5' * (capacity + 16)
                and raw['workspace-before'] == raw['workspace-after'] == b'\xa5' * 64 + b'\x5a' * 16,
                'emitter input, guards and untouched workspace')
        require(raw['output-after'] == (image + b'\xa5' * (capacity + 16 - count) if name == 'valid'
                                        else raw['output-before']), 'full emitted output or refusal')
    return dict(image=expected_image, calls=7, refusals=6, physical_bytes=physical)


def check_processes(root, capture, domain):
    rows = loads(read(root / 'processes/processes.json'))
    producer = Path(capture['producer_root'])
    original_source = Path(capture['source_root'])
    python = capture['python']
    rust = Path(capture['rust_bin'])
    fixture = str(original_source / 'reference/sync_tests.rs')
    binary = str(producer / 'threads/sync-tests')
    expected = [
        ('format', [str(rust / 'rustfmt'), '--check', '--edition', '2021', '--config', 'hard_tabs=true,max_width=100', fixture]),
        ('compiler-version', [str(rust / 'rustc'), '--version', '--verbose']),
        ('native-build', [python, '-B', str(original_source / 'build.py'), '--hepta', capture['compiler_root'],
                          '--output', str(producer / 'build')]),
        ('emit-boundary', [python, '-B', str(original_source / 'emit.py'), '--manifest',
                           str(producer / 'build/modules/audit-native-sync/manifest.json'), '--output', str(producer / 'emission')]),
        ('rust-build', [str(rust / 'rustc'), *domain['rust_profile'], '--crate-name', 'audit_native_sync_tests',
                        '--target', 'x86_64-unknown-linux-gnu', fixture, '-o', binary]),
        ('actual-threads', [binary, '--test-threads=1', '--nocapture']),
    ]
    require(len(rows) == len(expected), 'complete semantic process set')
    pids = set()
    for row, (name, argv) in zip(rows, expected, strict=True):
        require(row['name'] == name and row['argv'] == argv and row['cwd'] == str(original_source)
                and row['timeout_seconds'] == domain['process_budgets'][name], 'actual process command and original budget')
        require(row['exit_code'] == 0 and row['timed_out'] is False and row['completed'] is True
                and 0 < row['elapsed_seconds'] < row['timeout_seconds'], 'successful bounded process completion')
        require(type(row['pid']) is int and row['pid'] > 1 and row['pgid'] == row['pid']
                and row['pid'] != row['parent_pid'] and row['pid'] not in pids, 'actual isolated process identity')
        pids.add(row['pid'])
        require(row['stdin'] is None, 'no hidden semantic stdin')
        for stream in ('stdout', 'stderr'):
            item = row[stream]
            require(item['file'] == name + '.' + stream, 'complete process stream path')
            require(pin(read(root / 'processes' / item['file'])) == {k: item[k] for k in ('bytes', 'sha256')},
                    'full process stream bytes')
    version = read(root / 'processes/compiler-version.stdout').decode()
    require('\nrelease: 1.95.0\n' in version and '\nhost: x86_64-unknown-linux-gnu\n' in version,
            'exact Rust release and host')
    require(read(root / 'threads/sync-tests').startswith(b'\x7fELF'), 'actual Rust test executable retained')
    stdout = read(root / 'processes/actual-threads.stdout').decode()
    observed = re.findall(r'^test ([a-z0-9_]+) \.\.\. ok$', stdout, re.M)
    require(observed == sorted(domain['cases']) and 'test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;'
            in stdout, 'all fifteen actual Rust-hosted thread tests')
    require(read(root / 'processes/actual-threads.stderr').count(b'panicked at') == 7,
            'seven source-owned actual unwind observations')
    return rows[-1]['pid']


def words(raw):
    require(len(raw) == 128, 'complete physical command or response')
    return struct.unpack('<16Q', raw)


def check_journal(root, pid, domain):
    raw = read(root / 'threads/journal.jsonl')
    require(raw.endswith(b'\n'), 'complete physical journal')
    rows = [loads(line) for line in raw.splitlines()]
    calls = [row for row in rows if row['record'] == 'call']
    states = [row for row in rows if row['record'] == 'quiescent-state']
    observations = [row for row in rows if row['record'] == 'observation']
    require(len(rows) == len(calls) + len(states) + len(observations), 'only frozen journal records')
    require(len(calls) == domain['calls'] and sorted(row['index'] for row in calls) == list(range(domain['calls'])),
            'every actual boundary call exactly once')
    require(Counter(row['case'] for row in calls) == domain['cases'], 'complete per-case actual call counts')
    generations = defaultdict(set)
    per_case = defaultdict(list)
    per_context = defaultdict(list)
    refused = 0
    physical = 0
    for row in calls:
        name = row['case']
        require(type(row['tid']) is int and row['tid'] > 1 and row['pid'] == pid, 'actual kernel thread/process identity')
        require(type(row['generation']) is int and row['generation'] > 0, 'native context identity')
        generations[name].add(row['generation'])
        per_case[name].append(row)
        per_context[row['generation']].append(row)
        request = bytes.fromhex(row['input_hex'])
        before = bytes.fromhex(row['output_before_hex'])
        after = bytes.fromhex(row['output_after_hex'])
        frame = words(request)
        require(len(before) == len(after) == 160 and after[128:] == before[128:] == b'\xa5' * 32,
                'full physical output tail')
        require(row['alias'] in {'disjoint', 'input-output', 'output-state', 'input-state'}, 'declared physical alias control')
        require(before == (request + b'\xa5' * 32 if row['alias'] == 'input-output' else b'\xa5' * 160),
                'complete original output bytes')
        physical += len(request) + len(before) + len(after)
        if row['returned'] != 128:
            require(row['returned'] in (0xffffffff, 0xfffffffe, 0xfffffff9) and before == after,
                    'actual refusal preserves all output bytes')
            refused += 1
            continue
        require(row['alias'] == 'disjoint' and (row['input_length'], row['output_length'], row['state_length']) == (128, 128, 64),
                'exact successful borrowed-buffer frame')
        require(frame[0] == int.from_bytes(b'HASCMD01', 'little') and frame[1] <= 7
                and frame[2] <= 1 and frame[3] == row['generation'] and frame[5] <= 1
                and not any(frame[9:]), 'canonical successful request')
        result = words(after[:128])
        require(result[0] == int.from_bytes(b'HASYNR01', 'little') and result[1] == frame[1]
                and result[3] == row['tid'] and result[10] == row['generation'] and result[15] == 0,
                'native response and independently observed actual TID')
        require(result[2] in (0, 1, 2) and result[5] <= 0xffffffff and result[6] <= 1 and result[7] <= 1
                and result[13] <= 1 and result[14] <= 1, 'native observable state ranges')
        require(result[4] in ((0, 4, 11, 110) if frame[1] == 4 else (0,)), 'actual kernel result')
        if frame[1] != 6:
            require(result[8] == result[9] == 0, 'clock fields only on actual clock operation')
        if frame[1] in (1, 2) and result[2] != 2:
            require(result[11 + frame[2]] == row['tid'] and result[13 + frame[2]] == 1,
                    'acquisition grants real thread custody')
        if frame[1] == 4:
            require(result[11] == row['tid'] and result[13] == 1 and result[2] in (0, 1),
                    'condition wait returns with queue mutex reacquired')
        if result[2] == 2:
            require(frame[1] == 2, 'WouldBlock only from actual try-lock')
    require(refused == domain['physical_refusals'], 'all forty-seven physical refusals')
    require({name: len(values) for name, values in generations.items()} == domain['contexts'], 'all source-owned contexts')
    require(len(per_context) == domain['context_count'] and sorted(per_context) == list(range(1, 25)),
            'twenty-four distinct initialized contexts')
    for generation, group in per_context.items():
        group.sort(key=lambda row: row['index'])
        require(group[0]['returned'] == 128 and words(bytes.fromhex(group[0]['input_hex']))[1] == 0,
                'context starts with actual initialization')
    require(len(states) == 59, 'all quiescent refusal/state witnesses retained')
    for row in states:
        value = bytes.fromhex(row['state_hex'])
        require(row['generation'] in generations[row['case']] and len(value) == 80
                and value[64:] == b'\xa5' * 16 and 0 < row['calls_seen'] <= domain['calls'],
                'complete quiescent state and untouched physical tail')
        physical += len(value)
    by_kind = defaultdict(list)
    for row in observations:
        require(row['generation'] in generations[row['case']], 'observation belongs to actual context')
        by_kind[row['kind']].append(row)
    require({key: len(value) for key, value in by_kind.items()} == {
        'mutual-exclusion': 1, 'notify-all': 1, 'poison': 2, 'existing-unwind': 2,
        'clock': 128, 'interrupted-wait': 1}, 'complete independent semantic observations')
    for kind, case, worker_count in (
        ('mutual-exclusion', 'sixteen_threads_preserve_actual_mutual_exclusion', 16),
        ('notify-all', 'notify_all_releases_all_sixty_five_actual_waiters', 65)):
        observation = by_kind[kind][0]
        tids = observation['worker_tids']
        group = per_case[case]
        main_tid = min(group, key=lambda row: row['index'])['tid']
        require(observation['case'] == case and len(tids) == len(set(tids)) == worker_count
                and main_tid not in tids and set(row['tid'] for row in group) == set(tids) | {main_tid},
                'all actual independent worker threads')
        if kind == 'mutual-exclusion':
            require(observation['counter'] == 4096, 'all native-locked counter increments retained')
            for tid in tids:
                worker = sorted((r for r in group if r['tid'] == tid), key=lambda row: row['index'])
                require([words(bytes.fromhex(r['input_hex']))[1] for r in worker] == [1, 3] * 256,
                        'every worker actual acquisition/release pair')
        else:
            for tid in tids:
                worker = sorted((r for r in group if r['tid'] == tid), key=lambda row: row['index'])
                require([words(bytes.fromhex(r['input_hex']))[1] for r in worker] == [1, 7, 4, 3],
                        'every waiter releases and reacquires actual custody')
    for kind, expected in (('poison', True), ('existing-unwind', False)):
        require(sorted(row['mutex_kind'] for row in by_kind[kind]) == [0, 1]
                and all(row['original_poisoned'] is expected and row['native_poisoned'] is expected
                        for row in by_kind[kind]), 'actual original/native panic semantics')
    clock_case = per_case['native_clock_is_the_actual_unsigned_monotonic_epoch']
    clock_calls = sorted((r for r in clock_case if words(bytes.fromhex(r['input_hex']))[1] == 6), key=lambda r: r['index'])
    previous = 0
    for row, observation in zip(clock_calls, by_kind['clock'], strict=True):
        result = words(bytes.fromhex(row['output_after_hex'])[:128])
        value = (result[9] << 64) | result[8]
        require(observation['value'] == value and previous <= value
                and observation['before'] <= value <= observation['after'], 'actual monotonic clock bounded by independent syscalls')
        previous = value
    signal = by_kind['interrupted-wait'][0]
    require(signal['signal'] == 10 and signal['signals'] == 1 and signal['errno'] == 4, 'actual signal interruption')
    interrupted = [r for r in per_case['interrupted_kernel_wait_reacquires_custody_without_inventing_timeout']
                   if words(bytes.fromhex(r['input_hex']))[1] == 4]
    require(len(interrupted) == 1 and interrupted[0]['tid'] == signal['worker_tid']
            and words(bytes.fromhex(interrupted[0]['output_after_hex'])[:128])[4] == 4, 'signal targets the actual waiting worker')
    return dict(calls=len(calls), contexts=len(per_context), refusals=refused,
                quiescent_states=len(states), observations=len(observations), physical_bytes=physical,
                journal=pin(raw))


def semantic(root):
    root = Path(root).resolve(strict=True)
    identity = source()
    capture = envelope(root)
    domain = loads(read(ROOT / 'DOMAIN.json'))
    require(capture['schema'] == 'hepta.audit-native-sync.capture.v1' and capture['status'] == 'PASS'
            and capture['source_manifest_sha256'] == identity and capture['domain'] == pin(read(ROOT / 'DOMAIN.json')),
            'same-source complete semantic capture')
    require(capture['native_os_boundary_only'] is True and capture['audit_queue_controller_qualified'] is False
            and capture['public_handler_qualified'] is False and capture['whole_runtime_replaced'] is False,
            'exact qualified scope')
    build = check_build(root, identity)
    emission = check_emission(root, identity)
    pid = check_processes(root, capture, domain)
    journal = check_journal(root, pid, domain)
    return dict(schema='hepta.audit-native-sync.read.v1', status='COMPLETE_NATIVE_OS_BOUNDARY_PASS',
                source_manifest_sha256=identity, build=build, emission=emission, journal=journal,
                actual_thread_tests=15, native_os_boundary_only=True, audit_queue_controller_qualified=False,
                public_handler_qualified=False, whole_runtime_replaced=False, semantic_reexecutions=0)


def verify(output, require_controls=False):
    output = Path(output).resolve(strict=True)
    result = semantic(output / 'semantic')
    if require_controls:
        import reader_controls
        result['controls'] = reader_controls.verify(output, result)
    return result
