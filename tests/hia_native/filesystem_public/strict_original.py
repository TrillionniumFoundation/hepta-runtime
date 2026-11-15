"""Admit a fresh unchanged original replay at the native run's exact paths.

The frozen v3 reader owns original semantics and syscall interpretation. This
reader binds the different, scenario-by-scenario execution topology, complete
processes, source, resets and streams. It does not admit a native implementation
or turn an original capture into a native comparison.
"""
from pathlib import Path
from collections import Counter
import argparse
import hashlib
import importlib.util
import json
import os
import re
import stat
import sys
sys.dont_write_bytecode = True

FROZEN_READER = {'bytes': 63585, 'sha256': '98a52accc1b5c740221effde1895535a9cb9c2d719bad0f46d4f9fc02d2906ca'}
DRIVER_FILES = ('capture_common.py', 'replay_original.py', 'strict_original.py')
COUNTS = {'groups': 12, 'scenarios': 28, 'steps': 332, 'public_calls': 323, 'private_controls': 9}


def bootstrap(reader):
    path = Path(reader).absolute()
    for parent in [*reversed(path.parents), path]:
        if parent.is_symlink(): raise ValueError('filesystem SDK followup: reader symlink')
    with path.open('rb') as stream:
        actual = {'bytes': path.stat().st_size, 'sha256': hashlib.file_digest(stream, 'sha256').hexdigest()}
    if actual != FROZEN_READER: raise ValueError('filesystem SDK followup: frozen original reader identity')
    spec = importlib.util.spec_from_file_location('_frozen_filesystem_sdk_followup_reference', path)
    q = importlib.util.module_from_spec(spec); spec.loader.exec_module(q)
    return q


def absolute(q, value, label):
    q.need(type(value) is str, label+' path type'); path = Path(value)
    q.need(path.is_absolute() and '..' not in path.parts and str(path) == value, label+' absolute lexical path')
    return path


def cgroup_evidence(q, text):
    q.need(type(text) is str and text and text.endswith('\n') and '\x00' not in text, 'complete actual cgroup observation')
    rows = [line.split(':', 2) for line in text[:-1].split('\n')]
    q.need(all(len(row) == 3 and row[0].isdecimal() and re.fullmatch(r'[A-Za-z0-9_,=.-]*', row[1]) and row[2].startswith('/') for row in rows), 'actual Linux cgroup fields')
    q.need(len({row[0] for row in rows}) == len(rows), 'duplicate cgroup hierarchy')


def boot_evidence(q, value):
    q.need(type(value) is str and re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', value), 'actual kernel boot identity')
    return value


def tool_evidence(q, capture, name, descriptor):
    q.fields(descriptor, ('path', 'resolved_path', 'captured_file', 'bytes', 'sha256'), 'complete selected tool identity')
    absolute(q, descriptor['path'], 'selected '+name+' invocation')
    absolute(q, descriptor['resolved_path'], 'selected '+name+' resolved binary')
    q.same(descriptor['captured_file'], 'tool-'+name+'.bin', 'complete selected tool copy name')
    q.need(q.uint(descriptor['bytes'], 'selected tool size') > 0 and type(descriptor['sha256']) is str and re.fullmatch(r'[0-9a-f]{64}', descriptor['sha256']), 'selected tool full byte identity')
    copied = capture.file(descriptor['captured_file'], {key: descriptor[key] for key in ('bytes', 'sha256')})
    with copied.open('rb') as stream: q.need(stream.read(4) == b'\x7fELF', 'selected tool ELF bytes')
    return descriptor


def compiler_sysroot(q, rustc_info, rustc):
    outputs = rustc_info.get('outputs'); q.need(type(outputs) is dict and outputs, 'actual Cargo compiler observations')
    rows = list(outputs.values())
    q.need(all(type(row) is dict for row in rows), 'actual compiler output rows')
    successful = [row for row in rows if row.get('success') is True and type(row.get('code')) is int and row['code'] == 0 and row.get('stderr') == '' and type(row.get('stdout')) is str]
    q.need(any(row['stdout'].encode() == rustc for row in successful), 'actual compilation compiler version identity')
    roots = set()
    for row in successful:
        text = row['stdout']
        if 'target_arch="x86_64"\n' not in text or 'target_os="linux"\n' not in text or 'target_env="gnu"\n' not in text: continue
        roots.update(line for line in text.split('\n') if line.startswith('/'))
    q.need(len(roots) == 1, 'one actual compiler sysroot from successful Cargo query')
    return str(absolute(q, next(iter(roots)), 'actual compilation sysroot'))


def command_arguments(q, actual, executable, expected):
    q.need(type(actual) is list and len(actual) == 1+2*len(expected) and all(type(v) is str for v in actual), 'complete actual producer arguments')
    q.same(actual[0], str(executable), 'actual producer source invocation')
    flags = actual[1::2]; q.need(len(flags) == len(set(flags)), 'duplicate actual producer flag')
    q.same(dict(zip(flags, actual[2::2])), expected, 'actual producer complete argument values')


def process_evidence(q, row, name, command, cwd, capture, fence, stdout, stderr, stdin, tools):
    fields = ('name', 'command', 'cwd', 'controlled_env', 'pid', 'exit_code', 'start_error', 'timeout_seconds',
              'timed_out', 'elapsed_seconds', 'stdin', 'stdout', 'stderr')
    q.fields(row, fields, 'complete actual followup process receipt')
    q.same(row['name'], name, 'actual process name/order'); q.same(row['command'], command, 'actual full process command')
    q.same(row['cwd'], os.fsdecode(os.fsencode(cwd)), 'actual same-cwd process')
    q.need(row['start_error'] is None and row['timed_out'] is False, 'actual process start/timeout failure')
    q.same(row['exit_code'], 0, 'actual process exit'); q.same(row['timeout_seconds'], 180, 'actual 180 second process deadline')
    q.positive(row['elapsed_seconds'], 'actual process elapsed'); q.need(row['elapsed_seconds'] < 180, 'actual process elapsed exceeds deadline')
    q.need(q.uint(row['pid'], 'actual PID') > 0, 'actual process PID')
    environment = row['controlled_env']
    q.fields(environment, ('RUSTC', 'CARGO_TARGET_DIR', 'CARGO_BUILD_JOBS', 'PATH', 'LC_ALL', *q.FENCE), 'actual compiler/fence environment')
    expected = {'RUSTC': tools['rustc']['path'], 'CARGO_TARGET_DIR': str(capture/'target'), 'CARGO_BUILD_JOBS': '2',
                'LC_ALL': 'C', **dict.fromkeys(q.FENCE), **fence}
    q.same({key: environment[key] for key in expected}, expected, 'actual fixed compiler/fence settings')
    q.need(type(environment['PATH']) is str and environment['PATH'].startswith(str(Path(tools['rustc']['path']).parent)+':'), 'actual compiler PATH prefix')
    for kind, info in (('stdout', stdout), ('stderr', stderr)):
        q.same(row[kind], {'path': str(capture/(name+'.'+kind)), **info}, 'actual complete '+kind)
    q.same(row['stdin'], None if stdin is None else {'path': str(capture/(name+'.input.jsonl')), **stdin}, 'actual complete process input')


def reset_evidence(q, reset, scene):
    q.fields(reset, ('before', 'removed', 'after', 'scope'), 'complete owned reset record')
    q.same(reset['scope'], 'only this scenario owned native fixture roots; native processes have terminated', 'owned reset domain')
    q.filesystem(reset['before'], scene['observed_roots']); q.filesystem(reset['after'], scene['observed_roots'])
    expected = []
    for tree in reset['before']:
        root = q.hex_bytes(tree['root_hex'], 'reset raw root'); by_path = {q.hex_bytes(n['relative_hex'], 'reset raw node'): n for n in tree['nodes']}
        if 'errno' in by_path[b'']:
            q.need(len(by_path) == 1, 'absent reset root has children'); q.same(by_path[b''], {'relative_hex': '', 'errno': 2}, 'reset absent root')
            continue
        children = {}
        for rel in by_path:
            if rel: children.setdefault(os.path.dirname(rel), []).append(rel)
        def postorder(rel):
            node = by_path[rel]
            q.need('inode' in node and 'readdir_errno' not in node, 'complete removed tree observation')
            for child in sorted(children.get(rel, [])): postorder(child)
            path = root if not rel else root+b'/'+rel
            expected.append({'path_hex': path.hex(), 'device': node['device'], 'inode': node['inode'], 'mode': node['mode']})
        postorder(b'')
    q.same(reset['removed'], expected, 'all actual removed owned objects and postorder')
    q.same(reset['after'], [{'root_hex': path, 'nodes': [{'relative_hex': '', 'errno': 2}]} for path in scene['observed_roots']], 'owned reset leaves only absent scenario roots')
    return {'before_sha256': q.sha(q.canonical(reset['before'])), 'after_sha256': q.sha(q.canonical(reset['after'])), 'removed_objects': len(expected)}


def reference_evidence(reference_source, original_reader, driver_source, native_capture, original_capture):
    q = bootstrap(original_reader)
    source, drivers, native, capture = [q.Binder(root) for root in (reference_source, driver_source, native_capture, original_capture)]
    for name, (size, digest) in q.SOURCES.items(): source.file(name, {'bytes': size, 'sha256': digest})
    factory = q.load(source.file('oracle/verify_sources.py'), '_filesystem_sdk_followup_assembler')
    inputs_factory = q.load(source.file('cases.py'), '_filesystem_sdk_followup_input_generator')
    materialized, original = factory.assemble(source.root/'oracle')
    source_report, report = capture.json('SOURCE.json'), capture.json('ORIGINAL.json')
    q.fields(source_report, ('schema', 'reference_source_root', 'source_files', 'reference_reader', 'driver_source_root', 'driver_sources',
                            'tool_executables', 'native_capture_root', 'native_capture_read_root','native_predecessor',
                            'native_admission','native_admission_artifact_sha256','native_admission_is_separate', 'original_sources_unchanged'), 'followup source report')
    q.same(source_report['schema'], 'hepta.runtime.filesystem-sdk-followup-original-source.v1', 'followup source schema')
    q.need(source_report['native_admission_is_separate'] is True and source_report['original_sources_unchanged'] is True, 'followup source scope')
    old_source = absolute(q, source_report['reference_source_root'], 'original source')
    old_driver = absolute(q, source_report['driver_source_root'], 'producer source')
    old_native = absolute(q, source_report['native_capture_root'], 'actual native capture')
    native_read_root = absolute(q,source_report['native_capture_read_root'],'actual native predecessor read root')
    admission_path = absolute(q,source_report['native_admission']['path'],'actual prior native admission read path')
    old_reader = absolute(q, source_report['reference_reader']['path'], 'frozen reference reader')
    q.same(source_report['reference_reader'], {'path': str(old_reader), **FROZEN_READER}, 'frozen reference reader source pin')
    q.same(source_report['source_files'], source.artifacts, 'seventeen unchanged original source files')
    q.same(sorted(source_report['driver_sources']), sorted(DRIVER_FILES), 'complete followup producer closure')
    for name in DRIVER_FILES: drivers.file(name, source_report['driver_sources'][name])
    drivers.file('strict_original.py')
    native_report = native.json('NATIVE.json'); inputs = native.json('INPUTS.json')
    for name,pin in native_report['artifacts'].items(): native.file(name,pin)
    q.same(source_report['native_predecessor'], native.artifacts, 'complete native source/input/stream/build predecessor pins')
    q.fields(source_report['native_admission'],('path','bytes','sha256'),'complete prior native admission identity')
    prior = capture.json('NATIVE-ADMISSION.json',{key:source_report['native_admission'][key] for key in ('bytes','sha256')})
    q.same(prior.get('schema'),'hepta.runtime.filesystem-sdk-native-evidence.v1','native-only predecessor schema')
    q.need(prior.get('status')=='PASS' and prior.get('native_execution_complete') is True and prior.get('original_capture_read') is False and
        prior.get('original_comparison_complete') is False,'actual native-only predecessor admission domain')
    q.same(source_report['native_admission_artifact_sha256'],prior['artifact_sha256'],'complete admitted predecessor identity')
    q.same({name:digest for name,digest in prior['artifact_sha256'].items() if name.startswith('native-capture/')},
        {'native-capture/'+name:pin['sha256'] for name,pin in native.artifacts.items()},'all prior native physical bytes')
    q.same(prior['fixture_origin'],str(old_native/'fixtures'),'admitted original fixture origin')
    for name,pin in prior['admission_source_files'].items(): q.same(q.pin(q.inside(Path(__file__).absolute().parent,name)),pin,'prior native admission reader source')
    q.same(native_report.get('schema'), 'hepta.runtime.filesystem-sdk-native-capture.v1', 'actual native producer schema')
    q.same(native_report.get('status'), 'NATIVE_EXECUTION_COMPLETE', 'native producer completion')
    q.need(native_report.get('original_replayed') is False and native_report.get('all_processes_terminated') is True, 'native before original execution scope')
    q.same(native_report['fixture_root'], str(old_native/'fixtures'), 'exact actual native fixture root')
    old_fixture = old_native/'fixtures'; corpus = inputs_factory.materialized(old_fixture)
    q.same(inputs, corpus, 'full frozen native input regeneration'); q.same(capture.json('INPUTS.json'), corpus, 'original/native input identity')
    q.same(corpus['counts'], COUNTS, 'complete original input domains'); q.same(native_report['counts'], COUNTS, 'complete native input domains')
    q.same(sorted(native_report['completed_case_ids']), list(range(70000, 70332)), 'native completed all cases before original')
    old_binary = absolute(q, report['binary']['path'], 'fresh original binary')
    q.need(old_binary.parts[-3:] == ('target', 'release', 'hepta-filesystem-sdk-original'), 'original binary layout')
    old_capture = old_binary.parent.parent.parent
    q.same(report['reference_source_root'], str(old_source), 'reported reference provenance')
    q.same(report['native_capture_root'], str(old_native), 'reported native provenance')
    q.same(report['native_capture_read_root'],str(native_read_root),'reported actual predecessor read root')
    q.same(report['native_admission'],source_report['native_admission'],'reported native predecessor admission')
    q.same(report['fixture_root'], str(old_fixture), 'reported shared raw path root')
    q.same(capture.json('ORIGINAL-SOURCE.json'), original, 'unchanged compiled original closure/dependency subset')
    for name, raw in materialized.items(): q.need(capture.data('crate/'+name) == raw, 'complete actual original compiled crate '+name)
    scenes = [scene for group in corpus['groups'] for scene in group['scenarios']]
    names = ['SOURCE.json', 'HOST.json', 'INPUTS.json', 'ORIGINAL-SOURCE.json', 'COMMON-SETUP.json', 'SCENARIOS.json', 'processes.json', 'remote-process.json',
             'NATIVE-ADMISSION.json','tool-rustc.bin','tool-cargo.bin','tool-strace.bin']
    names += [name+'.'+kind for name in ('rustc-version', 'cargo-version', 'strace-version', 'locked-build') for kind in ('stdout', 'stderr')]
    suffixes = ('reset.json', 'input.jsonl', 'policy.json', 'strace', 'stdout', 'stderr', 'observations.jsonl', 'admission.json', 'input.jsonl.gz', 'stdout.gz', 'strace.gz')
    names += ['scenario-%03d.%s'%(scene['scenario_id'], suffix) for scene in scenes for suffix in suffixes]
    q.same(sorted(report.get('artifacts', {})), sorted(names), 'all complete followup artifact names')
    for name in names:
        q.fields(report['artifacts'][name], ('bytes', 'sha256'), 'typed artifact pin'); q.uint(report['artifacts'][name]['bytes'], 'artifact length')
        q.need(type(report['artifacts'][name]['sha256']) is str and re.fullmatch('[0-9a-f]{64}', report['artifacts'][name]['sha256']), 'artifact SHA256')
        capture.file(name, report['artifacts'][name])
    tools = source_report['tool_executables'];q.fields(tools,('rustc','cargo','strace'),'all actual selected tools')
    for name,descriptor in tools.items(): tool_evidence(q,capture,name,descriptor)
    for name, pin in tools.items(): q.same(report[name+'_executable'], pin, 'executed '+name+' identity')
    host = capture.json('HOST.json'); producer = capture.json('remote-process.json')
    q.fields(host, ('uid', 'euid', 'gid', 'egid', 'uname', 'status', 'cwd', 'USER', 'fixture_identity', 'monotonic_started_ns','boot_id'), 'actual host conditions')
    boot_evidence(q,host['boot_id']); native_host=native.json('HOST.json');boot_evidence(q,native_host['boot_id'])
    for name in ('uid', 'euid', 'gid', 'egid'): q.need(q.uint(host[name], 'actual '+name) > 0, 'unprivileged actual fixture execution')
    q.same(host['uid'], host['euid'], 'actual UID'); q.same(host['gid'], host['egid'], 'actual GID')
    q.need(type(host['uname']) is list and len(host['uname']) == 5 and host['uname'][0] == 'Linux' and host['uname'][-1] == 'x86_64', 'actual Linux execution target')
    absolute(q, host['cwd'], 'producer cwd')
    q.need(type(host['status']) is str and '\nCapEff:\t0000000000000000\n' in host['status'] and '\nUmask:\t0077\n' in host['status'], 'actual unprivileged capability and umask')
    q.need(type(host['fixture_identity']) is list and len(host['fixture_identity']) == 3 and all(type(x) is int and x >= 0 for x in host['fixture_identity']), 'actual owned root identity')
    q.same(host['fixture_identity'][2], host['uid'], 'actual fixture owner')
    q.fields(producer, ('pid', 'cgroup', 'argv'), 'actual durable producer')
    q.need(q.uint(producer['pid'], 'producer PID') > 0 and '\nPid:\t'+str(producer['pid'])+'\n' in host['status'], 'producer host/PID binding')
    cgroup_evidence(q,producer['cgroup'])
    command_arguments(q, producer['argv'], old_driver/'replay_original.py', {'--reference-source': str(old_source), '--reference-reader': str(old_reader),
        '--native-capture': str(native_read_root),'--native-admission':str(admission_path), '--output': str(old_capture),
        '--cargo': tools['cargo']['path'], '--rustc': tools['rustc']['path'],'--strace':tools['strace']['path']})
    start = q.uint(report['monotonic_started_ns'], 'actual original start'); finish = q.uint(report['monotonic_finished_ns'], 'actual original finish')
    q.same(host['monotonic_started_ns'], start, 'original start observation')
    q.need(0 < start < finish,'actual original monotonic interval')
    native_finish=q.uint(native_report['monotonic_finished_ns'],'actual native finish')
    same_boot=native_host['boot_id']==host['boot_id']
    q.need(native_finish>0 and (not same_boot or native_finish<start),'same-boot native completion before fresh original execution')
    q.positive(report['elapsed_seconds'], 'actual whole original duration')
    q.need(abs((finish-start)/1_000_000_000-report['elapsed_seconds']) < 0.1, 'whole duration/clock observation')
    initial = capture.json('COMMON-SETUP.json')
    q.need(type(initial) is list and len(initial) == len(corpus['common_setup']), 'complete common setup')
    for action, actual in zip(corpus['common_setup'], initial):
        q.fields(actual, ('action', 'status', 'elapsed_seconds'), 'actual common setup action'); q.same(actual['action'], action, 'same common input action')
        q.same(actual['status'], 'EXECUTED', 'common setup status'); q.positive(actual['elapsed_seconds'], 'common setup duration')
    processes = capture.json('processes.json'); q.need(type(processes) is list and len(processes) == 4+len(scenes), 'all actual followup process receipts')
    commands = [[tools['rustc']['path'], '-Vv'], [tools['cargo']['path'], '-Vv'], [tools['strace']['path'], '-V'],
                [tools['cargo']['path'], 'build', '--release', '--locked', '--manifest-path', str(old_capture/'crate/Cargo.toml')]]
    process_names = ['rustc-version', 'cargo-version', 'strace-version', 'locked-build']
    for number, name in enumerate(process_names):
        process_evidence(q, processes[number], name, commands[number], old_capture/'crate', old_capture, {},
            capture.artifacts[name+'.stdout'], capture.artifacts[name+'.stderr'], None,tools)
    rustc, cargo = capture.data('rustc-version.stdout'), capture.data('cargo-version.stdout')
    q.need(rustc.startswith(b'rustc 1.95.0 (59807616e 2026-04-14)\n') and b'host: x86_64-unknown-linux-gnu\n' in rustc, 'actual explicit Rust 1.95')
    q.need(cargo.startswith(b'cargo 1.95.0 ') and b'release: 1.95.0\n' in cargo, 'actual explicit Cargo 1.95')
    q.need(capture.data('strace-version.stdout').startswith(b'strace -- version '), 'actual tracer version')
    for name in process_names[:3]: q.need(not capture.data(name+'.stderr'), 'version process stderr')
    binary_relative = 'target/release/hepta-filesystem-sdk-original'; binary = capture.file(binary_relative)
    q.same(report['binary'], {'path': str(old_binary), **capture.artifacts[binary_relative]}, 'fresh compiled original binary identity')
    q.need(binary.stat().st_mode & 0o111 and binary.read_bytes().startswith(b'\x7fELF'), 'fresh executable ELF')
    rustc_info = capture.json('target/.rustc_info.json', report['target_rustc_info'])
    q.same(report['compiler_sysroot'],compiler_sysroot(q,rustc_info,rustc),'actual compilation sysroot observation')
    totals = Counter(); trace_totals = Counter(); summaries = []; observations = []; identifiers = []
    for number, scene in enumerate(scenes, 4):
        name = 'scenario-%03d'%scene['scenario_id']; roots = {session['root_hex'] for session in scene['sessions']}
        q.need(len(roots) == 1, 'actual per-scenario common cwd'); cwd = Path(os.fsdecode(q.hex_bytes(next(iter(roots)), 'actual original cwd bytes')))
        expected_input = inputs_factory.canonical(scene)
        q.need(capture.data(name+'.input.jsonl') == expected_input, 'complete same absolute original input')
        q.need(capture.data(name+'.policy.json') == inputs_factory.canonical(corpus['policies'][scene['policy_id']]), 'actual unchanged configuration projection')
        command = [tools['strace']['path'], '-f', '-qq', '-s', '4096', '-xx', '-e', q.TRACE, '-o', str(old_capture/(name+'.strace')),
                   '--', str(old_binary), str(old_fixture), str(old_capture/(name+'.policy.json'))]
        process_evidence(q, processes[number], name, command, cwd, old_capture, corpus['fence_environments'][scene['fence_id']],
            capture.artifacts[name+'.stdout'], capture.artifacts[name+'.stderr'], capture.artifacts[name+'.input.jsonl'],tools)
        reset = reset_evidence(q, capture.json(name+'.reset.json'), scene)
        stdout, stderr = capture.data(name+'.stdout'), capture.data(name+'.stderr'); q.need(not stderr, 'original scenario stderr')
        rows = q.parse_output(stdout)
        q.same([q.strict_json(line) for line in capture.data(name+'.observations.jsonl').split(b'\n') if line], rows, 'full decoded original record projection')
        semantic = q.rows_evidence(rows, [scene], stdout, corpus['policies'][scene['policy_id']] is not None)
        trace = q.trace_evidence(capture.data(name+'.strace'), rows, stdout, stderr, old_fixture, old_binary, old_capture/(name+'.policy.json'))
        q.same(trace['markers'], semantic['markers'], 'full actual syscall marker binding')
        q.same(capture.json(name+'.admission.json'), {'semantics': semantic, 'trace': trace}, 'all actual original producer summaries rederived')
        for suffix in ('input.jsonl', 'stdout', 'strace'): q.gzip_evidence(capture.file(name+'.'+suffix+'.gz'), capture.artifacts[name+'.'+suffix])
        totals.update(semantic['counts']); trace_totals.update(trace['syscall_counts']); identifiers += [case['case_id'] for case in semantic['cases']]
        summaries.append({'scenario_id': scene['scenario_id'], 'name': name, 'cwd_hex': os.fsencode(cwd).hex(), 'policy_id': scene['policy_id'],
            'fence_id': scene['fence_id'], 'original_counts': semantic['counts'], 'markers': semantic['markers'],
            'complete_stdout': capture.artifacts[name+'.stdout'], 'complete_trace': capture.artifacts[name+'.strace']})
        observations.append({'scenario_id': scene['scenario_id'], 'name': name, 'semantics': semantic, 'trace': trace, 'reset': reset})
    q.same(capture.json('SCENARIOS.json'), summaries, 'complete all-scenario original summary')
    q.same(sorted(identifiers), list(range(70000, 70332)), 'all unique observed original cases')
    q.need(len(set(row['pid'] for row in processes)) == len(processes), 'actual original distinct process PIDs')
    q.need(sum(row['elapsed_seconds'] for row in processes) <= report['elapsed_seconds'], 'whole original elapsed covers every process')
    derived = {'schema': 'hepta.runtime.filesystem-sdk-followup-original-capture.v1', 'status': 'ORIGINAL_EXECUTION_COMPLETE',
        'original_scenarios': len(scenes), 'original_counts': dict(totals), 'actual_processes': len(processes), 'fresh_locked_builds': 1,
        'version_processes': 3, 'actual_rust_replays': len(scenes), 'all_paths_equal_to_native_inputs': True, 'response_path_string_substitutions': 0,
        'native_comparison_executed': False, 'native_producer_admission_is_separate': True, 'new_native_calls': 0}
    q.same({key: report.get(key) for key in derived}, derived, 'complete original followup derived counts/scope')
    q.fields(report, (*derived, 'reference_source_root', 'native_capture_root','native_capture_read_root', 'fixture_root', 'elapsed_seconds', 'monotonic_started_ns', 'monotonic_finished_ns',
        'binary', 'rustc_executable', 'cargo_executable', 'strace_executable', 'target_rustc_info','compiler_sysroot','native_admission', 'artifacts'), 'complete followup original report')
    for binder in (source, drivers, native, capture):
        for name, pin in list(binder.artifacts.items()): q.same(q.pin(q.inside(binder.root, name)), pin, 'artifact changed during original admission')
    artifacts = {prefix+'/'+name: value for prefix, binder in (('reference-source', source), ('producer-source', drivers), ('native-capture', native), ('original-capture', capture)) for name, value in binder.artifacts.items()}
    artifacts['original-reader/strict_reference.py'] = FROZEN_READER
    return {'schema': 'hepta.runtime.filesystem-sdk-followup-original-evidence.v1', 'status': 'PASS',
        'observed_counts': dict(sorted(totals.items())), 'actual_processes': len(processes), 'fresh_locked_builds': 1, 'actual_rust_replays': len(scenes),
        'version_processes': 3, 'original_source': original, 'scenarios': observations, 'actual_process_receipts': processes,
        'actual_syscall_counts': dict(sorted(trace_totals.items())), 'actual_execution_roots': {'reference_source': str(old_source), 'producer_source': str(old_driver),
        'native_capture': str(old_native), 'original_capture': str(old_capture), 'fixture': str(old_fixture)},
        'native_evidence_admitted': False, 'native_comparison_executed': False, 'native_predecessor': source_report['native_predecessor'],
        'native_predecessor_admission':source_report['native_admission'],'native_predecessor_artifact_sha256':prior['artifact_sha256'],
        'cross_runner_order_basis':'complete native-only admission and all predecessor byte identities',
        'same_boot_monotonic_order_checked':same_boot,'tool_executables':tools,'compiler_sysroot':report['compiler_sysroot'],
        'same_absolute_fixture_and_cwd': True, 'response_path_string_substitutions': 0, 'original_full_router_executed': False,
        'original_config_loader_executed': False, 'full_configured_fence_acquisition_executed': False, 'remote_io_executed': False,
        'artifacts': len(artifacts), 'artifact_bytes': {key: value['bytes'] for key, value in sorted(artifacts.items())},
        'artifact_sha256': {key: value['sha256'] for key, value in sorted(artifacts.items())},
        'live_fixture_required': False, 'new_rust_processes': 0, 'new_native_calls': 0, 'new_filesystem_operations': 0}


def main():
    p = argparse.ArgumentParser()
    for name in ('reference-source', 'original-reader', 'driver-source', 'native-capture', 'original-capture', 'output'): p.add_argument('--'+name, type=Path, required=True)
    a = p.parse_args(); value = reference_evidence(a.reference_source, a.original_reader, a.driver_source, a.native_capture, a.original_capture)
    with a.output.open('x') as stream: json.dump(value, stream, sort_keys=True, ensure_ascii=True, allow_nan=False, indent=2); stream.write('\n')
    print(json.dumps({'status': value['status'], 'observed_counts': value['observed_counts'], 'actual_processes': value['actual_processes'],
        'artifacts': value['artifacts'], 'native_comparison_executed': False, 'new_rust_processes': 0, 'new_native_calls': 0}, sort_keys=True))


if __name__ == '__main__': main()
