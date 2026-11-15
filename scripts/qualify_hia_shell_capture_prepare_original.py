#!/usr/bin/env python3
"""Qualify the explicit blocking prepare projection against real native OS cases.

The reference source preserves the original capture block's branch and cleanup
order. Its six recorded API edits remove Tokio scheduling, and this reader never
upgrades that limited projection to production prepare, Tokio or registry parity.
"""
from __future__ import annotations
import argparse, hashlib, importlib.util, json, os, re, selectors, signal, stat
import struct, subprocess, sys, time
from pathlib import Path
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
DRIVER = 'scripts/qualify_hia_shell_capture_prepare_original.py'
REFERENCE = 'scripts/hia_native_shell_capture_prepare_reference.py'
HELPERS = 'scripts/hia_native_shell_process_reference.py'
NATIVE = 'tests/hia_native/shell_capture_prepare_io.py'
TRACE_SYNTAX = 'scripts/hia_native_shell_capture_mkdir_qualification.py'
SOURCES = (DRIVER, REFERENCE, HELPERS, NATIVE, TRACE_SYNTAX,
           'tests/hia_native/shell_capture_file_io.py', 'tests/hia_native/shell_capture_mkdir_io.py')
SCHEMA = 'hepta.runtime.shell-capture-prepare-original-comparison.v1'
TIMEOUT = 30
MASK = (1 << 64) - 1
BEGIN, END = b'HSPPORUST-BEGIN\n', b'HSPPORUST-END\n'
ACK = b'HSPPOEND'
TRACE_ARGUMENTS = ('-ff', '-xx', '-v', '-X', 'verbose', '-s', '65536', '-e',
    'trace=execve,execveat,mkdir,mkdirat,statx,newfstatat,open,openat,openat2,unlink,unlinkat,close,close_range,dup,dup2,dup3,fcntl,read,write')
CASE_FILES = ('spec.json', 'stdin.bin', 'stdout.bin', 'stderr.bin', 'before.json',
              'after.json', 'observation.json', 'execution.json', 'retirement.json')
SCOPE = dict(original_prepare_blocking_projection_compared=True, original_tests=0,
    original_helper_bodies_unchanged=True, original_capture_api_edits=6,
    actual_original_atomic_observed=True, kernel_errno_injected=0,
    actual_original_pid_work_fd_numbers_equated=False, raw_streams_and_raw_paths_retained=True,
    native_terminal_resume_counted_as_original_calls=False,
    native_controlled_cleanup_race_compared=False, ambient_sequence_concurrency_qualified=False,
    tokio_runtime_or_cancellation_qualified=False, tokio_blocking_task_failure_qualified=False,
    into_std_inflight_qualified=False, anyhow_error_type_qualified=False,
    native_error_display_qualified=False, registry_duplicate_admission_qualified=False,
    job_construction_qualified=False, ambient_observation_replacement_qualified=False,
    successful_receiver_cleanup='kernel process termination, not a semantic DROP',
    capture_preparation_qualified=False, production_activated=False,
    whole_runtime_replaced=False, old_stack_removal_qualified=False)

def need(condition, message):
    if not condition: raise ValueError(message)

def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + '\n').encode()

def exact(actual, expected, message):
    need(encoded(actual) == encoded(expected), message)

def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}

def load(name, path):
    specification = importlib.util.spec_from_file_location(name, path)
    need(specification is not None and specification.loader is not None, 'reader module unavailable')
    module = importlib.util.module_from_spec(specification); sys.modules[name] = module
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return module

def modules(runtime):
    sys.path.insert(0, str(runtime / 'scripts'))
    native = load('prepare_comparison_native', runtime / NATIVE)
    reference = load('prepare_comparison_reference', runtime / REFERENCE)
    helper = load('prepare_comparison_helpers', runtime / HELPERS)
    syntax = load('prepare_comparison_trace_syntax', runtime / TRACE_SYNTAX)
    need(native.ordinary(runtime / DRIVER) == native.ordinary(Path(__file__)),
         'executing comparison source differs from current source')
    return native, reference, helper, syntax

def source_pins(runtime, native):
    return {name: pin(native.ordinary(runtime / name)) for name in SOURCES}

def environment(output):
    return {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'TMPDIR': str(output / 'temporary')}

def request_for(spec):
    return b'HSPPORQ1' + struct.pack('<7Q', 1, spec['sequence_seed'], 0, 0, 0, 0, 0)

def trace_command(tracer, executable, folder):
    return [str(tracer), *TRACE_ARGUMENTS, '-o', str(folder / 'syscall.trace'), str(executable)]

def decode_response(stdout):
    need(len(stdout) >= 192 and stdout[:8] == b'HSPPORD1', 'complete original ready/response framing')
    ready = struct.unpack_from('<4Q', stdout)
    need(ready[1] > 1 and ready[2:] == (1, 0), 'original ready identity/domain')
    raw = stdout[32:]
    need(raw[:8] == b'HSPPOR01', 'complete original prepare response magic')
    h = struct.unpack_from('<20Q', raw)
    need(h[1] == len(raw) == 160 + sum(h[12:17]) and h[18:] == (0, 0), 'complete original prepare response extent')
    need(h[2] in (0, 1) and h[3] in (0, 1, 2, 3) and h[4] in (0, 1, 2)
         and h[6] in (0, 1) and h[17] in (0, 1) and h[9] == ready[1], 'original prepare typed domain')
    if h[2] == 0:
        need(h[3:6] == (0, 0, 0) and h[17] == 1 and h[6] == 1
             and 2 < h[10] <= 0x7fffffff and 2 < h[11] <= 0x7fffffff and h[10] != h[11],
             'original successful receiver ownership domain')
    else:
        need(h[3] in (1, 2, 3) and h[17] == 0 and h[10:12] == (MASK, MASK)
             and ((h[4] == 1 and 1 <= h[5] <= 4095) or (h[4] == 2 and h[5] == 0)),
             'original prepare error/absent ownership domain')
    at = 160; parts = []
    for length in h[12:17]: parts.append(raw[at:at + length]); at += length
    return ready, h, parts

def parse_trace(raw, executable, env, stdin, stdout, stderr, syntax):
    text = raw.decode('ascii')
    need(text.endswith('\n') and '\r' not in text and '\0' not in text, 'trace complete ASCII framing')
    lines = text.splitlines(); need(lines and lines[-1] == '+++ exited with 0 +++', 'original tracee did not exit normally')
    events = [syntax.record(line) for line in lines[:-1]]
    need(events and sum(row[0] in ('execve', 'execveat') for row in events) == 1,
         'original executable changed during the traced process')
    name, args, returned, error = events[0]
    need(name == 'execve' and len(args) == 3 and returned == error == 0, 'actual original execve')
    need(syntax.c_bytes(args[0]) == os.fsencode(executable), 'actual original executable path')
    need([syntax.c_bytes(item) for item in syntax.words(args[1], '[', ']')] == [os.fsencode(executable)],
         'actual original argument vector')
    need([syntax.c_bytes(item) for item in syntax.words(args[2], '[', ']')] ==
         [key + b'=' + value for key, value in env.items()], 'actual original environment vector')
    writes = {1: bytearray(), 2: bytearray()}; output_events = []; markers = []; input_events = []
    for index, (name, args, returned, error) in enumerate(events):
        if name == 'write':
            need(len(args) == 3 and syntax.integer(args[0]) in writes, 'unexpected original output descriptor')
            fd = syntax.integer(args[0]); body = syntax.c_bytes(args[1])
            need(syntax.integer(args[2]) == len(body) == returned and error == 0, 'incomplete original traced write')
            writes[fd].extend(body); output_events.append((index, fd, body))
            if fd == 2 and body in (BEGIN, END): markers.append((index, body))
        elif name == 'read' and len(args) == 3 and syntax.integer(args[0]) == 0:
            body = syntax.c_bytes(args[1])
            need(0 < len(body) == returned <= syntax.integer(args[2]) and error == 0,
                 'incomplete original control read')
            input_events.append((index, body))
    need(bytes(writes[1]) == stdout and bytes(writes[2]) == stderr, 'traced original writes differ from retained full streams')
    need(len(markers) == 2 and [body for _, body in markers] == [BEGIN, END], 'original std-call marker order/count')
    first, last = (index for index, _ in markers)
    before_output = b''.join(body for index, fd, body in output_events if fd == 1 and index < first)
    after_output = b''.join(body for index, fd, body in output_events if fd == 1 and index > last)
    need(before_output == stdout[:32] and after_output == stdout[32:]
         and not any(fd == 1 and first < index < last for index, fd, _ in output_events),
         'original ready/response causal publication order')
    before_input = [(i, body) for i, body in input_events if i < first]
    after_input = [(i, body) for i, body in input_events if i > last]
    need(b''.join(body for _, body in before_input) == stdin[:64]
         and b''.join(body for _, body in after_input) == ACK and stdin[64:] == ACK
         and len(before_input) + len(after_input) == len(input_events), 'actual control bytes or ordering differ')
    need(before_input and after_input and
         max(i for i, fd, _ in output_events if fd == 1 and i < first) < before_input[0][0]
         and max(i for i, fd, _ in output_events if fd == 1) < after_input[0][0],
         'input acknowledgement preceded its complete ready/response')
    for name, args, returned, error in events[1:first]:
        need(name in ('open', 'openat', 'newfstatat', 'close', 'fcntl', 'read', 'write'),
             'unregistered effect before original capture block')
        if name in ('open', 'openat'):
            at = int(name == 'openat'); need(len(args) in (2 + at, 3 + at), 'loader open framing')
            syntax.c_bytes(args[at]); flags = syntax.integer(args[at + 1])
            need(flags & 3 == 0 and flags & (0x40 | 0x200) == 0, 'writable file opened before original capture block')
        if name == 'fcntl':
            need(len(args) >= 2 and syntax.integer(args[1]) in (1, 3), 'mutating fcntl before original capture block')
    operations = []
    for name, args, returned, error in events[first + 1:last]:
        path_text = None; meta = None; fd = None; flags = 0; mode_argument = 0; dirfd = 0
        if name == 'mkdir':
            need(len(args) == 2 and syntax.integer(args[1]) == 0o777, 'actual original mkdir arguments')
            syscall, action, path_text, mode_argument = 83, 1, args[0], 0o777
        elif name == 'statx':
            need(len(args) == 5 and syntax.integer(args[2]) == 0 and syntax.integer(args[3]) == 4095,
                 'actual original statx flags/mask')
            syscall, mode_argument = 332, 4095
            if args[1] == 'NULL':
                need(syntax.integer(args[0]) == 0 and args[4] == 'NULL', 'actual original NULL statx probe')
                action = 3
            else:
                need(syntax.directory_fd(args[0]) == -100, 'actual original statx directory FD')
                action, path_text, meta, dirfd = 2, args[1], args[4], -100
        elif name == 'newfstatat':
            need(len(args) == 4 and syntax.directory_fd(args[0]) == -100 and syntax.integer(args[3]) == 0,
                 'actual original newfstatat arguments')
            syscall, action, path_text, meta, dirfd = 262, 4, args[1], args[2], -100
        elif name == 'openat':
            need(len(args) == 4 and syntax.directory_fd(args[0]) == -100
                 and syntax.integer(args[2]) == 0x80241 and syntax.integer(args[3]) == 0o666,
                 'actual original File create flags/mode/dirfd')
            syscall, action, path_text, dirfd, flags, mode_argument = 257, 1, args[1], -100, 0x80241, 0o666
        elif name == 'unlink':
            need(len(args) == 1, 'actual original unlink arguments'); syscall, action, path_text = 87, 2, args[0]
        elif name == 'close':
            need(len(args) == 1 and 2 < syntax.integer(args[0]) <= 0x7fffffff, 'actual original owned close descriptor')
            syscall, action, fd = 3, 3, syntax.integer(args[0])
        else: raise ValueError('unregistered effect inside original capture block: ' + name)
        need((syscall == 257 and error == 0 and 2 < returned <= 0x7fffffff)
             or returned == -error, 'original syscall raw result domain')
        path = b'' if path_text is None else syntax.c_bytes(path_text)
        observed = syntax.metadata(meta, action) if action in (2, 4) and syscall in (332, 262) and error == 0 else None
        operations.append(dict(syscall=syscall, action=action, path_hex=path.hex(), raw=returned, errno=error,
            fd=fd, dirfd=dirfd, flags=flags, mode_argument=mode_argument,
            metadata_identity=observed, returned_mode=observed['mode'] if observed else 0))
    need(all(name in ('read', 'write') for name, _, _, _ in events[last + 1:]),
         'additional original file/descriptor call after capture block')
    need(all(name != 'read' or syntax.integer(args[0]) == 0 for name, args, _, _ in events[last + 1:]),
         'unregistered read after capture block')
    return operations, dict(syscalls=len(operations), total_traced_syscalls=len(events),
        mkdir=sum(r['syscall'] == 83 for r in operations), statx=sum(r['syscall'] == 332 for r in operations),
        stat64=sum(r['syscall'] == 262 for r in operations), openat=sum(r['syscall'] == 257 for r in operations),
        close=sum(r['syscall'] == 3 for r in operations), unlink=sum(r['syscall'] == 87 for r in operations),
        all_syscall_path_strings_unabridged=True)

def normalized_path(raw, work, pid, seed, native):
    relative = native.relative_owned(raw, work)
    substitutions = {b'octofs-jobs-' + str(pid).encode(): b'{capture-directory}',
        (str(pid) + '-' + str(seed) + '.stdout.log').encode(): b'{stdout-capture}',
        (str(pid) + '-' + str(seed) + '.stderr.log').encode(): b'{stderr-capture}'}
    components = relative.split(b'/') if relative else []
    return {'absolute': raw.startswith(b'/'),
            'relative_components_hex': [substitutions.get(component, component).hex() for component in components]}

def logical_tree(rows, pid, seed, native):
    tree = native.cf.check_tree(rows); result = []
    substitutions = {b'octofs-jobs-' + str(pid).encode(): b'{capture-directory}',
        (str(pid) + '-' + str(seed) + '.stdout.log').encode(): b'{stdout-capture}',
        (str(pid) + '-' + str(seed) + '.stderr.log').encode(): b'{stderr-capture}'}
    for row in tree.values():
        path = bytes.fromhex(row['path_hex'])
        path = b'/'.join(substitutions.get(component, component) for component in path.split(b'/'))
        item = {'path_hex': path.hex(), 'kind': row['kind'], 'mode': row['mode'], 'uid': row['uid'], 'gid': row['gid']}
        for name in ('payload_hex', 'target_hex'):
            if name in row: item[name] = row[name]
        if row['kind'] != 'directory': item.update(size=row['size'], nlink=row['nlink'])
        result.append(item)
    result.sort(key=lambda row: bytes.fromhex(row['path_hex']))
    need(len({row['path_hex'] for row in result}) == len(result), 'logical path normalization collided')
    return result

def verify_result(spec, work, pid, header, payloads, native_case, native):
    sequence_seen = spec['error_stage'] != 1
    expected_after = (spec['sequence_seed'] + int(sequence_seen)) & MASK
    expected_paths = native.capture_paths(native.tmpdir_for(spec, work), pid, spec['sequence_seed'])
    if not sequence_seen: expected_paths = (expected_paths[0], b'', b'', b'')
    need(header[2:10] == (int(spec['error_stage'] != 0), spec['error_stage'],
         int(spec['error_stage'] != 0), spec['expected_errno'], int(sequence_seen),
         spec['sequence_seed'], expected_after, pid), 'original result differs from registered real outcome')
    need(tuple(payloads[:4]) == expected_paths, 'complete original real PID/TMPDIR/id path bytes')
    if spec['error_stage']:
        prefix = {1: b'Failed to create background job dir: ', 2: b'Failed to create shell stdout log: ',
                  3: b'Failed to create shell stderr log: '}[spec['error_stage']]
        need(payloads[4].startswith(prefix) and len(payloads[4]) > len(prefix), 'original error carrier message prefix')
        payloads[4].decode('utf-8')
    else: need(payloads[4] == b'', 'successful original capture emitted an error message')
    exact(native_case['spec'], spec, 'native/original case specification')
    need(len(native_case['requests']) == len(native_case['results']) == 2, 'native start/resume inventory')
    native_pid = native_case['execution']['pid']; native_work = Path(native_case['execution']['cwd'])
    for index, wire in enumerate(native_case['requests'], 1):
        need(wire == native.request_for(spec, native_work, native_pid, index), 'complete native START/RESUME input')
    need(native_case['results'][0] == native_case['results'][1] and native_case['results'][0][0] == 128,
         'native terminal resume repeated effects or changed the complete tuple')
    nh, np = native.decode_response(native_case['results'][0][1])
    need(nh[2:7] == header[2:7] and nh[7] == (header[7] if sequence_seen else 0)
         and nh[8] == (header[8] if sequence_seen else 0), 'original/native typed error and actual sequence differ')
    for index in (0, 2, 3):
        if index and not sequence_seen:
            need(payloads[index] == np[index] == b'', 'unobserved native/original capture path')
        else:
            exact(normalized_path(payloads[index], work, pid, spec['sequence_seed'], native),
                  normalized_path(np[index], native_work, native_pid, spec['sequence_seed'], native),
                  'native/original explicit PID/work path correspondence')
    need(payloads[1] == (f'{pid}-{spec["sequence_seed"]}'.encode() if sequence_seen else b'')
         and np[1] == (f'{native_pid}-{spec["sequence_seed"]}'.encode() if sequence_seen else b''),
         'actual independent process sequence identifier')
    return native_pid, native_work, nh

def compare_operations(spec, operations, native_case, work, pid, native):
    expected = native_case['operations']
    need(len(operations) == len(expected), 'complete original/native syscall count differs')
    native_work = Path(native_case['execution']['cwd']); native_pid = native_case['execution']['pid']
    correspondence = []; live_original = {}; live_native = {}; saw_file = False
    for index, (original, actual) in enumerate(zip(operations, expected)):
        nr, error = original['syscall'], original['errno']
        need(nr == actual['syscall'] and error == actual['errno'], 'actual original/native syscall/errno order differs')
        exact(normalized_path(bytes.fromhex(original['path_hex']), work, pid, spec['sequence_seed'], native),
              normalized_path(bytes.fromhex(actual['path_hex']), native_work, native_pid, spec['sequence_seed'], native),
              'actual original/native syscall path differs')
        need(original['flags'] == actual['flags'] and original['mode_argument'] == actual['mode_argument']
             and original['returned_mode'] == actual['returned_mode'], 'actual original/native syscall arguments/metadata differ')
        if nr in (83, 332, 262):
            need(not saw_file and actual['role'] == 2 and original['action'] == actual['action'],
                 'original directory preparation occurred after capture creation')
        else: saw_file = True
        if nr == 257 and not error:
            fd = original['raw']; native_fd = actual['raw']; token = actual['token']
            need(fd not in live_original and native_fd not in live_native and actual['role'] in (3, 4)
                 and not any(row['role'] == actual['role'] for row in correspondence), 'fresh original/native capture ownership')
            item = dict(role=actual['role'], original_fd=fd, native_fd=native_fd, native_token=token,
                        open_operation=index, close_operation=None, live_until_receiver_exit=True)
            correspondence.append(item); live_original[fd] = item; live_native[native_fd] = item
        elif nr == 3:
            fd = original['fd']; native_fd = actual['fd_argument']
            need(fd in live_original and native_fd in live_native and live_original[fd] is live_native[native_fd],
                 'original/native cleanup closed a descriptor outside the corresponding owned capture')
            item = live_original.pop(fd); live_native.pop(native_fd)
            need(item['role'] == 3 and actual['close_token'] == item['native_token'] and error == 0,
                 'original stderr failure did not close its owned stdout exactly once')
            item.update(close_operation=index, live_until_receiver_exit=False)
            need(index + 1 < len(operations) and operations[index + 1]['syscall'] == 87,
                 'original stdout cleanup close must immediately precede ignored unlink')
        else:
            need((original['raw'] & MASK) == actual['raw'], 'actual original/native raw syscall result differs')
        if nr in (257, 332, 262): need(original['dirfd'] == -100 or nr == 332 and original['action'] == 3,
                                      'original filesystem relative directory descriptor')
    if spec['error_stage'] == 0:
        need([row['role'] for row in correspondence] == [3, 4] and len(live_original) == 2,
             'successful original/native receiver did not own exactly two captures')
    elif spec['error_stage'] == 3:
        need(len(correspondence) == 1 and not live_original and correspondence[0]['close_operation'] is not None,
             'stderr failure leaked or discarded the wrong capture owner')
    else: need(not correspondence and not live_original, 'earlier original failure fabricated file ownership')
    return correspondence

def verify_trees(folder, spec, pid, receipt, operations, before, after, native):
    cf = native.cf; work = folder / 'work'; old, final = cf.check_tree(before), cf.check_tree(after)
    # Every registered fixture has separate objects and nlink=1 regular files;
    # no hard link is created by its setup or the original capture block.
    for tree in (old, final):
        need(len({(row['device'], row['inode']) for row in tree.values()}) == len(tree),
             'original owned fixture aliases distinct paths')
    setup = native.expected_setup(spec, work, pid)
    need(set(old) == set(setup), 'complete original owned setup inventory')
    for key, expected in setup.items():
        row = old[key]
        need(row['kind'] == expected['kind'] and stat.S_IMODE(row['mode']) == expected['mode']
             and (row['uid'], row['gid']) == (receipt['uid'], receipt['gid']), 'original setup mode/ownership')
        for field in ('payload_hex', 'target_hex'):
            if field in expected: need(row[field] == expected[field], 'original setup full payload/link bytes')
    model = {key: dict(row) for key, row in old.items()}; created = set(); truncated = set(); observed_metadata = {}
    for operation in operations:
        nr, error = operation['syscall'], operation['errno']; path = bytes.fromhex(operation['path_hex'])
        if error: continue
        if nr in (83, 257, 87): key = native.resolve_owned(path, work, model, nr == 257)
        if nr == 83:
            need(key not in model, 'original mkdir success replaced an existing object')
            model[key] = dict(kind='directory', mode=stat.S_IFDIR | (0o777 & ~spec['umask']),
                              uid=receipt['uid'], gid=receipt['gid']); created.add(key)
        elif nr == 257:
            if key not in model:
                model[key] = dict(kind='file', mode=stat.S_IFREG | (0o666 & ~spec['umask']),
                    uid=receipt['uid'], gid=receipt['gid'], nlink=1, size=0, payload_hex=''); created.add(key)
            else: need(model[key]['kind'] == 'file', 'original successful open did not target a regular capture')
            model[key].update(size=0, payload_hex=''); truncated.add(key)
        elif nr == 87:
            need(key in model and model[key]['kind'] != 'directory', 'original unlink success removed an unexpected object')
            del model[key]
        elif nr in (332, 262):
            key = native.resolve_owned(path, work, model)
            need(key in model and operation['metadata_identity'] is not None, 'original metadata target missing')
            metadata = operation['metadata_identity']; need(metadata['mode'] == model[key]['mode'], 'original metadata mode differs from owned object')
            if key in old:
                need(all(metadata[k] == old[key][k] for k in ('device', 'inode', 'mode')), 'original stat identity differs from existing object')
            observed_metadata[key] = metadata
    need(set(model) == set(final), 'original syscall effects differ from complete final tree membership')
    identities = {(row['device'], row['inode']) for row in old.values()}
    for key, expected in model.items():
        actual = final[key]
        for field in ('kind', 'mode', 'uid', 'gid', 'payload_hex', 'target_hex'):
            if field in expected: need(actual[field] == expected[field], 'original syscall final object/bytes differ')
        if expected['kind'] == 'file': need(actual['size'] == expected['size'] and actual['nlink'] == 1,
                                           'original complete capture extent/link count')
        if key in created:
            need((actual['device'], actual['inode']) not in identities, 'original created object reused a retained live inode')
        else:
            need(cf.identity(actual) == cf.identity(old[key]), 'original unrelated/truncated object changed identity')
            if actual['kind'] != 'directory' and key not in truncated: need(actual == old[key], 'original unrelated full object changed')
        if key in observed_metadata:
            need(all(actual[k] == observed_metadata[key][k] for k in ('device', 'inode', 'mode')),
                 'observed original metadata differs from surviving final object')

def observe_process(pid, tracer_pid, executable, work, native, expected=None):
    """Execution-only observer; never called by read_evidence."""
    cf = native.cf; root = Path('/proc') / str(pid); raw = (root / 'stat').read_bytes()
    identity = cf.process_identity(raw)
    need(identity['pid'] == pid and identity['ppid'] == tracer_pid and identity['state'] not in ('Z', 'X'),
         'actual tracee custody identity')
    if expected: need(identity['starttime'] == expected['starttime'], 'actual tracee starttime changed')
    need(os.readlink(root / 'exe') == str(executable) and os.readlink(root / 'cwd') == str(work),
         'actual tracee executable/cwd identity')
    fds = []
    for name in sorted(os.listdir(root / 'fd'), key=int):
        path = root / 'fd' / name
        fds.append(dict(fd=int(name), link_hex=os.fsencode(os.readlink(path)).hex(),
                        stat=cf.stat_row(os.stat(path)), fdinfo_hex=(root / 'fdinfo' / name).read_bytes().hex()))
    return dict(identity=identity, stat_hex=raw.hex(), exe_hex=os.fsencode(os.readlink(root / 'exe')).hex(),
        cwd_hex=os.fsencode(os.readlink(root / 'cwd')).hex(), status_hex=(root / 'status').read_bytes().hex(),
        command_hex=(root / 'cmdline').read_bytes().hex(), environment_hex=(root / 'environ').read_bytes().hex(), fds=fds)

def verify_observations(folder, spec, receipt, observed, result, payloads, after, correspondence, native):
    cf = native.cf; work = folder / 'work'; pid = receipt['target_pid']; first_identity = None
    initial_fds = None; env = native.environment_for(spec, work); final_tree = cf.check_tree(after)
    alive = {row['original_fd']: row for row in correspondence if row['live_until_receiver_exit']}
    snapshots = [observed['initial'], observed['admitted_process'], observed['published_process']]
    for index, snapshot in enumerate(snapshots):
        identity = cf.process_identity(bytes.fromhex(snapshot['stat_hex']))
        exact(snapshot['identity'], identity, 'retained original proc identity differs')
        need(identity['pid'] == pid and identity['ppid'] == receipt['tracer_pid'] and identity['state'] not in ('Z', 'X'),
             'retained original tracee custody identity')
        if first_identity is None: first_identity = identity
        need(identity['starttime'] == first_identity['starttime'] and identity['starttime'] > 0,
             'original tracee changed process lifetime')
        need(snapshot['exe_hex'] == os.fsencode(receipt['original_executable_before']['launch_path']).hex()
             and snapshot['cwd_hex'] == os.fsencode(work).hex(), 'original observed executable/cwd')
        need(bytes.fromhex(snapshot['command_hex']) == os.fsencode(receipt['original_executable_before']['launch_path']) + b'\0'
             and bytes.fromhex(snapshot['environment_hex']) == b''.join(key + b'=' + value + b'\0' for key, value in env.items()),
             'original observed argv/environment differs from launch')
        status = bytes.fromhex(snapshot['status_hex']).decode('ascii')
        for label, expected in (('Pid', [pid]), ('PPid', [receipt['tracer_pid']]),
                                 ('Uid', [receipt['uid']] * 4), ('Gid', [receipt['gid']] * 4)):
            matches = re.findall(r'^' + label + r':\s*([0-9\t ]+)$', status, re.M)
            need(len(matches) == 1 and [int(x) for x in matches[0].split()] == expected, 'original observed process account/parent differs')
        masks = re.findall(r'^Umask:\s*([0-7]+)$', status, re.M)
        need(len(masks) == 1 and int(masks[0], 8) == spec['umask'], 'original observed umask differs')
        names = [row['fd'] for row in snapshot['fds']]
        need(all(type(fd) is int and fd >= 0 for fd in names) and names == sorted(set(names)),
             'original complete descriptor inventory')
        fds = {row['fd']: row for row in snapshot['fds']}
        need(set(fds) == {0, 1, 2} | (set(alive) if index == 2 else set()), 'original descriptor ownership inventory differs')
        if initial_fds is None: initial_fds = fds
        for fd in (0, 1, 2):
            need(cf.identity(fds[fd]['stat']) == cf.identity(initial_fds[fd]['stat'])
                 and fds[fd]['link_hex'] == initial_fds[fd]['link_hex'], 'original transport descriptor changed identity')
        if index == 2:
            for fd, owner in alive.items():
                row = fds[fd]; info = cf.fdinfo(bytes.fromhex(row['fdinfo_hex']))
                target = native.resolve_owned(payloads[2 if owner['role'] == 3 else 3], work, final_tree)
                need(target in final_tree and final_tree[target]['kind'] == 'file', 'original receiver target missing')
                object_row = final_tree[target]
                need(cf.identity(row['stat']) == cf.identity(object_row) and row['stat']['size'] == 0
                     and info['inode'] == object_row['inode'] and info['position'] == 0 and info['flags'] == 0x88001
                     and row['link_hex'] == (os.fsencode(work) + b'/' + bytes.fromhex(target)).hex(),
                     'original receiver actual descriptor/inode/flags/position differ')
    if result[2] == 0:
        need({result[10], result[11]} == set(alive)
             and next(row for row in correspondence if row['role'] == 3)['original_fd'] == result[10]
             and next(row for row in correspondence if row['role'] == 4)['original_fd'] == result[11],
             'original published descriptors differ from actually owned receiver files')
    order = ('ready_received_ns', 'initial_observed_ns', 'setup_completed_ns', 'request_started_ns',
             'request_completed_ns', 'response_received_ns', 'published_observed_ns',
             'ack_started_ns', 'ack_completed_ns', 'process_completed_ns')
    values = [observed.get(key) for key in order]
    need(all(type(value) is int for value in values) and values == sorted(values)
         and receipt['started_ns'] <= values[0] <= values[-1] <= receipt['finished_ns'],
         'original observation/control causal order differs')
    need(observed['after'] == after and observed['exit_code'] == 0 and type(observed['exit_code']) is int,
         'original published tree or final exit observation differs')

def read_case(folder, spec, native_case, native, helper, syntax, build, tracer_identity,
              build_finished, *, retired=True):
    folder = Path(folder).absolute(); native.plain_dir(folder); work = folder / 'work'
    receipt = native.read_json(folder / 'execution.json'); trace_name = receipt.get('trace_file')
    need(type(trace_name) is str and re.fullmatch(r'syscall\.trace\.[1-9][0-9]*', trace_name), 'actual original trace filename')
    members = set(CASE_FILES) | {trace_name}
    if not retired: members.remove('retirement.json'); members.add('work')
    need(set(os.listdir(folder)) == members, 'complete original case retained inventory')
    exact(native.read_json(folder / 'spec.json'), spec, 'registered original prepare case differs')
    need(folder.name == spec['name'] and spec['native_only_controlled_race'] is False
         and spec['cleanup_directory_hook'] is False, 'original comparison includes a native controlled race')
    stdin, stdout, stderr, trace = (native.ordinary(folder / leaf) for leaf in ('stdin.bin', 'stdout.bin', 'stderr.bin', trace_name))
    need(stdin == request_for(spec) + ACK, 'complete original input/control bytes differ')
    need(stderr == BEGIN + END, 'complete original prepare call markers differ')
    ready, result, payloads = decode_response(stdout); pid = ready[1]
    before, after, observed = (native.read_json(folder / leaf) for leaf in ('before.json', 'after.json', 'observation.json'))
    executable = build['executable']['launch_path']; env = native.environment_for(spec, work)
    expected = dict(schema='hepta.runtime.shell-capture-prepare-original-execution.v1', case=spec['name'],
        case_directory=str(folder), cwd=str(work), command=trace_command(tracer_identity['launch_path'], executable, folder),
        environment=native.environment_record(env), umask=spec['umask'], deadline_seconds=TIMEOUT,
        original_executable_before=build['executable'], original_executable_after=build['executable'],
        tracer_before=tracer_identity, tracer_after=tracer_identity, stdin=pin(stdin), stdout=pin(stdout),
        stderr=pin(stderr), trace=pin(trace), trace_files_observed=[trace_name],
        exit_code=0, timed_out=False, error=None, target_pid=pid)
    for key, value in expected.items(): exact(receipt.get(key), value, 'original process binding differs: ' + key)
    need(int(trace_name.rsplit('.', 1)[1]) == pid and type(receipt.get('tracer_pid')) is int
         and receipt['tracer_pid'] > 1 and receipt['tracer_pid'] != pid
         and type(receipt.get('producer_pid')) is int and receipt['producer_pid'] > 1,
         'original tracer/tracee process identities differ')
    start, finish = receipt.get('started_ns'), receipt.get('finished_ns')
    need(type(start) is int and type(finish) is int and 0 < start <= finish
         and type(receipt.get('duration_ns')) is int and receipt['duration_ns'] == finish - start
         and finish - start <= TIMEOUT * 1_000_000_000, 'actual original process timing differs')
    need(type(receipt.get('started_unix_ns')) is int and type(receipt.get('finished_unix_ns')) is int
         and build_finished <= receipt['started_unix_ns'] <= receipt['finished_unix_ns'],
         'original call predates the admitted fresh reference build')
    need(type(receipt.get('uid')) is int and type(receipt.get('gid')) is int and receipt['uid'] != 0
         and (receipt['uid'], receipt['gid']) == (before[0]['uid'], before[0]['gid']),
         'original fixture must be owned by the actual unprivileged account')
    native_pid, native_work, native_header = verify_result(spec, work, pid, result, payloads, native_case, native)
    operations, counts = parse_trace(trace, executable, env, stdin, stdout, stderr, syntax)
    custody = compare_operations(spec, operations, native_case, work, pid, native)
    verify_trees(folder, spec, pid, receipt, operations, before, after, native)
    exact(logical_tree(before, pid, spec['sequence_seed'], native),
          logical_tree(native_case['before'], native_pid, spec['sequence_seed'], native),
          'original/native complete initial logical tree differs')
    exact(logical_tree(after, pid, spec['sequence_seed'], native),
          logical_tree(native_case['after'], native_pid, spec['sequence_seed'], native),
          'original/native complete final logical tree differs')
    verify_observations(folder, spec, receipt, observed, result, payloads, after, custody, native)
    if retired: native.verify_retirement(folder, after)
    else: exact(native.cf.tree_snapshot(work), after, 'original fixture changed before retirement')
    return dict(schema='hepta.runtime.shell-capture-prepare-original-case.v1', status='PASS', name=spec['name'],
        original_pid=pid, native_pid=native_pid, tracer_pid=receipt['tracer_pid'], trace_file=trace_name,
        complete_trace=pin(trace), trace_counts=counts, original_operations=operations,
        result_words=list(result), complete_payloads_hex=[part.hex() for part in payloads],
        actual_original_input=pin(stdin), complete_original_output=pin(stdout),
        complete_native_outputs=[{'return_value': ret, **pin(body)} for ret, body in native_case['results']],
        descriptor_correspondence=custody, before_entries=len(before), after_entries=len(after),
        path_correspondence={'original_work': str(work), 'native_work': str(native_work),
            'actual_pid_components': [pid, native_pid], 'sequence': spec['sequence_seed'],
            'matching': 'exact owned-prefix and registered whole-component PID/id substitution'},
        native_case_directory=receipt['native_case_directory'], **SCOPE)

def run_case(folder, spec, native_case, native_case_directory, native, helper, syntax,
             build, tracer_identity, build_finished):
    folder.mkdir(mode=0o700); work = folder / 'work'; work.mkdir(mode=0o700)
    native.write_new(folder / 'spec.json', encoded(spec))
    executable = Path(build['executable']['launch_path']); env = native.environment_for(spec, work)
    command = trace_command(tracer_identity['launch_path'], executable, folder)
    original_before = helper.tool_identity(executable); tracer_before = helper.tool_identity(Path(tracer_identity['launch_path']))
    started, unix_started = time.monotonic_ns(), time.time_ns()
    process = None; selector = selectors.DefaultSelector(); stdout = bytearray(); stdin = bytearray(); stderr = b''
    observed = {}; timed_out = False; failure = None; drained = False; target = None
    deadline = time.monotonic() + TIMEOUT
    def read(amount):
        result = bytearray()
        while len(result) < amount:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining): raise TimeoutError('original prepare process deadline')
            data = os.read(process.stdout.fileno(), amount - len(result))
            need(bool(data), 'unexpected original ready/response EOF'); result.extend(data); stdout.extend(data)
        return bytes(result)
    def write(raw):
        at = 0
        while at < len(raw):
            sent = os.write(process.stdin.fileno(), raw[at:]); need(sent > 0, 'original control write failed'); at += sent
        stdin.extend(raw)
    try:
        process = subprocess.Popen(command, cwd=work, env=env, umask=spec['umask'], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, bufsize=0)
        selector.register(process.stdout, selectors.EVENT_READ)
        ready = read(32); words = struct.unpack('<4Q', ready)
        need(ready[:8] == b'HSPPORD1' and words[1] > 1 and words[2:] == (1, 0), 'actual original ready header')
        target = words[1]; observed['ready_received_ns'] = time.monotonic_ns()
        observed['initial'] = observe_process(target, process.pid, executable, work, native)
        observed['initial_observed_ns'] = time.monotonic_ns()
        native.setup_fixture(work, spec, target); before = native.cf.tree_snapshot(work)
        native.write_new(folder / 'before.json', encoded(before))
        observed['admitted_process'] = observe_process(target, process.pid, executable, work, native, observed['initial']['identity'])
        observed['setup_completed_ns'] = time.monotonic_ns()
        observed['request_started_ns'] = time.monotonic_ns(); write(request_for(spec)); observed['request_completed_ns'] = time.monotonic_ns()
        header = read(160); h = struct.unpack('<20Q', header)
        need(header[:8] == b'HSPPOR01' and 160 <= h[1] <= 1048576 and h[1] == 160 + sum(h[12:17]),
             'actual original response bounds')
        read(h[1] - 160); observed['response_received_ns'] = time.monotonic_ns()
        observed['published_process'] = observe_process(target, process.pid, executable, work, native, observed['initial']['identity'])
        observed['after'] = native.cf.tree_snapshot(work); observed['published_observed_ns'] = time.monotonic_ns()
        observed['ack_started_ns'] = time.monotonic_ns(); write(ACK); observed['ack_completed_ns'] = time.monotonic_ns()
        process.stdin.close(); process.stdin = None
        tail, stderr = process.communicate(timeout=max(0.01, deadline - time.monotonic())); stdout.extend(tail); drained = True
        observed['process_completed_ns'] = time.monotonic_ns(); observed['exit_code'] = process.returncode
    except BaseException as error:
        timed_out = isinstance(error, (TimeoutError, subprocess.TimeoutExpired)); failure = type(error).__name__ + ': ' + str(error)
        if process is not None and process.poll() is None: os.killpg(process.pid, signal.SIGKILL)
    finally:
        selector.close()
        if process is not None:
            if process.stdin is not None: process.stdin.close(); process.stdin = None
            if not drained:
                tail, stderr = process.communicate(timeout=5); stdout.extend(tail)
        finished, finished_unix = time.monotonic_ns(), time.time_ns()
        after = native.cf.tree_snapshot(work)
        if not (folder / 'before.json').exists(): native.write_new(folder / 'before.json', encoded(after))
        traces = sorted(path.name for path in folder.iterdir() if path.name.startswith('syscall.trace.'))
        trace_name = traces[0] if len(traces) == 1 else None
        trace = native.ordinary(folder / trace_name) if trace_name else b''
        receipt = dict(schema='hepta.runtime.shell-capture-prepare-original-execution.v1', case=spec['name'],
            case_directory=str(folder), native_case_directory=str(native_case_directory), command=command, cwd=str(work),
            environment=native.environment_record(env), umask=spec['umask'], uid=os.geteuid(), gid=os.getegid(),
            producer_pid=os.getpid(), tracer_pid=process.pid if process else None, target_pid=target,
            trace_file=trace_name, trace_files_observed=traces, started_ns=started, finished_ns=finished,
            duration_ns=finished - started, started_unix_ns=unix_started, finished_unix_ns=finished_unix,
            deadline_seconds=TIMEOUT, exit_code=process.returncode if process else None, timed_out=timed_out, error=failure,
            original_executable_before=original_before, original_executable_after=helper.tool_identity(executable),
            tracer_before=tracer_before, tracer_after=helper.tool_identity(Path(tracer_identity['launch_path'])),
            stdin=pin(stdin), stdout=pin(stdout), stderr=pin(stderr), trace=pin(trace))
        for name, raw in (('stdin.bin', bytes(stdin)), ('stdout.bin', bytes(stdout)), ('stderr.bin', stderr),
                          ('execution.json', encoded(receipt)), ('observation.json', encoded(observed)), ('after.json', encoded(after))):
            native.write_new(folder / name, raw)
    try:
        need(failure is None and receipt['exit_code'] == 0, 'actual original capture process failed: ' + str(failure))
        read_case(folder, spec, native_case, native, helper, syntax, build, tracer_identity, build_finished, retired=False)
    except BaseException as error:
        native.write_new(folder / 'failure.json', encoded({'status': 'FAIL', 'error': type(error).__name__ + ': ' + str(error)}))
        native.write_new(folder / 'retirement.json', encoded(native.retire(work, after))); raise
    native.write_new(folder / 'retirement.json', encoded(native.retire(work, after)))
    return read_case(folder, spec, native_case, native, helper, syntax, build, tracer_identity, build_finished)

def admitted(runtime, reference_build, native_corpus, native_manifest, native, reference, helper, rustc, linker):
    build = reference.read_evidence(runtime, reference_build, rustc, linker)
    need(build.get('status') == 'PASS' and build.get('fresh_original_prepare_projection_build_qualified') is True,
         'fresh original prepare projection strong admission')
    report = helper.decode(helper.read(reference_build, 'result.json'))
    finished = max(row['finished_unix_ns'] for row in report['processes'])
    original = {'path': str(reference_build), 'report': pin(helper.read(reference_build, 'result.json')), 'evidence': build}
    evidence = native.read_evidence(native_corpus, native_manifest, require_full=True)
    need(evidence.get('status') == 'PASS' and type(evidence['counts'].get('cases')) is int
         and evidence['counts']['cases'] == 15 and evidence['counts']['retired_fixtures'] == 15
         and evidence['counts']['original_prepare_pair_candidates'] == 14
         and evidence['counts']['native_only_controlled_races'] == 1
         and evidence['physical_controls']['physical_negative_controls'] == len(native.CONTROL_ERRORS),
         'complete native prepare corpus/retirement/controls admission')
    baseline = {'path': str(native_corpus), 'manifest': {'path': str(native_manifest), **pin(native.ordinary(native_manifest))},
                'report': pin(native.ordinary(native_corpus / 'report.json')), 'evidence': evidence}
    specifications = [spec for spec in native.case_specs() if spec['native_only_controlled_race'] is False]
    need(len(specifications) == 14, 'complete original prepare natural case inventory')
    return build, finished, original, baseline, specifications

def retained_inventory(output, specifications, native):
    names = ['source-snapshots/' + name for name in SOURCES]
    for spec in specifications:
        folder = output / 'cases' / spec['name']; trace = native.read_json(folder / 'execution.json')['trace_file']
        need(type(trace) is str and re.fullmatch(r'syscall\.trace\.[1-9][0-9]*', trace), 'retained original trace path')
        names.extend('cases/' + spec['name'] + '/' + leaf for leaf in (*CASE_FILES, trace))
    names.extend(('strace-version.stdout', 'strace-version.stderr', 'strace-version.execution.json'))
    return {name: pin(native.ordinary(output / name)) for name in names}

def counts_for(cases):
    return dict(paired_real_prepare_cases=len(cases), actual_original_processes=len(cases), actual_tracer_processes=len(cases),
        actual_tracer_version_queries=1, retired_original_fixtures=len(cases),
        original_syscalls=sum(row['trace_counts']['syscalls'] for row in cases),
        original_mkdir=sum(row['trace_counts']['mkdir'] for row in cases),
        original_statx=sum(row['trace_counts']['statx'] for row in cases),
        original_stat64=sum(row['trace_counts']['stat64'] for row in cases),
        original_openat=sum(row['trace_counts']['openat'] for row in cases),
        original_close=sum(row['trace_counts']['close'] for row in cases),
        original_unlink=sum(row['trace_counts']['unlink'] for row in cases),
        original_atomic_observations=sum(row['result_words'][6] for row in cases),
        original_files_live_until_receiver_exit=sum(owner['live_until_receiver_exit'] for row in cases for owner in row['descriptor_correspondence']),
        native_terminal_resumes_not_repeated_in_original=len(cases), native_controlled_races_not_replayed_as_original=1)

def read_evidence(runtime, reference_build, native_corpus, native_manifest, output,
                  rustc=None, linker=None, tracer=Path('/usr/bin/strace')):
    runtime, reference_build, native_corpus, native_manifest, output = (
        Path(value).absolute() for value in (runtime, reference_build, native_corpus, native_manifest, output))
    native, reference, helper, syntax = modules(runtime); report = native.read_json(output / 'result.json')
    need(report.get('schema') == SCHEMA and report.get('status') == 'PASS' and report.get('error') is None,
         'original prepare comparison incomplete')
    need(report.get('recorded_directory') == str(output) and report.get('runtime') == str(runtime), 'comparison recorded paths')
    exact(report.get('scope'), SCOPE, 'comparison scope differs')
    exact(report.get('sources'), source_pins(runtime, native), 'comparison current source differs')
    for name in SOURCES:
        need(helper.read(output, 'source-snapshots/' + name) == helper.read(runtime, name), 'comparison complete source snapshot differs')
    build, finished, original, baseline, specifications = admitted(
        runtime, reference_build, native_corpus, native_manifest, native, reference, helper, rustc, linker)
    exact(report.get('reference_build'), original, 'original prepare build binding differs')
    exact(report.get('native_corpus'), baseline, 'native prepare corpus binding differs')
    identity = helper.tool_identity(tracer); exact(report.get('tracer'), identity, 'actual tracer bytes differ')
    helper.completed_process(output, 'strace-version', report.get('tracer_version'), [identity['launch_path'], '--version'], output, TIMEOUT)
    need(helper.read(output, 'strace-version.stderr') == b'' and helper.read(output, 'strace-version.stdout').startswith(b'strace -- version '),
         'actual tracer version query differs')
    exact(report.get('execution_environment'), environment(output), 'comparison version-query environment differs')
    need(set(os.listdir(output / 'cases')) == {spec['name'] for spec in specifications}, 'original natural case directory inventory')
    rows = []
    for spec in specifications:
        native_folder = native_corpus / 'cases' / spec['name']; current = native.read_case(native_folder, native_manifest)
        receipt = native.read_json(output / 'cases' / spec['name'] / 'execution.json')
        need(receipt.get('native_case_directory') == str(native_folder), 'comparison rebound to a different native case')
        rows.append(read_case(output / 'cases' / spec['name'], spec, current, native, helper, syntax, build, identity, finished))
    exact(report.get('cases'), rows, 'reconstructed original prepare case results differ')
    exact(report.get('files'), retained_inventory(output, specifications, native), 'complete original retained byte inventory differs')
    need(len({row['original_pid'] for row in rows}) == len(rows), 'original natural cases reused an original process')
    counts = counts_for(rows); exact(report.get('counts'), counts, 'original prepare counts differ')
    need(not os.listdir(output / 'temporary'), 'original temporary fixture remains')
    need(set(os.listdir(output)) <= {'result.json', 'evidence.json', 'source-snapshots', 'cases', 'temporary',
         'strace-version.stdout', 'strace-version.stderr', 'strace-version.execution.json'}, 'unknown comparison output member')
    return dict(schema='hepta.runtime.shell-capture-prepare-original-evidence.v1', status='PASS',
        report_sha256=pin(native.ordinary(output / 'result.json'))['sha256'], counts=counts,
        fresh_original_build_qualified=True, complete_native_corpus_and_controls_verified=True, **SCOPE)

def run(runtime, reference_build, native_corpus, native_manifest, output,
        rustc=None, linker=None, tracer=Path('/usr/bin/strace')):
    output.mkdir(parents=True, exist_ok=False); (output / 'cases').mkdir(); (output / 'temporary').mkdir()
    report = dict(schema=SCHEMA, status='RUNNING', error=None, recorded_directory=str(output), runtime=str(runtime),
                  scope={**SCOPE, 'original_prepare_blocking_projection_compared': False}, cases=[])
    def save(): (output / 'result.json').write_bytes(encoded(report))
    save()
    try:
        native, reference, helper, syntax = modules(runtime); report['sources'] = source_pins(runtime, native)
        for name in SOURCES:
            destination = output / 'source-snapshots' / name; destination.parent.mkdir(parents=True, exist_ok=True)
            native.write_new(destination, helper.read(runtime, name))
        build, finished, original, baseline, specifications = admitted(
            runtime, reference_build, native_corpus, native_manifest, native, reference, helper, rustc, linker)
        report.update(reference_build=original, native_corpus=baseline, tracer=helper.tool_identity(tracer),
                      execution_environment=environment(output)); save()
        row = helper.process(output, 'strace-version', [report['tracer']['launch_path'], '--version'],
                             output, report['execution_environment'], TIMEOUT)
        report['tracer_version'] = row; save(); need(row['passed'], 'actual tracer version query failed')
        for spec in specifications:
            native_folder = native_corpus / 'cases' / spec['name']; current = native.read_case(native_folder, native_manifest)
            validation = run_case(output / 'cases' / spec['name'], spec, current, native_folder,
                                  native, helper, syntax, build, report['tracer'], finished)
            report['cases'].append(validation); save()
            print(json.dumps({'case': spec['name'], 'status': 'ORIGINAL_PAIR_PASS', 'syscalls': validation['trace_counts']['syscalls']}, sort_keys=True), flush=True)
        report['files'] = retained_inventory(output, specifications, native); report['counts'] = counts_for(report['cases'])
        exact(source_pins(runtime, native), report['sources'], 'comparison sources changed during actual execution')
        report.update(status='PASS', scope=SCOPE); save()
        checked = read_evidence(runtime, reference_build, native_corpus, native_manifest, output, rustc, linker, tracer)
        native.write_new(output / 'evidence.json', encoded(checked))
    except BaseException as error:
        report.update(status='FAIL', error=type(error).__name__ + ': ' + str(error),
                      scope={**SCOPE, 'original_prepare_blocking_projection_compared': False}); save()
    return report

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime', type=Path, default=ROOT)
    parser.add_argument('--reference-build', type=Path, required=True)
    parser.add_argument('--native-corpus', type=Path, required=True)
    parser.add_argument('--native-manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--rustc', type=Path); parser.add_argument('--linker', type=Path)
    parser.add_argument('--tracer', type=Path, default=Path('/usr/bin/strace'))
    parser.add_argument('--read-only', action='store_true'); args = parser.parse_args()
    values = [path.absolute() for path in (args.runtime, args.reference_build, args.native_corpus, args.native_manifest, args.output)]
    if args.read_only: result = read_evidence(*values, args.rustc, args.linker, args.tracer)
    else:
        report = run(*values, args.rustc, args.linker, args.tracer)
        result = dict(status=report['status'], error=report['error'], report=str(values[-1] / 'result.json'),
                      counts=report.get('counts'), whole_runtime_replaced=False)
    print(json.dumps(result, sort_keys=True)); return 0 if result['status'] == 'PASS' else 1

if __name__ == '__main__': raise SystemExit(main())
