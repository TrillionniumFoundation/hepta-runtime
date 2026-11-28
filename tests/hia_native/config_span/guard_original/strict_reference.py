"""Read-only full admission of unchanged guard, actual Rust process, and strace."""
from pathlib import Path
from collections import Counter
import argparse
import errno
import gzip
import hashlib
import importlib.util
import json
import math
import re
import stat
import struct
import sys
sys.dont_write_bytecode = True

SOURCES = {
    "Cargo.toml": [
        168,
        "1c634e0188096b1b4d87b8cd51691b61a42761444c3986f479b7af40410d6a42"
    ],
    "Cargo.lock": [
        396,
        "a5e5523362d03e40e8b2dd1bd54d74d56a2bf3018baa33d9a13fa0853a68b34c"
    ],
    "cases.py": [
        7972,
        "fc80b0d0f09dafd00ecb51307761b4064acea4fa4f21ad23974479049e22811a"
    ],
    "src/driver.rs": [
        3147,
        "33993782b2904cf6632e5c9b6f347f7f64d54b80dd9ab6a530bb524dd377614e"
    ],
    "verify_sources.py": [
        3206,
        "7ab6b9af116b65597563bea4be4d9856f3a668d3807e5fbecdc305bc9e706b0b"
    ],
    "run.py": [
        12370,
        "a3e770da5475243b2a25e6636b36036f14ad00d75c4dce3c1dd0ed601a88b235"
    ],
    "original/config.rs": [
        25272,
        "228f83aa263920ef16e6fca93ce52292cae3cecae5be4b47788a7070fee97f35"
    ],
    "original/runtime.Cargo.lock": [
        90148,
        "7f39704b92d5fc762a98a5313949034db464ca9485827b19b5dde7aa69902d43"
    ]
}


def need(value, message):
    if not value: raise ValueError('directory guard reference: '+message)
def canonical(value): return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(',', ':')).encode()+b'\n'
def same(actual, expected, message): need(canonical(actual) == canonical(expected), message)
def sha(raw): return hashlib.sha256(raw).hexdigest()
def uint(value, message):
    need(type(value) is int and 0 <= value < (1 << 64), message); return value
def positive(value, message): need(type(value) in (int, float) and math.isfinite(value) and 0 < value <= 180, message)


def strict_json(raw):
    def pairs(values):
        result = {}
        for key, value in values: need(key not in result, 'duplicate JSON key'); result[key] = value
        return result
    def bad(value): raise ValueError('directory guard reference: nonfinite JSON')
    def number(value):
        parsed = float(value); need(math.isfinite(parsed), 'nonfinite JSON number'); return parsed
    try: return json.loads(raw, object_pairs_hook=pairs, parse_float=number, parse_constant=bad)
    except (UnicodeError, json.JSONDecodeError) as error: raise ValueError('directory guard reference: malformed JSON') from error


def pin(path):
    with Path(path).open('rb') as stream: return {'bytes': Path(path).stat().st_size, 'sha256': hashlib.file_digest(stream, 'sha256').hexdigest()}


def inside(root, name):
    root, relative = Path(root).absolute(), Path(name)
    need(not relative.is_absolute() and relative.parts and '..' not in relative.parts, 'artifact path escape')
    for folder in [*reversed(root.parents), root]: need(folder.is_dir() and not folder.is_symlink(), 'artifact root symlink')
    path = root
    for part in relative.parts:
        path /= part; value = path.lstat(); need(not stat.S_ISLNK(value.st_mode), 'artifact symlink')
    need(stat.S_ISREG(value.st_mode) and value.st_uid == root.stat().st_uid, 'artifact type/owner')
    return path


class Binder:
    def __init__(self, root): self.root = Path(root).absolute(); self.artifacts = {}
    def file(self, name, expected=None):
        path = inside(self.root, name); actual = pin(path)
        if expected is not None: same(actual, expected, 'complete artifact pin '+str(name))
        same(actual, self.artifacts.setdefault(str(Path(name)), actual), 'artifact changed during admission'); return path
    def data(self, name, expected=None): return self.file(name, expected).read_bytes()
    def json(self, name, expected=None): return strict_json(self.data(name, expected))


class HashWriter:
    def __init__(self): self.hash = hashlib.sha256(); self.count = 0
    def write(self, raw): self.hash.update(raw); self.count += len(raw); return len(raw)
    def pin(self): return {'bytes': self.count, 'sha256': self.hash.hexdigest()}


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path); module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module


def process(row, command, cwd, old_capture, toolchain):
    need(type(row) is dict and 'start_error' not in row and row.get('timed_out') is False, 'actual process startup/timeout')
    same(row.get('command'), command, 'actual process command'); same(row.get('cwd'), str(cwd), 'actual process cwd')
    same(row.get('exit_code'), 0, 'actual process exit'); same(row.get('timeout_seconds'), 180, 'actual process deadline')
    positive(row.get('elapsed_seconds'), 'actual process elapsed'); need(uint(row.get('pid'), 'actual PID') > 0, 'missing PID')
    env = row.get('controlled_env'); need(type(env) is dict and set(env) == {'RUSTC', 'CARGO_TARGET_DIR', 'CARGO_BUILD_JOBS', 'PATH'}, 'complete explicit compiler environment')
    same({key: env[key] for key in ('RUSTC', 'CARGO_TARGET_DIR', 'CARGO_BUILD_JOBS')},
         {'RUSTC': toolchain['rustc'], 'CARGO_TARGET_DIR': str(old_capture/'target'), 'CARGO_BUILD_JOBS': '2'}, 'fixed explicit Rust toolchain')
    need(type(env['PATH']) is str and env['PATH'].startswith(str(Path(toolchain['rustc']).parent)+':'), 'fixed compiler PATH')


def split_arguments(raw):
    result = []; start = 0; depth = 0; quoted = False
    for at, byte in enumerate(raw):
        if byte == '"': quoted = not quoted
        elif not quoted:
            if byte in '([{': depth += 1
            elif byte in ')]}': depth -= 1; need(depth >= 0, 'trace argument nesting')
            elif byte == ',' and depth == 0: result.append(raw[start:at].strip()); start = at+1
    need(not quoted and depth == 0, 'unfinished trace argument'); result.append(raw[start:].strip()); return result


def quoted(raw):
    match = re.fullmatch(r'"((?:\\x[0-9a-f]{2})*)"(\.\.\.)?', raw)
    need(match is not None, 'trace string is not complete hex encoding')
    body = bytes.fromhex(match.group(1).replace('\\x', '')); clipped = match.group(2) is not None
    need(not clipped or len(body) == 4095, 'trace truncated path is not the actual 4095-byte prefix')
    return body, clipped


def path_record(raw, fixture):
    body, clipped = quoted(raw)
    normalized = b'@fixture'+body[len(fixture):] if body == fixture or body.startswith(fixture+b'/') else body
    return {'path_hex': body.hex(), 'normalized_path_hex': normalized.hex(), 'path_truncated': clipped}


def trace_evidence(raw, cases, stdout, stderr, fixture, binary, observations):
    """Admit every traced line, reconstruct both actual streams, keep every guard syscall."""
    need(type(raw) is bytes and raw.endswith(b'\n'), 'unfinished full trace')
    fixture = str(fixture).encode(); binary = str(binary).encode()
    trace_pid = None; active = None; completed = []; offset = 0; counts = Counter(); owned = set()
    opened = closed = probes = truncations = execs = 0; produced = {1: bytearray(), 2: bytearray()}
    next_stdout = 0; seen_stdout = 0; events = []; outside = []
    for line_number, line in enumerate(raw.splitlines(keepends=True), 1):
        match = re.fullmatch(rb'(\d+)\s+([a-z_0-9]+)\((.*)\)\s+=\s+(-?\d+)(?:\s+([A-Z0-9_]+)\s+\([^\n]*\))?\n', line)
        need(match is not None, 'unparsed full trace line '+str(line_number))
        pid, name, args, result, err = int(match[1]), match[2].decode(), split_arguments(match[3].decode('ascii')), int(match[4]), match[5]
        if trace_pid is None: trace_pid = pid
        need(pid == trace_pid and pid > 0, 'trace PID changed')
        error_name = err.decode() if err else None
        need((result == -1) == (error_name is not None), 'trace result/errno shape')
        error_number = getattr(errno, error_name, None) if error_name else 0
        need(type(error_number) is int and (error_name is None or error_number > 0), 'trace errno name')
        event = {'syscall': name, 'return': result, 'errno_name': error_name, 'errno': error_number,
                 'line': line_number, 'offset': offset, 'bytes': len(line), 'sha256': sha(line)}
        offset += len(line); counts[name] += 1
        if name == 'write':
            need(len(args) == 3 and args[0] in ('1', '2'), 'trace write descriptor')
            descriptor = int(args[0]); body, clipped = quoted(args[1])
            need(not clipped and int(args[2]) == len(body) == result, 'trace write is not exact complete delivery')
            produced[descriptor].extend(body)
            if descriptor == 2:
                need(len(body) == 32 and body[:8] == b'HFDGMK01', 'trace marker frame')
                cid, edge, op = struct.unpack_from('<3Q', body, 8)
                need(len(completed) < len(cases), 'extra trace marker')
                case = cases[len(completed)]; need((cid, op) == (case['case_id'], case['operation']), 'trace marker case order')
                if edge == 0:
                    need(active is None and seen_stdout == len(completed) and not owned, 'trace begin state')
                    need(probes == 2*len(completed)+1, 'missing pre-operation FD observation')
                    active = {'case_id': cid, 'operation': op, 'name': case['name'], 'domain': case['domain'],
                              'begin': event, 'events': [], 'fd_probe_before': probes}
                else:
                    need(edge == 1 and active is not None and not owned, 'trace end state')
                    active['end'] = event; active['syscalls'] = len(active['events'])
                    need(op == 1 or not active['events'], 'uninstalled config performed filesystem resolution')
                    completed.append(active); active = None
            else:
                need(active is None and seen_stdout < len(completed) and not owned, 'stdout before operation/cleanup completed')
                row = observations[seen_stdout]; finish = row['record']['offset']+row['record']['bytes']
                need(body == stdout[next_stdout:finish], 'trace complete stdout case bytes')
                need(probes == 2*(seen_stdout+1), 'missing post-operation FD observation')
                next_stdout = finish; seen_stdout += 1
            continue
        if name == 'execve':
            need(active is None and line_number == 1 and len(args) == 3 and result == 0, 'trace executable entry')
            need(quoted(args[0]) == (binary, False) and args[1] == '['+args[0]+']', 'trace actual executable/argv')
            need(re.fullmatch(r'0x[0-9a-f]+ /\* \d+ vars \*/', args[2]) is not None, 'trace exec environment shape')
            execs += 1
        elif name == 'openat':
            need(active is None and len(args) == 3 and args[0] == 'AT_FDCWD', 'unexpected canonicalize descriptor open')
            path, clipped = quoted(args[1]); need(not clipped, 'truncated descriptor path')
            flags = args[2].split('|')
            need(flags in (['O_RDONLY', 'O_CLOEXEC'], ['O_RDONLY', 'O_NONBLOCK', 'O_CLOEXEC', 'O_DIRECTORY']), 'trace open mutation/flags')
            need(result >= 3 and result not in owned, 'trace descriptor ownership')
            owned.add(result); opened += 1; event.update(path_record(args[1], fixture)); event.update(fd=result, flags=flags)
            if path == b'/proc/self/fd':
                need(flags == ['O_RDONLY', 'O_NONBLOCK', 'O_CLOEXEC', 'O_DIRECTORY'], 'FD observation flags')
                probes += 1
            else: need(not completed and active is None and probes == 0, 'unexpected open after loader')
        elif name == 'close':
            need(active is None and len(args) == 1 and args[0].isdigit() and result == 0, 'trace close shape')
            fd = int(args[0]); need(fd in owned, 'trace close without owned descriptor')
            owned.remove(fd); closed += 1; event['fd'] = fd
        elif name == 'access':
            need(active is None and probes == 0 and len(args) == 2 and args[1] == 'R_OK', 'trace loader access')
            event.update(path_record(args[0], fixture))
        elif name == 'readlink':
            need(active is not None and active['operation'] == 1 and len(args) == 3, 'readlink outside active original guard')
            event.update(path_record(args[0], fixture)); event['capacity'] = int(args[2])
            need(event['capacity'] == 1023, 'actual libc canonicalize readlink window')
            if result >= 0:
                body, clipped = quoted(args[1]); need(not clipped and result == len(body) <= event['capacity'], 'trace readlink payload')
                event['target_hex'] = body.hex()
            else: need(re.fullmatch(r'0x[0-9a-f]+', args[1]) is not None, 'trace failed readlink output pointer')
        elif name == 'getcwd':
            need(active is not None and active['operation'] == 1 and len(args) == 2, 'getcwd outside original guard')
            body, clipped = quoted(args[0]); need(not clipped and body == fixture and result == len(body)+1, 'actual cwd bytes')
            need(int(args[1]) >= result, 'getcwd capacity'); event.update(path_record(args[0], fixture)); event['capacity'] = int(args[1])
        elif name == 'faccessat2':
            need(active is not None and active['operation'] == 1 and len(args) == 4 and
                 args[0] == 'AT_FDCWD' and args[2:] == ['F_OK', 'AT_EACCESS'] and result in (-1, 0), 'actual trailing-component check')
            event.update(path_record(args[1], fixture)); event.update(dirfd='AT_FDCWD', mode='F_OK', flags='AT_EACCESS')
        else: raise ValueError('directory guard reference: unexpected syscall '+name)
        truncations += int(event.get('path_truncated', False))
        if active is not None: active['events'].append(event); events.append(event)
        else: outside.append(event)
    need(active is None and len(completed) == len(cases) and seen_stdout == len(cases), 'trace operation count')
    need(execs == 1 and not owned and opened == closed and probes == 2*len(cases), 'trace FD lifetime closure')
    need(bytes(produced[1]) == stdout and bytes(produced[2]) == stderr and next_stdout == len(stdout), 'trace complete stream reconstruction')
    return {'trace_pid': trace_pid, 'trace_bytes': len(raw), 'trace_sha256': sha(raw), 'lines': sum(counts.values()),
            'syscall_counts': dict(sorted(counts.items())), 'canonicalization_syscalls': len(events),
            'outside_operation_syscalls': len(outside), 'open_descriptors': opened, 'closed_descriptors': closed,
            'fd_observations': probes, 'marker_pairs': len(completed), 'truncated_path_arguments': truncations,
            'trace_string_limit': 4096, 'truncated_path_prefix_bytes': 4095, 'full_request_paths_in_bound_binary': True,
            'stdout_bytes_reconstructed': len(stdout), 'stderr_bytes_reconstructed': len(stderr),
            'case_traces': completed, 'outside_operation_events': outside}


def fixture_evidence(before, after, factory, host):
    same(before, after, 'fixture changed during reference')
    nodes = [{'kind': 'directory', 'path': b'', 'mode': 0o700}, *factory.fixture_nodes()]
    need(type(before) is list and len(before) == len(nodes), 'complete fixture node count')
    devices = set(); identities = set()
    for node, row in zip(nodes, before):
        need(type(row) is dict and row.get('relative_hex') == node['path'].hex(), 'fixture relative path/order')
        if node['path'] == b'denied/child':
            same(row, {'relative_hex': node['path'].hex(), 'errno': errno.EACCES}, 'actual denied fixture observation'); continue
        fields = {'relative_hex', 'mode', 'device', 'inode', 'links', 'uid', 'gid', 'size', 'mtime_ns', 'ctime_ns'}
        fields |= {'target_hex'} if node['kind'] == 'symlink' else {'content_bytes', 'content_sha256'} if node['kind'] == 'file' else set()
        same(sorted(row), sorted(fields), 'complete fixture state fields')
        for name in ('mode', 'device', 'inode', 'links', 'uid', 'gid', 'size', 'mtime_ns', 'ctime_ns'): uint(row[name], 'typed fixture '+name)
        need(row['inode'] > 0 and row['links'] > 0, 'fixture identity/links')
        same([row['uid'], row['gid']], [host['uid'], host['gid']], 'fixture owner')
        identity = (row['device'], row['inode']); need(identity not in identities, 'unexpected fixture hardlink identity'); identities.add(identity); devices.add(row['device'])
        if node['kind'] == 'directory':
            same(row['mode'], stat.S_IFDIR+(0 if node['path'] == b'denied' else node['mode']), 'fixture directory mode')
        elif node['kind'] == 'file':
            same(row['mode'], stat.S_IFREG+node['mode'], 'fixture file mode')
            same({'bytes': row['content_bytes'], 'sha256': row['content_sha256']}, {'bytes': len(node['data']), 'sha256': sha(node['data'])}, 'fixture complete file content')
            same(row['size'], len(node['data']), 'fixture file size')
        else:
            same(row['mode'], stat.S_IFLNK+0o777, 'fixture symlink mode'); same(row['target_hex'], node['target'].hex(), 'fixture symlink target')
            same(row['size'], len(node['target']), 'fixture symlink size')
    need(len(devices) == 1, 'fixture unexpected devices')
    return {'nodes': len(nodes), 'before_after_identical': True, 'actual_denied_observations': 1,
            'snapshot_sha256': sha(canonical(before)), 'live_fixture_required': False}


def gzip_evidence(path, expected):
    writer = HashWriter()
    with gzip.open(path, 'rb') as stream:
        while block := stream.read(1024*1024): writer.write(block)
    same(writer.pin(), expected, 'complete decompressed stream')


def reference_evidence(source_root, capture_root):
    source = Binder(source_root); capture = Binder(capture_root)
    for name, (size, digest) in SOURCES.items(): source.file(name, {'bytes': size, 'sha256': digest})
    factory = load(source.file('verify_sources.py'), '_guard_source_verify')
    main_source, lock, original = factory.assemble(source.root)
    source_report = capture.json('SOURCE.json'); report = capture.json('RESULT.json')
    same(report.get('schema'), 'hepta.runtime.directory-move-guard-original-capture.v1', 'capture schema')
    same(report.get('status'), 'PASS', 'capture status')
    original_source = Path(report['source_root']); original_fixture = Path(report['fixture_root']); original_capture = Path(report['output_root'])
    need(all(path.is_absolute() and '..' not in path.parts for path in (original_source,original_fixture,original_capture)), 'actual execution roots')
    execution = source_report.get('execution')
    same(sorted(execution) if type(execution)is dict else None,
         sorted(['output_root','fixture_root','fixture_mode','rustc','cargo','strace']), 'explicit portable execution fields')
    same({key: execution[key] for key in ('output_root','fixture_root','fixture_mode')},
         {key: report[key] for key in ('output_root','fixture_root','fixture_mode')}, 'execution fixture/output provenance')
    need(execution['fixture_mode'] in ('new-owned','existing-owned'), 'owned fixture mode')
    if execution['fixture_mode']=='new-owned':same(str(original_fixture),str(original_capture/'fixtures'),'new fixture ownership')
    else:need(original_fixture not in (original_source,original_capture),'independent existing owned fixture')
    for key in ('rustc','cargo','strace'):
        value=execution[key];need(type(value)is str and Path(value).is_absolute()and '..'not in Path(value).parts,'explicit '+key+' invocation')
    same(source_report.get('source_root'), str(original_source), 'source root provenance')
    same(source_report.get('source_files'), source.artifacts, 'complete eight-file source graph')
    same(source_report.get('original'), original, 'unchanged original source spans/lock subset')
    materialized = {'src/main.rs': main_source, 'Cargo.lock': lock, 'Cargo.toml': source.data('Cargo.toml')}
    for name, body in materialized.items(): need(capture.data('crate/'+name) == body, 'byte-exact compiled crate '+name)
    same(source_report.get('materialized'), {name: capture.artifacts['crate/'+name] for name in materialized}, 'materialized source pins')
    same(sorted(source_report), ['execution', 'materialized', 'original', 'source_files', 'source_root'], 'complete source report shape')
    names = ['HOST.json', 'SOURCE.json', 'cargo-version.stderr', 'cargo-version.stdout', 'fixture-after.json', 'fixture-before.json',
             'input-cases.jsonl', 'input.bin', 'input.bin.gz', 'locked-build.stderr', 'locked-build.stdout', 'observations.jsonl',
             'original.stderr', 'original.stderr.gz', 'original.stdout', 'original.stdout.gz', 'original.strace', 'original.strace.gz',
             'processes.json', 'remote-process.json', 'rustc-version.stderr', 'rustc-version.stdout', 'strace-version.stderr', 'strace-version.stdout']
    same(sorted(report.get('artifact_bytes', {})), sorted(names), 'complete capture artifact bytes set')
    same(sorted(report.get('artifact_sha256', {})), sorted(names), 'complete capture artifact digest set')
    for name in names:
        size = uint(report['artifact_bytes'][name], 'typed artifact byte count'); digest = report['artifact_sha256'][name]
        need(type(digest) is str and re.fullmatch('[0-9a-f]{64}', digest) is not None, 'artifact digest shape')
        capture.file(name, {'bytes': size, 'sha256': digest})
    cases_factory = load(source.file('cases.py'), '_guard_cases')
    replay = load(source.file('run.py'), '_guard_capture_producer')
    cases = cases_factory.iter_cases(original_fixture); need(len(cases) == 92, 'fixed input case count')
    need([case['case_id'] for case in cases] == list(range(60000, 60092)), 'fixed input case order')
    writer = HashWriter(); cases_factory.encode(writer, cases)
    same(writer.pin(), capture.artifacts['input.bin'], 'complete regenerated input bytes')
    input_rows = [strict_json(line) for line in capture.data('input-cases.jsonl').split(b'\n') if line]
    same(input_rows, replay.input_rows(cases), 'full input spans/raw path/root order')
    stdout, stderr = capture.data('original.stdout'), capture.data('original.stderr')
    need(stderr == replay.marker_bytes(cases), 'complete actual marker stream')
    observations = replay.parse_output(stdout, cases)
    observed = [strict_json(line) for line in capture.data('observations.jsonl').split(b'\n') if line]
    same(observed, observations, 'complete original output/error/errno/FD projection')
    for row in observations:
        same(row['fd_before'], 4, 'actual pre-operation FD count'); same(row['fd_after'], 4, 'actual post-operation FD count')
        if row['operation'] == 2:
            same([row['status'], row['errno_present'], row['errno']], [1, 0, 0], 'actual missing-config result')
            same([row['short']['text'], row['chain']['text']], ['runtime tools are disabled; start with --runtime-config <file>']*2,
                 'actual missing-config error bytes')
    for name in ('input.bin', 'original.stdout', 'original.stderr', 'original.strace'):
        gzip_evidence(capture.file(name+'.gz'), capture.artifacts[name])
    processes = capture.json('processes.json'); need(type(processes) is list and len(processes) == 5, 'all actual subprocesses')
    commands = [[execution['rustc'], '-Vv'], [execution['cargo'], '-Vv'], [execution['strace'], '-V'],
        [execution['cargo'], 'build', '--release', '--locked', '--manifest-path', str(original_capture/'crate/Cargo.toml')],
        [execution['strace'], '-f', '-qq', '-s', '4096', '-xx', '-e', 'trace=%file,close,write', '-o',
         str(original_capture/'original.strace'), '--', str(original_capture/'target/release/hepta-directory-guard-original')]]
    process_names = ['rustc-version', 'cargo-version', 'strace-version', 'locked-build', 'original']
    for number, (row, command, name) in enumerate(zip(processes, commands, process_names)):
        same(row.get('name'), name, 'actual subprocess order/name')
        same(sorted(row), sorted(['name', 'command', 'controlled_env', 'cwd', 'elapsed_seconds', 'exit_code', 'pid',
             'stderr', 'stdin', 'stdout', 'timed_out', 'timeout_seconds']), 'complete subprocess receipt')
        process(row, command, original_fixture if number == 4 else original_capture/'crate', original_capture, execution)
        for kind in ('stdout', 'stderr'):
            key = name+'.'+kind
            same(row[kind], {'path': str(original_capture/key), **capture.artifacts[key]}, 'actual complete '+name+' '+kind)
        same(row['stdin'], {'path': str(original_capture/'input.bin'), **capture.artifacts['input.bin']} if number == 4 else None, 'actual process complete stdin')
    need(len({row['pid'] for row in processes}) == len(processes), 'actual subprocess PIDs reused')
    rustc = capture.data('rustc-version.stdout'); cargo = capture.data('cargo-version.stdout')
    need(rustc.startswith(b'rustc 1.95.0 (59807616e 2026-04-14)\n') and b'host: x86_64-unknown-linux-gnu\n' in rustc,
         'actual Rust version/host')
    need(cargo.startswith(b'cargo 1.95.0 ') and b'release: 1.95.0\n' in cargo, 'actual Cargo version')
    need(capture.data('strace-version.stdout').startswith(b'strace -- version '), 'actual strace version')
    for name in ('rustc-version', 'cargo-version', 'strace-version'): need(not capture.data(name+'.stderr'), 'version process stderr')
    tools = {'rustc': (644784, 'bff349e72704ff70bc08a234a3847338e797065bbedde5e556808bc87b7bf7c6'),
             'cargo': (42185192, '841072d1d92f9e841d9ba5b0814182a0adf064acf4527cd120967b7bc49dcb66'),
             'strace': None}
    strace_image=capture.file('toolchain/strace.bin');need(strace_image.read_bytes().startswith(b'\x7fELF'),'actual platform strace image')
    tools['strace']=(capture.artifacts['toolchain/strace.bin']['bytes'],capture.artifacts['toolchain/strace.bin']['sha256'])
    for name, (size, digest) in tools.items():
        same(report.get(name+'_executable'), {'path': execution[name],
             'bytes': size, 'sha256': digest}, 'actual fixed executable identity '+name)
    binary = capture.file('target/release/hepta-directory-guard-original')
    same(report.get('binary'), {'path': commands[-1][-1], **capture.artifacts['target/release/hepta-directory-guard-original']}, 'actual replay binary')
    need(binary.stat().st_mode & 0o111 and binary.read_bytes().startswith(b'\x7fELF'), 'actual original executable')
    rustc_info = capture.json('target/.rustc_info.json', report.get('target_rustc_info'))
    info_rows = rustc_info.get('outputs'); need(type(info_rows) is dict, 'target compiler identity records')
    need(any(type(row) is dict and row.get('success') is True and type(row.get('code')) is int and row['code'] == 0 and
             row.get('stderr') == '' and row.get('stdout', '').encode() == rustc for row in info_rows.values()), 'actual target compiler full version')
    need(any(type(row)is dict and row.get('success')is True and any(line.startswith('/') for line in row.get('stdout','').splitlines()) for row in info_rows.values()), 'actual target compiler path outputs')
    host = capture.json('HOST.json')
    for name in ('uid', 'euid', 'gid', 'egid'): need(uint(host.get(name), 'host '+name) > 0, 'unprivileged fixture execution')
    same(host['uid'], host['euid'], 'host effective UID'); same(host['gid'], host['egid'], 'host effective GID')
    same(host.get('cwd'), str(original_fixture), 'host fixture cwd'); same(host.get('scope'), 'owned local Linux fixture', 'host fixture scope')
    need(type(host.get('uname')) is list and len(host['uname']) == 5 and host['uname'][0] == 'Linux' and host['uname'][-1] == 'x86_64', 'actual Linux host')
    need(type(host.get('status')) is str and '\nCapEff:\t0000000000000000\n' in host['status'] and '\nUmask:\t0077\n' in host['status'], 'actual permission/umask conditions')
    fixture = fixture_evidence(capture.json('fixture-before.json'), capture.json('fixture-after.json'), cases_factory, host)
    producer = capture.json('remote-process.json')
    same(sorted(producer), ['argv', 'cgroup', 'pid'], 'producer process identity fields')
    argv=producer.get('argv');need(type(argv)is list and all(type(x)is str for x in argv) and len(argv)>=11 and len(argv)%2==1,'actual producer argv shape')
    same(argv[0],str(original_source/'run.py'),'actual source entry')
    options={}
    for option,value in zip(argv[1::2],argv[2::2],strict=True):
        need(option in ('--root','--output','--rustc','--cargo','--strace','--fixture-root')and option not in options,'unique explicit execution options')
        options[option]=value
    expected_options={'--root':str(original_source),'--output':str(original_capture),'--rustc':execution['rustc'],'--cargo':execution['cargo'],'--strace':execution['strace']}
    if execution['fixture_mode']=='existing-owned':expected_options['--fixture-root']=str(original_fixture)
    same(options,expected_options,'actual explicit producer argv')
    need(uint(producer['pid'], 'producer PID') > 0 and '\nPid:\t'+str(producer['pid'])+'\n' in host['status'], 'actual producer PID/host correlation')
    need(type(producer['cgroup'])is str and re.fullmatch(r'(?:\d+:[^\n]*:[^\n]+\n)+',producer['cgroup'])is not None,'actual Linux producer cgroup')
    trace = trace_evidence(capture.data('original.strace'), cases, stdout, stderr, original_fixture,
                           original_capture/'target/release/hepta-directory-guard-original', observations)
    counts = {'cases': len(cases), 'unchanged_guard_helper_cases': sum(c['operation'] == 1 for c in cases),
        'uninstalled_config_projection_cases': sum(c['operation'] == 2 for c in cases), 'successes': sum(r['status'] == 0 for r in observations),
        'errors': sum(r['status'] == 1 for r in observations), 'marker_pairs': len(cases),
        'complete_error_bytes': sum(r['short']['bytes']+r['chain']['bytes'] for r in observations),
        'actual_processes': 5, 'actual_original_replays': 1, 'fresh_locked_builds': 1, 'version_processes': 3, 'trace_string_limit': 4096,
        'new_native_calls': 0, 'source_files_unchanged': True, 'fixture_before_after_equal': True, 'installed_config_startup_executed': False,
        'public_sdk_executed': False, 'public_filesystem_handler_executed': False, 'actual_move_executed': False}
    same({key: report.get(key) for key in counts}, counts, 'derived capture counts/scope')
    positive(report.get('elapsed_seconds'), 'capture actual duration')
    need(report['elapsed_seconds'] >= sum(row['elapsed_seconds'] for row in processes), 'capture duration smaller than actual subprocesses')
    same(sorted(report), sorted([*counts, 'schema', 'status', 'source_root', 'fixture_root', 'output_root', 'fixture_mode', 'elapsed_seconds',
         'artifact_bytes', 'artifact_sha256', 'rustc_executable', 'cargo_executable', 'strace_executable', 'binary', 'target_rustc_info']), 'complete result report')
    for binder in (source, capture):
        for name, expected in list(binder.artifacts.items()): same(pin(inside(binder.root, name)), expected, 'file changed while reading')
    artifacts = {**{'source/'+key: value for key, value in source.artifacts.items()}, **{'capture/'+key: value for key, value in capture.artifacts.items()}}
    return {'schema': 'hepta.runtime.directory-move-guard-original-evidence.v1', 'status': 'PASS', **counts,
        'complete_input_bytes': capture.artifacts['input.bin']['bytes'], 'complete_output_bytes': len(stdout), 'complete_marker_bytes': len(stderr),
        'original_source': original, 'input_cases': input_rows, 'observations': observations, 'fixture': fixture, 'trace': trace,
        'actual_processes_receipts': processes, 'actual_producer': producer, 'actual_execution_roots': {'source': str(original_source), 'capture': str(original_capture), 'fixture':str(original_fixture)},
        'toolchain': {name: report[name+'_executable'] for name in tools}, 'original_binary': report['binary'],
        'artifacts': len(artifacts), 'artifact_bytes': {key: value['bytes'] for key, value in sorted(artifacts.items())},
        'artifact_sha256': {key: value['sha256'] for key, value in sorted(artifacts.items())},
        'live_fixture_required': False, 'new_rust_processes': 0, 'new_filesystem_operations': 0}


def main():
    p = argparse.ArgumentParser()
    for name in ('source', 'capture', 'output'): p.add_argument('--'+name, type=Path, required=True)
    a = p.parse_args(); value = reference_evidence(a.source, a.capture)
    with a.output.open('x') as stream: json.dump(value, stream, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False); stream.write('\n')
    print(json.dumps({'status': value['status'], 'cases': value['cases'], 'actual_processes': value['actual_processes'],
        'canonicalization_syscalls': value['trace']['canonicalization_syscalls'], 'artifacts': value['artifacts'],
        'evidence_bytes': a.output.stat().st_size, 'evidence_sha256': pin(a.output)['sha256'], 'new_rust_processes': 0, 'new_native_calls': 0}, sort_keys=True))


if __name__ == '__main__': main()
