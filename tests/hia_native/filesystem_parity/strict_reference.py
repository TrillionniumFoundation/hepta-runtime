"""Read-only admission of the unchanged fd-relative Linux Rust original."""
from pathlib import Path
import argparse
import copy
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

SOURCE_FILES = {
    'Cargo.lock': (597, 'e7acd632c5eeaeb67f4f856bde6e477991f579e4bab51e81a0afd315f501b2cf'),
    'Cargo.toml': (176, '07f7c97663b67b7086f9ded2a89ad1d5febe54849f4a5449f12e6622cb5789ff'),
    'original-runtime.lock': (90148, '7f39704b92d5fc762a98a5313949034db464ca9485827b19b5dde7aa69902d43'),
    'original_parity_ops.rs': (11952, '0e608303d16c22b95dc99bae2e6bb00ba0571872f52d15a7fe8e2f021286ccc1'),
    'src/driver.rs': (4316, 'f093a78aa751f1f7702fe7e06bd11ef6e777dc687c04e00389d0c16122cc0d7c'),
    'verify_sources.py': (2398, '6aa7438a71bd1913b7fa347d1a05b424c05ec33d1601c2306dab5faf0536a776'),
}
CASES_PIN = {'bytes': 12031, 'sha256': 'f2d3efb4e3da4a800206c018908bd5999a6d14b31dc8a7dd81a502413111dedb'}
CAPTURE_PIN = {'bytes': 18199, 'sha256': 'f46faf9747aa13c4ea5b1188c3a19fe1d8d1afb5befab3fc4d129da1506b3950'}
BUILD_PIN = {'bytes': 5257, 'sha256': 'e084459b40ebe481a52ab7a507495d962c8d6d8e6476e5fe45900d6123b4c4f8'}
GROUP_COUNTS = {'validation': 29, 'mkdir': 23, 'file_move': 18, 'directory_move': 16, 'ordering': 30, 'cross_device': 5, 'wide': 2}
TOOL = str(Path.home()/'.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin')+'/'
TRACE_FLAGS = ['-f', '-qq', '-ttt', '-s', '0', '-xx', '-e', 'trace=%file,%desc,getpgid',
    '-e', 'raw=read,write,readv,writev,pread64,pwrite64,preadv,pwritev,sendfile,splice,tee,vmsplice']
STAT_FIELDS = {'dev', 'ino', 'mode', 'nlink', 'uid', 'gid', 'size', 'mtime_ns', 'ctime_ns'}
SHA = re.compile(r'[0-9a-f]{64}\Z')


def need(condition, message):
    if not condition: raise ValueError('filesystem parity reference: '+message)


def uint(value, message, maximum=(1<<64)-1):
    need(type(value) is int and 0 <= value <= maximum, message)
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(',', ':')).encode()+b'\n'


def same(actual, expected, message):
    need(canonical(actual) == canonical(expected), message)


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate JSON member '+key); result[key] = value
        return result
    def constant(value): raise ValueError('filesystem parity reference: non-finite JSON '+value)
    def floating(value):
        parsed = float(value); need(math.isfinite(parsed), 'non-finite JSON number'); return parsed
    try: return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant, parse_float=floating)
    except (UnicodeDecodeError, json.JSONDecodeError) as error: raise ValueError('filesystem parity reference: invalid JSON') from error


def pin(path):
    with Path(path).open('rb') as stream:
        return {'bytes': Path(path).stat().st_size, 'sha256': hashlib.file_digest(stream, 'sha256').hexdigest()}


def inside(root, relative):
    root = Path(root).absolute(); relative = Path(relative)
    need(not relative.is_absolute() and relative.parts and '..' not in relative.parts, 'artifact path escaped its owner')
    for ancestor in [*reversed(root.parents), root]:
        need(ancestor.is_dir() and not ancestor.is_symlink(), 'artifact owner path traverses a symlink')
    current = root; owner = root.stat().st_uid
    for part in relative.parts:
        current /= part; st = current.lstat(); need(not stat.S_ISLNK(st.st_mode), 'artifact path traverses a symlink')
    need(stat.S_ISREG(st.st_mode), 'artifact is not a regular file')
    need(st.st_uid == owner, 'artifact does not belong to its owner')
    return current


class Binder:
    def __init__(self, root): self.root = Path(root).absolute(); self.artifacts = {}
    def file(self, relative, expected=None):
        path = inside(self.root, relative); actual = pin(path)
        if expected is not None:
            need(type(expected) is dict and set(expected) == {'bytes', 'sha256'}, 'invalid artifact pin fields')
            uint(expected['bytes'], 'artifact byte count'); need(type(expected['sha256']) is str and SHA.fullmatch(expected['sha256']), 'artifact SHA256 type')
            same(actual, expected, 'artifact bytes differ: '+str(relative))
        key = str(Path(relative)); previous = self.artifacts.setdefault(key, actual)
        same(previous, actual, 'artifact changed during admission')
        return path
    def data(self, relative, expected=None): return self.file(relative, expected).read_bytes()
    def json(self, relative, expected=None): return strict_json(self.data(relative, expected))


def relocate(recorded, old_root):
    need(type(recorded) is str, 'recorded artifact path type')
    path = Path(recorded); need(path.is_absolute() and '..' not in path.parts, 'recorded artifact path is not absolute')
    try: return path.relative_to(old_root)
    except ValueError as error: raise ValueError('filesystem parity reference: recorded artifact escapes original owner') from error


def process_gate(row, command, cwd):
    need(type(row) is dict, 'process record type')
    same(row.get('command'), command, 'actual process command'); same(row.get('cwd'), cwd, 'actual process working directory')
    need(type(row.get('exit_code')) is int and row['exit_code'] == 0, 'process exit was not zero')
    need(row.get('timed_out') is False and 'start_error' not in row, 'process timed out or did not start')
    need(type(row.get('timeout_seconds')) is int and row['timeout_seconds'] == 180, 'actual deadline is not 180')
    elapsed = row.get('elapsed_seconds')
    need(type(elapsed) in (int, float) and math.isfinite(elapsed) and 0 < elapsed <= 180, 'invalid actual elapsed time')
    need(uint(row.get('pid'), 'actual process PID') > 0, 'missing actual PID')


def load_source(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def build_evidence(binder, build_relative, old_root):
    build_relative = Path(build_relative); result = binder.json(build_relative/'RESULT.json')
    need(result.get('schema') == 'hepta.runtime.filesystem-parity-original-build.v1' and result.get('status') == 'PASS', 'build result schema/status')
    for name, value in {'actual_processes': 3, 'actual_semantic_cases': 0, 'fresh_locked_original_builds': 1,
                        'new_native_calls': 0, 'source_unchanged': True}.items(): same(result.get(name), value, 'build '+name)
    same(result.get('driver'), BUILD_PIN, 'build driver pin'); binder.file('build_original_v2.py', BUILD_PIN)
    table = {name: {'bytes': size, 'sha256': digest} for name, (size, digest) in SOURCE_FILES.items()}
    same(result.get('source_files'), table, 'complete original source table')
    same(binder.json('source/SOURCE-FILES.json', result['source_table']), table, 'source table file')
    same(binder.json(build_relative/'verified-source/SOURCE-FILES.json'), table, 'clean source table')
    for name, expected in table.items():
        binder.file(Path('source')/name, expected); binder.file(build_relative/'verified-source'/name, expected)
    factory = load_source(binder.file(build_relative/'verified-source/verify_sources.py'), '_fs_parity_original_verified')
    source, expected_proof = factory.assemble(binder.root/build_relative/'verified-source')
    proof = binder.json(build_relative/'SOURCE.json', result['source']); same(proof, expected_proof, 'unchanged full original module proof')
    need(proof['local_linux_module_unchanged'] is True and proof['unchanged_module']['start'] == 5405 and proof['unchanged_module']['end'] == 11895, 'original complete module slice')
    need(binder.data(build_relative/'crate/src/main.rs', result['materialized']['src/main.rs']) == source, 'generated original crate differs')
    same(sorted(result['materialized']), ['Cargo.lock', 'Cargo.toml', 'src/main.rs'], 'materialized crate members')
    for name in ('Cargo.toml', 'Cargo.lock'):
        need(binder.data(build_relative/'crate'/name, result['materialized'][name]) == binder.data(Path('source')/name), 'crate source or lock changed')
    processes = binder.json(build_relative/'processes.json', result['processes']); need(type(processes) is list and len(processes) == 3, 'three actual build processes required')
    original_build = Path(old_root)/build_relative; crate = str(original_build/'crate')
    commands = [[TOOL+'rustc', '-Vv'], [TOOL+'cargo', '-Vv'], [TOOL+'cargo', 'build', '--release', '--locked', '--manifest-path', str(original_build/'crate/Cargo.toml')]]
    names = ['rustc-version', 'cargo-version', 'locked-build']; streams = []
    for row, command, name in zip(processes, commands, names):
        process_gate(row, command, crate); same(row.get('name'), name, 'build process order')
        same(row.get('controlled_env'), {'RUSTC': TOOL+'rustc', 'CARGO_BUILD_JOBS': '2', 'CARGO_TARGET_DIR': str(original_build/'target')}, 'explicit fixed compiler environment')
        need(row.get('stdin', 'missing') is None, 'build stdin provenance')
        out = binder.data(build_relative/(name+'.stdout'), row['stdout']); err = binder.data(build_relative/(name+'.stderr'), row['stderr'])
        if name != 'locked-build': need(not err, 'compiler version stderr')
        else: need(not out, 'build unexpectedly produced stdout')
        streams.append(out)
    need(streams[0].startswith(b'rustc 1.95.0 (59807616e 2026-04-14)\n') and b'host: x86_64-unknown-linux-gnu\n' in streams[0], 'actual Rust 1.95 target version')
    need(streams[1].startswith(b'cargo 1.95.0 '), 'actual Cargo 1.95 version')
    info = binder.json(build_relative/'target/.rustc_info.json', result['target_rustc_info'])
    need(type(info.get('outputs')) is dict and any(type(v) is dict and v.get('stdout') == streams[0].decode() for v in info['outputs'].values()), 'target compiler information differs from actual version')
    binary_relative = relocate(result['binary']['path'], old_root)
    same(str(binary_relative), str(build_relative/'target/release/hepta-filesystem-parity-original'), 'actual original binary path')
    binary_pin = {key: result['binary'][key] for key in ('bytes', 'sha256')}
    need(binder.data(binary_relative, binary_pin).startswith(b'\x7fELF\x02\x01'), 'original binary is not actual x86-64 ELF')
    return result, proof, processes


def input_stream(path, cases):
    rows = []; position = 16
    with Path(path).open('rb') as stream:
        need(stream.read(16) == b'HFPRI001'+struct.pack('<Q', len(cases)), 'input header/count')
        for case in cases:
            fixed = struct.pack('<4Q', case['case_id'], case['operation'], len(case['first']), len(case['second']))
            need(stream.read(32) == fixed, 'original input frame header'); digest = hashlib.sha256(fixed)
            for expected in (case['first'], case['second']):
                for offset in range(0, len(expected), 1<<20):
                    block = expected[offset:offset+(1<<20)]; need(stream.read(len(block)) == block, 'complete original raw path input'); digest.update(block)
            size = 32+len(case['first'])+len(case['second'])
            rows.append({'input_offset': position, 'input_bytes': size, 'input_sha256': digest.hexdigest()}); position += size
        need(stream.read(1) == b'', 'trailing original input')
    return rows


def output_stream(raw, cases):
    need(len(raw) >= 64 and raw[:8] == b'HFPRO001', 'original output magic/header')
    values = struct.unpack_from('<7Q', raw, 8)
    header = dict(zip(('cases', 'uid', 'euid', 'gid', 'egid', 'prior_umask', 'active_umask'), values))
    need(header['cases'] == len(cases) and header['uid'] == header['euid'] and header['gid'] == header['egid'] and header['euid'] != 0, 'actual non-root observation header')
    need(header['active_umask'] == 0o22 and header['prior_umask'] <= 0o777, 'actual umask observation')
    position = 64; rows = []
    for case in cases:
        begin = position; need(len(raw)-position >= 80, 'truncated original result header')
        values = struct.unpack_from('<10Q', raw, position); position += 80
        cid, op, status, created, present, err, sl, cl, before_count, after_count = values
        need((cid, op) == (case['case_id'], case['operation']), 'original case identity/order')
        need(status in (0, 1) and present in (0, 1), 'original status or errno tag')
        need(before_count == after_count == 3, 'actual stdio descriptor count')
        need(sl+cl+(before_count+after_count)*40 <= len(raw)-position, 'original result spans overflow/truncation')
        short = raw[position:position+sl]; position += sl; chain = raw[position:position+cl]; position += cl
        try: short_text, chain_text = short.decode('utf-8'), chain.decode('utf-8')
        except UnicodeError as error: raise ValueError('filesystem parity reference: invalid original error UTF8') from error
        fds = [list(struct.unpack_from('<5Q', raw, position+i*40)) for i in range(before_count+after_count)]; position += len(fds)*40
        before, after = fds[:before_count], fds[before_count:]
        need(before == after and [fd[0] for fd in before] == [0, 1, 2], 'original descriptor cleanup differs')
        need(all(fd[1] == 0 and fd[2] > 0 and fd[3] > 0 and stat.S_IFMT(fd[4]) in (stat.S_IFREG, stat.S_IFIFO) for fd in before), 'actual descriptor metadata')
        if status == 0:
            need(not short and not chain and present == 0 and err == 0, 'successful result carries an error')
            need(created in (1, 2) if op == 1 else created == 0, 'original successful return type')
        else:
            need(created == 0 and bool(short) and bool(chain), 'original error invents mkdir bool or lacks text')
            need((0 < err < 4096) if present else err == 0, 'original errno optional value')
        rows.append({'case_id': cid, 'operation': op, 'status': status, 'created_tag': created,
            'errno_present': present, 'errno': err, 'short': short_text, 'chain': chain_text,
            'before_descriptors': before, 'after_descriptors': after,
            'output_offset': begin, 'output_bytes': position-begin, 'output_sha256': hashlib.sha256(raw[begin:position]).hexdigest(),
            'begin_marker': -1700000000+2*cid, 'end_marker': -1700000000+2*cid+1})
    need(position == len(raw), 'trailing original output')
    return header, rows


def split_args(text):
    result = []; begin = 0; level = 0; quoted = False; escaped = False
    for index, char in enumerate(text):
        if quoted:
            if escaped: escaped = False
            elif char == '\\': escaped = True
            elif char == '"': quoted = False
        elif char == '"': quoted = True
        elif char in '([{': level += 1
        elif char in ')]}': level -= 1; need(level >= 0, 'strace argument nesting')
        elif char == ',' and level == 0: result.append(text[begin:index].strip()); begin = index+1
    need(not quoted and level == 0, 'incomplete strace argument')
    result.append(text[begin:].strip()); return result


def quoted_path(value, expected=None):
    match = re.fullmatch(r'"((?:\\x[0-9a-f]{2})*)"(\.\.\.)?', value)
    need(match is not None, 'strace path is not exact byte quoting')
    raw = bytes.fromhex(match[1].replace('\\x', '')); truncated = match[2] is not None
    if expected is not None:
        need(raw == (expected[:4095] if truncated else expected), 'strace path differs from complete input')
        if truncated: need(len(raw) == 4095 and len(expected) > 4095, 'strace PATH_MAX minus NUL display boundary')
    else: need(not truncated, 'unexpected path display truncation')
    return raw, truncated


def absolute_components(path):
    if not path.startswith(b'/'): return None
    parts = [match.group() for match in re.finditer(rb'[^/]+', path) if match.group() != b'.']
    if not parts or any(part == b'..' or b'\0' in part for part in parts): return None
    return parts


def path_equal_components(path):
    absolute = path.startswith(b'/'); parts = [match.group() for match in re.finditer(rb'[^/]+', path) if match.group() != b'.']
    prefix = [b'/'] if absolute else ([b'.'] if path.startswith(b'./') or path == b'.' else [])
    return prefix+parts


def path_fields(raw):
    return {'path_hex': raw.hex() if len(raw) <= 4096 else None,
            'path_bytes': len(raw), 'path_sha256': hashlib.sha256(raw).hexdigest()}


def component_fields(raw, displayed, truncated):
    return {'component_hex': displayed.hex(), 'component_bytes': len(raw),
            'component_sha256': hashlib.sha256(raw).hexdigest(), 'display_truncated': truncated}


def operation_trace(events, case, output):
    first, second, operation = case['first'], case['second'], case['operation']
    a, b = absolute_components(first), absolute_components(second)
    invalid = a is None or (operation != 1 and (b is None or path_equal_components(first) == path_equal_components(second)))
    fs_events = [event for event in events if event['name'] not in ('mmap', 'munmap', 'mremap', 'brk')]
    if invalid:
        need(not fs_events and output['status'] == 1 and output['errno_present'] == 0, 'validation/equality did not precede all filesystem effects')
        return {'calls': [], 'actions': [], 'opens': 0, 'closes': 0, 'maximum_live_descriptors': 0, 'path_display_truncations': 0}
    live = {}; logical = {}; next_logical = 0
    opens = closes = maximum = roots = truncations = 0; calls = []; actions = []
    walks = [a] if operation == 1 else [a[:-1], b[:-1]]
    walk_index = -1; cursor = 0; source_parent = destination_parent = None; final_seen = False
    for event in events:
        name, args, result, error = event['name'], event['args'], event['return'], event['errno']
        if name in ('mmap', 'munmap', 'mremap', 'brk'):
            if name == 'mmap': need(len(args) == 6 and args[4] == '-1' and 'MAP_ANONYMOUS' in args[3], 'file mapping inside original operation')
            continue
        need(name in ('openat', 'mkdirat', 'newfstatat', 'renameat2', 'close'), 'unexpected syscall inside original operation: '+name)
        error_number = getattr(errno, error, None) if error else 0
        need(type(error_number) is int, 'unknown actual OS errno')
        call = {'name': name, 'return': result, 'errno': error_number,
            'normalized_return': -error_number if error else result, 'trace_line': event.get('line')}
        if name == 'openat':
            need(not final_seen and len(args) == 3 and args[2] == 'O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_PATH|O_DIRECTORY', 'unsafe original directory open flags/order')
            if args[0] == 'AT_FDCWD':
                raw, truncated = quoted_path(args[1], b'/'); expected = b'/'
                walk_index += 1; roots += 1; cursor = 0
                need(walk_index < len(walks) and (walk_index == 0 or source_parent is not None), 'source/destination parent order')
                path = b'/'; parent = -100; parent_logical = None; parent_path = None
            else:
                parent = int(args[0]); need(parent in live and walk_index >= 0, 'openat used an unowned descriptor')
                parts = walks[walk_index]; need(cursor < len(parts), 'extra path traversal')
                expected = parts[cursor]; raw, truncated = quoted_path(args[1], expected)
                if truncated:
                    need(result == -1 and error == 'ENAMETOOLONG', 'truncated pathname did not produce actual length refusal'); truncations += 1
                path = live[parent].rstrip(b'/')+b'/'+expected
                parent_logical, parent_path = logical[parent], live[parent].hex()
                if result >= 0: cursor += 1
            call.update(parent_fd=parent, parent_logical_fd=parent_logical, parent_path_hex=parent_path, flags=0x2b0000,
                        **path_fields(path), **component_fields(expected, raw, truncated))
            if result >= 0:
                need(result >= 3 and result not in live and not error, 'openat descriptor ownership collision')
                live[result] = path; logical[result] = next_logical; next_logical += 1
                call['opened_logical_fd'] = logical[result]
                opens += 1; maximum = max(maximum, len(live)); need(maximum <= 3, 'more than three original owned descriptors')
                if cursor == len(walks[walk_index]):
                    if walk_index == 0: source_parent = result
                    else: destination_parent = result
            else:
                need(result == -1 and bool(error), 'invalid failed openat result'); call['opened_logical_fd'] = None
        elif name == 'mkdirat':
            need(operation == 1 and len(args) == 3 and args[2] == '0700' and not final_seen, 'mkdir mode or operation')
            parent = int(args[0]); need(parent in live and cursor < len(a), 'mkdir uses unowned parent')
            raw, truncated = quoted_path(args[1], a[cursor]); need(not truncated, 'unexpected mkdir display truncation')
            path = live[parent].rstrip(b'/')+b'/'+raw; need(result in (0, -1), 'invalid mkdir return')
            need(calls and calls[-1]['name'] == 'openat' and calls[-1]['return'] == -1 and calls[-1]['errno'] == errno.ENOENT and calls[-1]['path_sha256'] == hashlib.sha256(path).hexdigest(), 'mkdir was not preceded by the exact missing component')
            if result == 0: actions.append({'kind': 'mkdir', 'path': path})
            call.update(parent_fd=parent, parent_logical_fd=logical[parent], parent_path_hex=live[parent].hex(), mode=0o700,
                        **path_fields(path), **component_fields(a[cursor], raw, truncated))
        elif name == 'newfstatat':
            need(operation in (2, 3) and roots == 2 and len(args) == 4 and args[3] == 'AT_SYMLINK_NOFOLLOW' and not final_seen, 'source fstat order/flags')
            parent = int(args[0]); need(parent == source_parent and parent in live and destination_parent in live, 'source fstat parent lifetime')
            leaf, truncated = quoted_path(args[1], a[-1]); need(not truncated, 'fstat path truncation')
            path = live[parent].rstrip(b'/')+b'/'+leaf
            call.update(parent_fd=parent, parent_logical_fd=logical[parent], parent_path_hex=live[parent].hex(), flags=0x100,
                        stat_display=args[2], **path_fields(path), **component_fields(a[-1], leaf, truncated))
            observed_type = re.search(r'st_mode=(S_IF[A-Z]+)', args[2])
            call['source_type'] = observed_type[1] if observed_type else None
            need((result == 0 and observed_type is not None) or (result == -1 and observed_type is None and bool(error)), 'actual source stat result/type')
        elif name == 'renameat2':
            need(operation in (2, 3) and len(args) == 5 and args[4] == 'RENAME_NOREPLACE' and not final_seen, 'rename no-replace/one-shot contract')
            src, dst = int(args[0]), int(args[2]); need(src == source_parent and dst == destination_parent and src in live and dst in live, 'rename parent ownership')
            aa, ta = quoted_path(args[1], a[-1]); bb, tb = quoted_path(args[3], b[-1]); need(not ta and not tb, 'unexpected rename display truncation')
            source = live[src].rstrip(b'/')+b'/'+aa; destination = live[dst].rstrip(b'/')+b'/'+bb
            need(calls and calls[-1]['name'] == 'newfstatat' and calls[-1]['return'] == 0, 'rename did not follow successful no-follow source stat')
            need(calls[-1]['source_type'] == ('S_IFREG' if operation == 2 else 'S_IFDIR'), 'rename followed a disallowed source file type')
            if result == 0: actions.append({'kind': 'move', 'source': source, 'destination': destination})
            call.update(source_fd=src, destination_fd=dst, source_logical_fd=logical[src], destination_logical_fd=logical[dst],
                source_parent_hex=live[src].hex(), destination_parent_hex=live[dst].hex(), source_name_hex=aa.hex(), destination_name_hex=bb.hex(),
                source_hex=source.hex(), destination_hex=destination.hex(), flags=1); final_seen = True
        else:
            need(len(args) == 1, 'close argument count'); fd = int(args[0]); need(fd in live and result == 0 and not error, 'original close does not retire an owned live descriptor')
            call.update(fd=fd, logical_fd=logical[fd], path_hex=live[fd].hex()); del live[fd]; del logical[fd]; closes += 1
        calls.append(call)
    need(not live and opens == closes, 'original operation leaked an owned descriptor')
    need(roots == (1 if operation == 1 else 2) or output['status'] == 1, 'incomplete successful parent walk')
    effects = [call for call in calls if call['name'] != 'close']
    if effects and effects[-1]['return'] == -1:
        need(output['status'] == 1 and output['errno_present'] == 1, 'actual OS failure lost its original downcast errno')
    if output['errno_present']:
        need(effects and effects[-1]['return'] == -1 and output['errno'] == effects[-1]['errno'], 'downcast errno differs from last actual effect')
    if output['status'] == 0 and operation == 1: need(output['created_tag'] == (2 if actions else 1), 'mkdir bool differs from actual successful mkdirat calls')
    if output['status'] == 0 and operation != 1: need(len(actions) == 1 and actions[0]['kind'] == 'move', 'unit success lacks actual atomic rename')
    return {'calls': calls, 'actions': actions, 'opens': opens, 'closes': closes, 'maximum_live_descriptors': maximum, 'path_display_truncations': truncations}


def trace_stream(raw, cases, outputs, input_bytes, output_bytes, expected_binary=None):
    try: text = raw.decode('ascii')
    except UnicodeError as error: raise ValueError('filesystem parity reference: non-ASCII strace stream') from error
    lines = text.splitlines(); need(text.endswith('\n') and lines, 'incomplete strace file')
    current = None; markers = []; result = {}; operation_events = []; traced_pid = None; read_bytes = write_bytes = executions = 0
    case_map = {case['case_id']: case for case in cases}; output_map = {row['case_id']: row for row in outputs}
    for line_number, line in enumerate(lines, 1):
        match = re.fullmatch(r'(\d+)[ ]+(\d+\.\d+) ([A-Za-z_][A-Za-z0-9_]*)\((.*)\)\s*=\s*(.*)', line)
        need(match is not None, 'incomplete or unsupported actual strace record')
        pid, stamp, name, arguments, tail = match.groups(); pid = int(pid)
        if traced_pid is None: traced_pid = pid; need(name == 'execve', 'trace does not begin with original execution')
        need(pid == traced_pid and math.isfinite(float(stamp)), 'unexpected traced process or timestamp')
        returned = re.match(r'(-?(?:0x[0-9a-f]+|[0-9]+))(?: ([A-Z][A-Z0-9_]+))?', tail)
        need(returned is not None, 'incomplete actual syscall return')
        value = int(returned[1], 16 if '0x' in returned[1] else 10); error = returned[2]; args = split_args(arguments)
        if name == 'execve':
            executions += 1; need(executions == 1 and current is None and value == 0 and len(args) == 3, 'original process execution identity')
            if expected_binary is not None: quoted_path(args[0], expected_binary.encode())
        if name == 'getpgid':
            need(len(args) == 1 and value == -1 and error == 'ESRCH', 'invalid original marker result')
            marker = int(args[0]); delta = marker+1700000000; cid, is_end = divmod(delta, 2)
            need(cid in case_map, 'marker for an unrequested case'); markers.append(marker)
            if not is_end:
                need(current is None and cid not in result, 'nested or repeated original begin marker'); current = cid; operation_events = []
            else:
                need(current == cid, 'original end marker without matching begin')
                result[cid] = operation_trace(operation_events, case_map[cid], output_map[cid]); current = None
        elif current is not None: operation_events.append({'name': name, 'args': args, 'return': value, 'errno': error, 'line': line_number})
        elif name in ('read', 'write') and len(args) == 3 and value > 0:
            descriptor = int(args[0], 0)
            if name == 'read' and descriptor == 0: read_bytes += value
            if name == 'write' and descriptor == 1: write_bytes += value
            need(not (name == 'write' and descriptor == 2), 'original wrote stderr')
    need(current is None, 'unterminated original marker interval')
    same(markers, [marker for case in cases for marker in (-1700000000+2*case['case_id'], -1700000000+2*case['case_id']+1)], 'complete ordered marker pairs')
    need(read_bytes == input_bytes and write_bytes == output_bytes, 'actual input/output syscall byte totals')
    return {'pid': traced_pid, 'raw_lines': len(lines), 'marker_pairs': len(cases), 'operations': result}


def state_evidence(binder, capture_relative, descriptor, roots):
    need(type(descriptor) is dict and set(descriptor) == {'path', 'bytes', 'sha256'}, 'state descriptor fields')
    value = binder.json(Path(capture_relative)/descriptor['path'], {key: descriptor[key] for key in ('bytes', 'sha256')})
    same(value.get('schema'), 'hepta.runtime.filesystem-parity-state.v1', 'state schema')
    same(value.get('roots_hex'), [root.hex() for root in roots], 'state roots')
    need(type(value.get('entries')) is list, 'state entries type'); nodes = {}
    for row in value['entries']:
        need(type(row) is dict and type(row.get('path_hex')) is str, 'state entry/path type')
        try: path = bytes.fromhex(row['path_hex'])
        except ValueError as error: raise ValueError('filesystem parity reference: invalid path bytes') from error
        need(path.hex() == row['path_hex'] and path not in nodes and any(path == root or path.startswith(root+b'/') for root in roots), 'state path duplicate or outside fixture')
        need(set(row.get('stat', {})) == STAT_FIELDS, 'state complete stat fields'); st = row['stat']
        for field in STAT_FIELDS: uint(st[field], 'state stat '+field)
        need(st['ino'] > 0 and st['dev'] > 0 and st['nlink'] > 0, 'state identity fields')
        kind = row.get('kind'); expected_kind = {stat.S_IFREG: 'file', stat.S_IFDIR: 'directory', stat.S_IFLNK: 'symlink', stat.S_IFIFO: 'fifo'}.get(stat.S_IFMT(st['mode']))
        need(expected_kind is not None, 'unexpected special inode in the fixed fixture domain')
        same(kind, expected_kind, 'state type/mode mismatch'); allowed = {'path_hex', 'stat', 'kind'}
        if kind == 'file':
            allowed.add('content'); content = row.get('content')
            need(type(content) is dict and set(content) == {'path', 'bytes', 'sha256'}, 'full file content descriptor')
            need(content['path'] == 'objects/'+content['sha256']+'.bin' and content['bytes'] == st['size'], 'state full file content size/name')
            binder.file(Path(capture_relative)/content['path'], {key: content[key] for key in ('bytes', 'sha256')})
        elif kind == 'symlink':
            allowed.add('target_hex'); need(type(row.get('target_hex')) is str, 'full raw symlink target')
            target = bytes.fromhex(row['target_hex']); need(target.hex() == row['target_hex'] and len(target) == st['size'], 'symlink target length/encoding')
        elif kind == 'directory':
            if 'list_error' in row:
                allowed.add('list_error'); need(set(row['list_error']) == {'errno', 'text'}, 'directory observer error fields')
                need(type(row['list_error']['errno']) is int and row['list_error']['errno'] == errno.EACCES and type(row['list_error']['text']) is str, 'directory observer actual permission error')
            else:
                allowed.add('children_hex'); names = row.get('children_hex'); need(type(names) is list, 'directory complete entries')
                decoded = [bytes.fromhex(name) for name in names]
                need(decoded == sorted(set(decoded)) and all(name and b'/' not in name and b'\0' not in name for name in decoded), 'directory child names invalid')
        same(sorted(row), sorted(allowed), 'state entry exact fields'); nodes[path] = row
    expected = set(roots)
    for path, node in nodes.items():
        if node['kind'] == 'directory' and 'children_hex' in node: expected.update(path+b'/'+bytes.fromhex(name) for name in node['children_hex'])
    same(sorted(path.hex() for path in nodes), sorted(path.hex() for path in expected), 'state full tree closure')
    return value, nodes


def semantic_node(node):
    value = {'kind': node['kind'], 'stat': {key: node['stat'][key] for key in ('dev', 'ino', 'mode', 'uid', 'gid')}}
    if node['kind'] == 'file': value.update(content=node['content'], size=node['stat']['size'], nlink=node['stat']['nlink'])
    if node['kind'] == 'symlink': value.update(target_hex=node['target_hex'], size=node['stat']['size'])
    return value


def compare_state_model(nodes, model):
    for path, node in nodes.items():
        need(path in model, 'state contains an unobserved filesystem mutation')
        same(semantic_node(node), semantic_node(model[path]), 'state inode/type/content/mode changed without an actual effect')
        if node['kind'] == 'directory':
            children = sorted(child[len(path)+1:] for child in model if child.startswith(path+b'/') and b'/' not in child[len(path)+1:])
            if 'children_hex' in node: same(node['children_hex'], [child.hex() for child in children], 'state directory enumeration differs from actual mutations')
            else: need((node['stat']['mode'] & 0o500) != 0o500, 'observer hid a readable owned directory')
    hidden = {path for path, node in nodes.items() if node['kind'] == 'directory' and 'list_error' in node}
    need(all(path in nodes or any(path.startswith(parent+b'/') for parent in hidden) for path in model), 'state omitted visible filesystem nodes')


def apply_actions(model, actions, after, final, header):
    for action in actions:
        if action['kind'] == 'mkdir':
            path = action['path']; need(path not in model, 'successful mkdir replaced an existing node')
            observed = after.get(path, final.get(path)); need(observed is not None and observed['kind'] == 'directory', 'successful mkdir lacks full observed node')
            need(stat.S_IMODE(observed['stat']['mode']) == 0o700 and observed['stat']['uid'] == header['euid'] and observed['stat']['gid'] == header['egid'], 'mkdir mode/ownership was not 0700')
            parent = path.rsplit(b'/', 1)[0]; need(parent in model and observed['stat']['dev'] == model[parent]['stat']['dev'], 'mkdir device or parent')
            need(all((observed['stat']['dev'], observed['stat']['ino']) != (node['stat']['dev'], node['stat']['ino']) for node in model.values()), 'mkdir reused a still-live inode')
            model[path] = copy.deepcopy(observed)
        else:
            source, destination = action['source'], action['destination']
            need(source in model and destination not in model, 'actual atomic move replaced an existing node or lacks source')
            moved = {path: node for path, node in model.items() if path == source or path.startswith(source+b'/')}
            for path in moved: del model[path]
            for path, node in moved.items():
                target = destination+path[len(source):]; item = copy.deepcopy(node); item['path_hex'] = target.hex(); model[target] = item


def admit_states(binder, capture_relative, groups, rows, traces, headers):
    snapshot_count = 0
    for name, group in groups.items():
        folder = capture_relative/name
        def named_state(filename):
            relative = Path(name)/filename; expected = pin(binder.file(capture_relative/relative))
            return state_evidence(binder, capture_relative, {'path': str(relative), **expected}, group['roots'])
        prepared, initial = named_state('prepared-state.json'); armed, armed_nodes = named_state('armed-state.json'); restored, final = named_state('restored-state.json'); snapshot_count += 3
        model = copy.deepcopy(initial)
        expected_paths = set(group['roots'])
        for item in group['setup']:
            path = item['path']
            need(any(path == root or path.startswith(root+b'/') for root in group['roots']), 'setup path outside the fixture')
            while path not in group['roots']:
                expected_paths.add(path); path = path.rsplit(b'/', 1)[0]
        same(sorted(path.hex() for path in initial), sorted(path.hex() for path in expected_paths), 'prepared tree differs from complete input-only setup')
        for item in group['setup']:
            if item['kind'] == 'chmod': model[item['path']]['stat']['mode'] = (model[item['path']]['stat']['mode'] & ~0o7777)|item['mode']
            elif item['kind'] == 'write':
                node = initial[item['path']]; need(node['kind'] == 'file' and node['content']['sha256'] == hashlib.sha256(item['data']).hexdigest() and node['content']['bytes'] == len(item['data']), 'prepared original fixture full bytes')
            elif item['kind'] == 'symlink': need(initial[item['path']]['target_hex'] == item['target'].hex(), 'prepared original symlink target')
            elif item['kind'] == 'hardlink':
                a, b = initial[item['path']]['stat'], initial[item['target']]['stat']; need((a['dev'], a['ino']) == (b['dev'], b['ino']), 'actual prepared hardlink inode')
            elif item['kind'] == 'fifo': need(initial[item['path']]['kind'] == 'fifo', 'actual prepared FIFO')
            elif item['kind'] == 'mkdir': need(initial[item['path']]['kind'] == 'directory', 'actual prepared directory')
        compare_state_model(armed_nodes, model); previous = armed
        for case in group['cases']:
            row = rows[case['case_id']]
            before, before_nodes = state_evidence(binder, capture_relative, row['before_state'], group['roots'])
            after, after_nodes = state_evidence(binder, capture_relative, row['after_state'], group['roots']); snapshot_count += 2
            same(before, previous, 'state changed between actual sequential requests'); compare_state_model(before_nodes, model)
            actions = traces[case['case_id']]['actions']; apply_actions(model, actions, after_nodes, final, headers[case['case_id']]); compare_state_model(after_nodes, model)
            if not actions: same(after, before, 'failed/read-only original operation modified filesystem state')
            previous = after
        restoration = binder.json(folder/'observer-restorations.json'); expected_restore = []
        for item in group['restore_modes']:
            node = model[item['path']]; before_mode = stat.S_IMODE(node['stat']['mode']); node['stat']['mode'] = (node['stat']['mode'] & ~0o7777)|item['mode']
            expected_restore.append({'path_hex': item['path'].hex(), 'before_mode': before_mode, 'after_mode': item['mode']})
        same(restoration, expected_restore, 'observer permission restoration provenance'); compare_state_model(final, model)
        if name == 'cross_device':
            devices = binder.json(folder/'devices.json'); same(devices.get('roots_hex'), [root.hex() for root in group['roots']], 'cross-device roots')
            actual_devices = [initial[root]['stat']['dev'] for root in group['roots']]
            same(devices.get('devices'), actual_devices, 'cross-device actual stat devices'); need(actual_devices[0] != actual_devices[1], 'EXDEV domain is not on distinct filesystems')
            for case in group['cases'][:4]:
                row = rows[case['case_id']]; need(row['status'] == 1 and row['errno_present'] == 1 and row['errno'] == errno.EXDEV and not traces[case['case_id']]['actions'], 'actual no-fallback EXDEV refusal')
    return snapshot_count


def reference_evidence(reference_root, capture_root):
    reference_root, capture_root = Path(reference_root).absolute(), Path(capture_root).absolute()
    try: capture_relative = capture_root.relative_to(reference_root)
    except ValueError as error: raise ValueError('filesystem parity reference: capture is outside its owner') from error
    binder = Binder(reference_root); summary = binder.json(capture_relative/'ORIGINAL.json')
    need(summary.get('schema') == 'hepta.runtime.filesystem-parity-original-capture.v1' and summary.get('status') == 'PASS', 'capture schema/status')
    source = binder.json(capture_relative/'SOURCE.json', summary['source'])
    need(set(source) == {'schema', 'build_root', 'build_result', 'binary', 'cases_path', 'cases', 'driver_path', 'driver', 'strace', 'fixture_home', 'cross_root', 'scope'}, 'capture source exact fields')
    same(source['schema'], 'hepta.runtime.filesystem-parity-capture-source.v1', 'capture source schema')
    same(source['scope'], 'unchanged Linux local_linux module; no public SDK, async wrapper, policy, cache or session execution', 'original execution scope')
    original_capture = Path(source['fixture_home']); original_root = Path(source['build_root']).parent
    need(original_root.is_absolute() and '..' not in original_root.parts and original_capture.is_absolute() and '..' not in original_capture.parts, 'original provenance owner path')
    same(str(original_capture.relative_to(original_root)), str(capture_relative), 'capture provenance path')
    build_relative = relocate(source['build_root'], original_root)
    build, proof, build_processes = build_evidence(binder, build_relative, original_root)
    same(source['build_result'], pin(binder.file(build_relative/'RESULT.json')), 'capture actual build binding')
    same(source['binary'], build['binary'], 'capture actual binary binding')
    cases_relative = relocate(source['cases_path'], original_root); driver_relative = relocate(source['driver_path'], original_root)
    same(source['cases'], CASES_PIN, 'input-only generator identity'); same(source['driver'], CAPTURE_PIN, 'real-I/O capture harness identity')
    cases_path = binder.file(cases_relative, CASES_PIN); binder.file(driver_relative, CAPTURE_PIN)
    need(source['strace']['path'] == '/usr/bin/strace' and uint(source['strace']['bytes'], 'strace executable size') > 0 and SHA.fullmatch(source['strace']['sha256']), 'actual strace identity')
    generator = load_source(cases_path, '_fs_parity_input_cases')
    groups = generator.groups(original_capture, Path(source['cross_root']))
    same({name: len(group['cases']) for name, group in groups.items()}, GROUP_COUNTS, 'full unique corpus domains')
    inputs = binder.json(capture_relative/'INPUTS.json', summary['inputs'])
    expected_inputs = {'groups': {name: [generator.summary(case) for case in group['cases']] for name, group in groups.items()},
        'fixture_definitions': generator.fixture_json({name: {key: value for key, value in group.items() if key != 'cases'} for name, group in groups.items()})}
    same(inputs, expected_inputs, 'input and fixture generator complete equality')
    row_bytes = binder.data(capture_relative/'cases.jsonl', summary['cases_stream']); need(row_bytes.endswith(b'\n'), 'incomplete original case rows')
    rows = [strict_json(line) for line in row_bytes.split(b'\n')[:-1]]
    same([row.get('case_id') for row in rows], list(range(123)), 'complete ordered original case rows')
    processes = binder.json(capture_relative/'processes.json', summary['processes']); need(type(processes) is list and len(processes) == 8, 'eight actual original replay processes')
    actual_cases = {}; traces = {}; headers = {}; process_names = []; total_lines = 0
    for name, group in groups.items():
        subsets = [[case] for case in group['cases']] if group.get('regular_file_stdin') else [group['cases']]
        for index, cases in enumerate(subsets):
            process_name = name+('-'+str(index) if len(subsets) > 1 else ''); process_names.append(process_name)
            row = processes[len(process_names)-1]; folder = capture_relative/'processes'/process_name
            same(binder.json(folder/'process.json'), row, 'individual actual process receipt')
            command = ['/usr/bin/strace', *TRACE_FLAGS, '-o', str(original_capture/'processes'/process_name/'trace.txt'), build['binary']['path']]
            process_gate(row, command, str(original_capture)); same(row.get('name'), process_name, 'replay process order')
            need(row.get('failure', 'missing') is None, 'actual replay failure')
            same(row.get('input_kind'), 'regular-file' if group.get('regular_file_stdin') else 'pipe', 'actual input carrier')
            same(row.get('cases'), [case['case_id'] for case in cases], 'replay case IDs')
            paths = {}
            for key, filename in (('stdin', 'input.bin'), ('stdout', 'stdout.bin'), ('stderr', 'stderr.bin'), ('trace', 'trace.txt')):
                descriptor = row[key]; same(descriptor.get('path'), str(Path('processes')/process_name/filename), 'process stream path')
                need(set(descriptor) == {'path', 'bytes', 'sha256'}, 'process stream descriptor fields')
                paths[key] = binder.file(folder/filename, {field: descriptor[field] for field in ('bytes', 'sha256')})
                compressed = binder.file(folder/(filename+'.gz'))
                with gzip.open(compressed, 'rb') as stream:
                    digest = hashlib.sha256(); count = 0
                    while block := stream.read(1<<20): digest.update(block); count += len(block)
                same({'bytes': count, 'sha256': digest.hexdigest()}, {field: descriptor[field] for field in ('bytes', 'sha256')}, 'complete compressed stream differs')
            need(row['stderr']['bytes'] == 0, 'original replay stderr was nonempty')
            in_rows = input_stream(paths['stdin'], cases); header, out_rows = output_stream(paths['stdout'].read_bytes(), cases)
            same(row.get('header'), header, 'actual original result header')
            expected_input_type = stat.S_IFREG if group.get('regular_file_stdin') else stat.S_IFIFO
            for original_row in out_rows:
                need([stat.S_IFMT(fd[4]) for fd in original_row['before_descriptors']] == [expected_input_type, stat.S_IFIFO, stat.S_IFREG], 'actual FD types differ from process carriers')
            trace = trace_stream(paths['trace'].read_bytes(), cases, out_rows, row['stdin']['bytes'], row['stdout']['bytes'], build['binary']['path']); total_lines += trace['raw_lines']
            for case, original_input, original_output in zip(cases, in_rows, out_rows):
                cid = case['case_id']; actual_cases[cid] = {**generator.summary(case), **original_input, **original_output, 'group': name, 'process': process_name}
                traces[cid] = trace['operations'][cid]; headers[cid] = header
    for row in rows:
        cid = row['case_id']; same({key: value for key, value in row.items() if key not in ('before_state', 'after_state')}, actual_cases[cid], 'full original record is not raw-stream derived')
    snapshot_count = admit_states(binder, capture_relative, groups, rows, traces, headers)
    expected_summary = {'schema': 'hepta.runtime.filesystem-parity-original-capture.v1', 'status': 'PASS',
        'source': summary['source'], 'inputs': summary['inputs'], 'processes': summary['processes'], 'cases_stream': summary['cases_stream'],
        'cases': 123, 'replay_processes': 8, 'fresh_builds_in_capture': 0, 'new_native_calls': 0, 'wide_cases': 2,
        'body_bytes': sum(len(row['short'].encode())+len(row['chain'].encode()) for row in rows), 'case_counts': GROUP_COUNTS,
        'complete_original_outputs': True, 'strict_reference_admission_complete': False}
    same(summary, expected_summary, 'capture summary recomputation')
    return {'schema': 'hepta.runtime.filesystem-parity-original-evidence.v1', 'status': 'PASS',
        'cases': 123, 'case_counts': GROUP_COUNTS, 'body_bytes': expected_summary['body_bytes'],
        'actual_build_processes': 3, 'actual_replay_processes': 8, 'actual_original_processes': 11,
        'fresh_locked_builds': 1, 'fixed_rust_version': '1.95.0', 'registry_dependencies': proof['registry_dependencies'],
        'original_module': proof['unchanged_module'], 'actual_marker_pairs': 123, 'raw_trace_lines': total_lines,
        'actual_semantic_syscalls': sum(len(trace['calls']) for trace in traces.values()),
        'actual_owned_opens': sum(trace['opens'] for trace in traces.values()), 'actual_owned_closes': sum(trace['closes'] for trace in traces.values()),
        'maximum_live_descriptors': max(trace['maximum_live_descriptors'] for trace in traces.values()),
        'path_display_truncations': sum(trace['path_display_truncations'] for trace in traces.values()),
        'path_display_note': 'All syscall records retained; strace caps displayed path strings at PATH_MAX even with -s 0. The one overlong component is bound to its complete input span and exact displayed prefix.',
        'complete_input_bytes': sum(row['stdin']['bytes'] for row in processes), 'complete_output_bytes': sum(row['stdout']['bytes'] for row in processes),
        'state_snapshots': snapshot_count, 'actual_exdev_cases': 4, 'wide_cases': 2,
        'public_sdk_qualified': False, 'async_wrapper_qualified': False, 'cache_session_qualified': False, 'native_qualified': False,
        'new_rust_processes': 0, 'new_native_calls': 0, 'live_fixture_dependencies': [],
        'normalized_syscalls': [{'case_id': cid, 'operation': rows[cid]['operation'], 'group': rows[cid]['group'], 'process': rows[cid]['process'],
            'begin_marker': rows[cid]['begin_marker'], 'end_marker': rows[cid]['end_marker'],
            'calls': traces[cid]['calls']} for cid in range(123)],
        'artifact_sha256': {name: value['sha256'] for name, value in sorted(binder.artifacts.items())},
        'artifact_bytes': {name: value['bytes'] for name, value in sorted(binder.artifacts.items())}}


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--capture', type=Path, required=True); parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(); result = reference_evidence(args.reference, args.capture)
    with args.output.open('x') as stream: json.dump(result, stream, sort_keys=True, indent=2, allow_nan=False); stream.write('\n')
    print(json.dumps({key: value for key, value in result.items() if key not in ('artifact_sha256', 'artifact_bytes', 'normalized_syscalls')}, sort_keys=True))


if __name__ == '__main__': main()
