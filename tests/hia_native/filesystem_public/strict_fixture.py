"""Read every private-carrier byte without running or restoring any fixture.

The caller admits the native executable and supplies requests regenerated from
the frozen inputs. This module does not prove HIA semantics or original parity;
it binds actual process receipts, streams and the exact two-session framing.
"""
from pathlib import Path
import gzip
import math
import struct

FENCE = ('HEPTA_EFFECT_OWNER_FENCE_DIR', 'HEPTA_EFFECT_OWNER_SELF', 'HEPTA_EFFECT_OWNER_FENCE_REQUIRED')
TRACE = ['-f', '-qq', '-s', '4096', '-xx', '-e', 'trace=%file,close,write,getpgid,getdents64,flock,fcntl,dup,dup2,dup3']


def duration(q, value, maximum, label):
    q.need(type(value) in (float, int) and math.isfinite(value) and 0 < value <= maximum, label)


def offset_span(q, info, raw, at, label):
    q.fields(info, ('offset', 'bytes', 'sha256'), label)
    q.same(info['offset'], at, label + ' contiguous offset')
    length = q.uint(info['bytes'], label + ' length')
    q.need(0 <= at <= len(raw) and length <= len(raw) - at, label + ' within full stream')
    body = raw[at:at + length]
    q.same(info['sha256'], q.sha(body), label + ' entire bytes')
    return body


def request_bytes(q, request):
    q.fields(request, ('session', 'slot', 'payload'), 'input-only private request')
    q.need(type(request['session']) is int and request['session'] in (0, 1), 'actual private session')
    q.need(type(request['slot']) is int and 0 <= request['slot'] < 2**64, 'actual private slot')
    q.need(type(request['payload']) is bytes and len(request['payload']) < 2**64, 'full private request payload')
    return b'HFSFXQ02' + struct.pack('<3Q', request['session'], request['slot'], len(request['payload'])) + request['payload']


def decode_response(q, raw, session, slot):
    if slot == 34:
        q.need(len(raw) >= 96 and raw[:8] == b'HFSJPR02', 'complete private public-result header')
        owner, mode, closed, *tail = struct.unpack_from('<11Q', raw, 8)
        q.need(owner == session and mode in (0, 1, 2, 3) and closed in (0, 1), 'private public-result identity/mode')
        q.same(tail[-2:], [0, 0], 'private public-result reserved words')
        if mode == 3: q.need(closed == 1 and tail[:6] == [0] * 6, 'closed private session performed native work')
        head = {'header_bytes': 96, 'session': session, 'slot': slot, 'mode': mode, 'closed': closed, 'counter_deltas': tail[:6]}
        body = raw[96:]
        if mode in (1, 2): q.need(body.endswith(b'\n') and body.count(b'\n') == 1, 'one complete actual public JSON line')
        else: q.need(body == b'', 'silent private result contains public output')
    else:
        q.need(len(raw) >= 104 and raw[:8] == b'HFSFXR02', 'complete private child-result header')
        owner, child, code, extent, *tail = struct.unpack_from('<12Q', raw, 8)
        q.need(owner == session and child == slot and len(raw) - 104 == extent, 'private child-result complete identity/extent')
        head = {'header_bytes': 104, 'session': session, 'slot': slot, 'native_return': code,
                'body_bytes': extent, 'counter_deltas': tail[:6], 'workspace_capacity': tail[6], 'output_capacity': tail[7]}
        body = raw[104:]
    return head, body


def fixture_evidence(q, capture_root, *, binary, argv, cwd, fence, requests, strace_path, trace=True):
    capture = q.Binder(capture_root); start = capture.json('started.json'); finish = capture.json('process.json')
    q.fields(binary, ('path', 'bytes', 'sha256'), 'already-admitted native binary')
    q.need(type(binary['path']) is str and Path(binary['path']).is_absolute(), 'native executable provenance')
    q.need(type(argv) is list and argv and argv[0] == binary['path'] and all(type(arg) is str for arg in argv), 'full actual private invocation')
    q.need(type(cwd) is str and Path(cwd).is_absolute(), 'actual raw cwd')
    q.need(type(fence) is dict and set(fence) <= set(FENCE) and all(type(v) is str for v in fence.values()), 'declared actual fence environment')
    environment = {'PATH': '', 'LC_ALL': 'C', **fence}
    pin = {name: binary[name] for name in ('bytes', 'sha256')}
    q.fields(start, ('command', 'native_argv', 'cwd', 'environment', 'pid', 'binary', 'observer_fd'), 'complete native start receipt')
    q.same(start['native_argv'], argv, 'actual private argv'); q.same(start['cwd'], cwd, 'actual private cwd')
    q.same(start['environment'], environment, 'complete actual private environment'); q.same(start['binary'], pin, 'actual native start binary')
    q.need(start['observer_fd'] is None, 'undeclared external observer fd')
    q.need(q.uint(start['pid'], 'actual native PID') > 0, 'actual native PID')
    names = ('command', 'native_argv', 'cwd', 'environment', 'pid', 'exit_code', 'timed_out', 'drain_deadline_seconds',
        'drain_elapsed_seconds', 'elapsed_seconds', 'failure_cleanup_requested', 'start_error', 'exchanges', 'streams',
        'wait_deadline_seconds', 'wait_timed_out', 'cleanup_error', 'kill_cleanup_deadline_seconds', 'kill_requested',
        'pipe_eof', 'unconsumed_stdout', 'binary')
    q.fields(finish, (*names, 'trace') if trace else names, 'complete native final receipt')
    for name in ('command', 'native_argv', 'cwd', 'environment', 'pid', 'binary'):
        q.same(finish[name], start[name], 'native start/end ' + name)
    q.need(finish['start_error'] is None and finish['cleanup_error'] is None and finish['timed_out'] is False
        and finish['wait_timed_out'] is False and finish['failure_cleanup_requested'] is False and finish['kill_requested'] is False,
        'actual native start/timeout/cleanup failure')
    q.same(finish['exit_code'], 0, 'actual native exit')
    q.same(finish['pipe_eof'], {'stdout': True, 'stderr': True}, 'complete actual pipe capture')
    for name, expected in (('drain_deadline_seconds', 60), ('wait_deadline_seconds', 5), ('kill_cleanup_deadline_seconds', 5)):
        q.same(finish[name], expected, 'actual ' + name)
    duration(q, finish['elapsed_seconds'], 180, 'actual native lifetime')
    duration(q, finish['drain_elapsed_seconds'], 60, 'actual native drain duration')
    q.same(finish['unconsumed_stdout'], {'bytes': 0, 'sha256': q.sha(b'')}, 'no unclaimed native stdout')
    q.fields(finish['streams'], ('attempted-stdin', 'stdin', 'stdout', 'stderr'), 'complete native stream set')
    raw = {}; original_capture = None
    for name, descriptor in finish['streams'].items():
        q.fields(descriptor, ('path', 'uncompressed', 'compressed'), 'whole stream descriptor')
        path = Path(descriptor['path'])
        q.need(path.is_absolute() and '..' not in path.parts and path.name == name + '.bin.gz', 'stream ownership provenance')
        if original_capture is None: original_capture = path.parent
        q.need(path.parent == original_capture, 'same captured process owner')
        q.fields(descriptor['compressed'], ('bytes', 'sha256'), 'complete compressed pin')
        q.fields(descriptor['uncompressed'], ('bytes', 'sha256'), 'complete uncompressed pin')
        with gzip.open(capture.file(name + '.bin.gz', descriptor['compressed']), 'rb') as stream: raw[name] = stream.read()
        q.same(descriptor['uncompressed'], {'bytes': len(raw[name]), 'sha256': q.sha(raw[name])}, 'full decompressed native ' + name)
    q.need(type(strace_path) is str and Path(strace_path).is_absolute() and '..' not in Path(strace_path).parts, 'selected tracer invocation path')
    command = [strace_path, *TRACE, '-o', str(original_capture / 'native.strace'), '--', *argv] if trace else argv
    q.same(finish['command'], command, 'actual full native trace command')
    if trace:
        q.fields(finish['trace'], ('path', 'bytes', 'sha256'), 'whole actual syscall trace')
        q.same(finish['trace']['path'], str(original_capture / 'native.strace'), 'actual syscall trace ownership')
        capture.file('native.strace', {name: finish['trace'][name] for name in ('bytes', 'sha256')})
    exchanges = capture.json('exchanges.json')
    q.need(type(requests) is list and type(exchanges) is list and len(exchanges) == len(requests), 'all planned native carrier requests')
    q.same(finish['exchanges'], len(exchanges), 'actual carrier exchange count')
    at = {'attempted-stdin': 0, 'stdin': 0, 'stdout': 0, 'stderr': 0}; evidence = []; bodies = []
    for index, (row, request) in enumerate(zip(exchanges, requests, strict=True)):
        expected = request_bytes(q, request)
        q.fields(row, ('index', 'session', 'slot', 'deadline_seconds', 'elapsed_seconds', 'timed_out', 'transport', 'error',
            'attempted_input', 'accepted_input', 'stdout_range', 'stderr_range', 'response', 'body', 'header', 'stdout_eof', 'stderr_eof'),
            'complete actual private exchange')
        q.same(row['index'], index, 'actual private exchange order')
        for name in ('session', 'slot'): q.same(row[name], request[name], 'actual private ' + name)
        q.same(row['deadline_seconds'], 60, 'actual private deadline')
        duration(q, row['elapsed_seconds'], 60, 'actual private elapsed')
        q.need(row['timed_out'] is False and row['error'] is None and row['transport'] == 'private-frame', 'complete actual carrier execution')
        for name in ('stdout_eof', 'stderr_eof'): q.need(type(row[name]) is bool, 'actual EOF observation type')
        attempted = offset_span(q, row['attempted_input'], raw['attempted-stdin'], at['attempted-stdin'], 'attempted native input')
        accepted = offset_span(q, row['accepted_input'], raw['stdin'], at['stdin'], 'accepted native input')
        q.need(attempted == accepted == expected, 'all exact native request bytes actually delivered')
        at['attempted-stdin'] += len(attempted); at['stdin'] += len(accepted)
        start_offset = at['stdout']; incoming = {}
        for name in ('stdout', 'stderr'):
            area = row[name + '_range']; q.fields(area, ('offset', 'bytes'), 'actual exchange ' + name + ' range')
            q.same(area['offset'], at[name], 'contiguous native ' + name)
            size = q.uint(area['bytes'], 'native ' + name + ' size')
            q.need(size <= len(raw[name]) - at[name], 'native range exceeds complete stream')
            incoming[name] = raw[name][at[name]:at[name] + size]; at[name] += size
        complete = offset_span(q, row['response'], raw['stdout'], start_offset, 'entire native frame')
        q.need(complete == incoming['stdout'], 'native frame owns all exchange stdout')
        header, body = decode_response(q, complete, request['session'], request['slot'])
        q.same(row['header'], header, 'actual decoded native header')
        recorded_body = offset_span(q, row['body'], raw['stdout'], start_offset + header['header_bytes'], 'complete native response body')
        q.need(body == recorded_body, 'native body exact extent')
        bodies.append(body)
        evidence.append({'index': index, 'session': request['session'], 'slot': request['slot'], 'header': header,
            'input': row['accepted_input'], 'frame': row['response'], 'body': row['body'],
            'stdout_range': row['stdout_range'], 'stderr_range': row['stderr_range']})
    for name in ('attempted-stdin', 'stdin', 'stdout'): q.same(at[name], len(raw[name]), 'all captured ' + name + ' bytes consumed')
    q.need(sum(row['elapsed_seconds'] for row in exchanges) + finish['drain_elapsed_seconds'] <= finish['elapsed_seconds'], 'actual process covers all exchange durations')
    for name, value in list(capture.artifacts.items()): q.same(q.pin(q.inside(capture.root, name)), value, 'captured file changed while reading')
    proof = {'schema': 'hepta.runtime.filesystem-sdk-private-carrier-evidence.v1', 'status': 'PASS',
        'actual_command': command, 'actual_native_argv': argv, 'actual_cwd': cwd, 'actual_pid': finish['pid'], 'binary': binary,
        'streams': {name: descriptor['uncompressed'] for name, descriptor in finish['streams'].items()},
        'exchanges': evidence, 'stderr_bytes_after_last_exchange': len(raw['stderr']) - at['stderr'],
        'actual_trace_present': trace, 'closed_mode_is_os_broken_pipe': False,
        'source_graph_admitted_by_this_reader': False, 'tool_semantics_admitted': False,
        'live_process_or_fixture_required': False, 'artifacts': len(capture.artifacts),
        'artifact_sha256': {name: value['sha256'] for name, value in sorted(capture.artifacts.items())},
        'artifact_bytes': {name: value['bytes'] for name, value in sorted(capture.artifacts.items())},
        'new_native_calls': 0, 'new_rust_processes': 0}
    return proof, bodies
