"""Admit full actual process streams, independently of tool semantics.

The caller separately admits the ELF source graph and observer protocol. This
reader checks every attempted/delivered byte and every reply without launching
processes or reading their former live paths.
"""
from pathlib import Path
import gzip
import math

FENCE_KEYS = ('HEPTA_EFFECT_OWNER_FENCE_DIR', 'HEPTA_EFFECT_OWNER_SELF', 'HEPTA_EFFECT_OWNER_FENCE_REQUIRED')
TRACE_ARGS = ['-f', '-qq', '-s', '4096', '-xx', '-e', 'trace=%file,close,write,getpgid,getdents64,flock,fcntl,dup,dup2,dup3']


def bounded_time(q, value, limit, label):
    q.need(type(value) in (int, float) and math.isfinite(value) and 0 < value <= limit, label)


def span(q, descriptor, raw, offset, label):
    q.fields(descriptor, ('offset', 'bytes', 'sha256'), label+' span')
    q.same(descriptor['offset'], offset, label+' contiguous offset')
    length = q.uint(descriptor['bytes'], label+' complete length')
    q.need(length <= len(raw)-offset, label+' span extends beyond complete stream')
    body = raw[offset:offset+length]
    q.same(descriptor['sha256'], q.sha(body), label+' full span SHA256')
    return body


def stdio_evidence(q, capture_root, *, binary, argv, cwd, fence, requests, strace_path, observer_fd=None, trace=True):
    """Return JSON evidence and complete raw responses for exact comparison.

    ``binary`` is an already-admitted {path,bytes,sha256} descriptor. Requests are
    an input-only sequence of {wire: bytes, response_count: 0|1}. Expected tool
    responses are neither inputs nor computations of this function.
    """
    capture = q.Binder(capture_root); started = capture.json('started.json'); receipt = capture.json('process.json')
    q.fields(binary, ('path', 'bytes', 'sha256'), 'actual admitted binary descriptor')
    q.need(type(binary['path']) is str and Path(binary['path']).is_absolute(), 'actual binary provenance path')
    q.need(type(argv) is list and argv and argv[0] == binary['path'] and all(type(arg) is str for arg in argv), 'complete actual native argv')
    q.need(type(cwd) is str and Path(cwd).is_absolute(), 'actual process cwd')
    q.need(type(fence) is dict and set(fence) <= set(FENCE_KEYS) and all(type(v) is str for v in fence.values()), 'actual declared fence environment')
    environment = {'PATH': '', 'LC_ALL': 'C', **fence}; binary_pin = {name: binary[name] for name in ('bytes', 'sha256')}
    q.fields(started, ('command', 'native_argv', 'cwd', 'environment', 'pid', 'binary', 'observer_fd'), 'actual process start receipt')
    q.same(started['native_argv'], argv, 'actual native invocation'); q.same(started['cwd'], cwd, 'actual process cwd')
    q.same(started['environment'], environment, 'actual complete process environment'); q.same(started['binary'], binary_pin, 'actual start binary bytes')
    q.same(started['observer_fd'], observer_fd, 'actual observer descriptor declaration')
    q.need(observer_fd is None or type(observer_fd) is int and observer_fd >= 3, 'observer descriptor type')
    q.need(q.uint(started['pid'], 'actual process PID') > 0, 'actual process PID')
    fields = {'command', 'native_argv', 'cwd', 'environment', 'pid', 'exit_code', 'timed_out', 'drain_deadline_seconds',
        'drain_elapsed_seconds', 'elapsed_seconds', 'failure_cleanup_requested', 'start_error', 'exchanges', 'streams', 'wait_deadline_seconds',
        'wait_timed_out', 'cleanup_error', 'kill_cleanup_deadline_seconds', 'kill_requested', 'pipe_eof', 'unconsumed_stdout', 'binary'}
    if trace: fields.add('trace')
    q.fields(receipt, fields, 'complete actual process final receipt')
    for name in ('command', 'native_argv', 'cwd', 'environment', 'pid', 'binary'): q.same(receipt[name], started[name], 'actual start/end '+name)
    q.need(receipt['start_error'] is None and receipt['cleanup_error'] is None and receipt['timed_out'] is False and receipt['wait_timed_out'] is False,
        'actual public process startup/timeout/cleanup failure')
    q.need(receipt['failure_cleanup_requested'] is False and receipt['kill_requested'] is False, 'failed public process cannot qualify')
    q.same(receipt['exit_code'], 0, 'actual public process exit')
    q.same(receipt['pipe_eof'], {'stdout': True, 'stderr': True}, 'complete pipe EOF capture')
    q.same(receipt['drain_deadline_seconds'], 60, 'actual process drain deadline')
    q.same(receipt['wait_deadline_seconds'], 5, 'actual process wait deadline')
    q.same(receipt['kill_cleanup_deadline_seconds'], 5, 'actual failure cleanup deadline')
    bounded_time(q, receipt['drain_elapsed_seconds'], 60, 'actual process drain duration')
    bounded_time(q, receipt['elapsed_seconds'], 180, 'actual process lifetime inside native gate')
    q.same(receipt['unconsumed_stdout'], {'bytes': 0, 'sha256': q.sha(b'')}, 'no unclaimed process stdout')
    q.fields(receipt['streams'], ('attempted-stdin', 'stdin', 'stdout', 'stderr'), 'all complete actual byte streams')
    raw = {}; old_capture = None
    for name, descriptor in receipt['streams'].items():
        q.fields(descriptor, ('path', 'uncompressed', 'compressed'), 'complete stream descriptor')
        old_path = Path(descriptor['path'])
        q.need(old_path.is_absolute() and '..' not in old_path.parts and old_path.name == name+'.bin.gz', 'recorded stream ownership')
        if old_capture is None: old_capture = old_path.parent
        q.need(old_path.parent == old_capture, 'all process streams have the same recorded owner')
        q.fields(descriptor['uncompressed'], ('bytes', 'sha256'), 'complete decompressed stream pin')
        q.fields(descriptor['compressed'], ('bytes', 'sha256'), 'complete compressed stream pin')
        packed = capture.file(name+'.bin.gz', descriptor['compressed'])
        with gzip.open(packed, 'rb') as stream: raw[name] = stream.read()
        q.same(descriptor['uncompressed'], {'bytes': len(raw[name]), 'sha256': q.sha(raw[name])}, 'complete decompressed actual '+name)
    q.need(type(strace_path) is str and Path(strace_path).is_absolute() and '..' not in Path(strace_path).parts, 'selected tracer invocation path')
    command = [strace_path, *TRACE_ARGS, '-o', str(old_capture/'native.strace'), '--', *argv] if trace else argv
    q.same(receipt['command'], command, 'complete actual tracing/native command')
    if trace:
        q.same(receipt['trace'].get('path'), str(old_capture/'native.strace'), 'actual trace owner')
        q.fields(receipt['trace'], ('path', 'bytes', 'sha256'), 'complete actual trace descriptor')
        capture.file('native.strace', {key: receipt['trace'][key] for key in ('bytes', 'sha256')})
    exchanges = capture.json('exchanges.json')
    q.need(type(exchanges) is list and len(exchanges) == len(requests), 'all actual planned input exchanges')
    q.same(receipt['exchanges'], len(exchanges), 'actual complete exchange count')
    positions = {'attempted-stdin': 0, 'stdin': 0, 'stdout': 0, 'stderr': 0}; responses = []; evidence = []
    for index, (row, request) in enumerate(zip(exchanges, requests)):
        q.fields(request, ('wire', 'response_count'), 'declared input-only exchange')
        q.need(type(request['wire']) is bytes and request['wire'].endswith(b'\n'), 'complete planned request bytes')
        q.need(type(request['response_count']) is int and request['response_count'] in (0, 1), 'planned request/notification type')
        q.fields(row, ('index', 'deadline_seconds', 'elapsed_seconds', 'timed_out', 'transport', 'error', 'attempted_input', 'accepted_input',
            'stdout_range', 'stderr_range', 'responses', 'stdout_eof', 'stderr_eof'), 'complete actual exchange receipt')
        q.same(row['index'], index, 'actual exchange sequence'); q.same(row['deadline_seconds'], 60, 'actual exchange deadline')
        bounded_time(q, row['elapsed_seconds'], 60, 'actual exchange duration'); q.need(row['timed_out'] is False, 'actual exchange timeout')
        for key in ('stdout_eof', 'stderr_eof'): q.need(type(row[key]) is bool, 'actual pipe observation type')
        attempted = span(q, row['attempted_input'], raw['attempted-stdin'], positions['attempted-stdin'], 'attempted input')
        accepted = span(q, row['accepted_input'], raw['stdin'], positions['stdin'], 'accepted input')
        q.need(attempted == request['wire'] and accepted == attempted[:len(accepted)], 'complete actual attempted request and accepted prefix')
        q.need(len(accepted) <= len(attempted), 'actual accepted input exceeds request')
        positions['attempted-stdin'] += len(attempted); positions['stdin'] += len(accepted)
        incoming = {}
        for name in ('stdout', 'stderr'):
            area = row[name+'_range']; q.fields(area, ('offset', 'bytes'), 'complete exchange '+name+' range')
            q.same(area['offset'], positions[name], 'contiguous exchange '+name)
            length = q.uint(area['bytes'], 'actual '+name+' range length')
            q.need(length <= len(raw[name])-positions[name], 'actual '+name+' range exceeds full stream')
            incoming[name] = raw[name][positions[name]:positions[name]+length]; positions[name] += length
        q.need(type(row['responses']) is list and len(row['responses']) <= request['response_count'], 'actual response list/cardinality')
        parts = []; offset = 0
        for response in row['responses']:
            q.fields(response, ('bytes', 'sha256'), 'complete response span')
            length = q.uint(response['bytes'], 'actual response length'); body = incoming['stdout'][offset:offset+length]; offset += length
            q.need(len(body) == length and body.endswith(b'\n') and body.count(b'\n') == 1, 'full single newline response')
            q.same(q.sha(body), response['sha256'], 'complete actual response SHA256'); parts.append(body)
        q.need(offset == len(incoming['stdout']), 'stdout bytes outside response ownership')
        transport = row['transport']; error = row['error']
        if transport == 'response':
            q.need(request['response_count'] == 1 and len(parts) == 1 and len(accepted) == len(attempted) and error is None, 'complete successful response transport')
        elif transport == 'notification':
            q.need(request['response_count'] == 0 and not parts and len(accepted) == len(attempted) and error is None, 'complete notification transport')
        elif transport == 'write-error':
            q.need(request['response_count'] == 1 and not parts and len(accepted) < len(attempted), 'actual closed transport input/output distinction')
            q.fields(error, ('type', 'errno', 'message'), 'actual write error')
            q.same(error['type'], 'BrokenPipeError', 'actual observed write failure type'); q.same(error['errno'], 32, 'actual OS pipe failure errno')
            q.need(type(error['message']) is str and error['message'], 'actual complete pipe error message')
        else:
            q.need(transport == 'eof' and request['response_count'] == 1 and not parts and error is None and row['stdout_eof'] is True, 'actual EOF transport')
        responses.append(parts)
        evidence.append({'index': index, 'transport': transport, 'attempted_input': row['attempted_input'], 'accepted_input': row['accepted_input'],
            'response_spans': row['responses'], 'stdout_range': row['stdout_range'], 'stderr_range': row['stderr_range'], 'error': error})
    for name in ('attempted-stdin', 'stdin', 'stdout'): q.same(positions[name], len(raw[name]), 'all actual '+name+' bytes consumed')
    q.need(sum(row['elapsed_seconds'] for row in exchanges)+receipt['drain_elapsed_seconds'] <= receipt['elapsed_seconds'], 'process lifetime covers actual exchanges/drain')
    for name, pin in list(capture.artifacts.items()): q.same(q.pin(q.inside(capture.root, name)), pin, 'complete transport artifact changed during admission')
    proof = {'schema': 'hepta.runtime.filesystem-sdk-stdio-evidence.v1', 'status': 'PASS', 'actual_command': command, 'actual_native_argv': argv,
        'actual_cwd': cwd, 'actual_pid': receipt['pid'], 'binary': binary, 'streams': {name: descriptor['uncompressed'] for name, descriptor in receipt['streams'].items()},
        'exchanges': evidence, 'actual_stderr_bytes_after_last_exchange': len(raw['stderr'])-positions['stderr'], 'actual_trace_present': trace,
        'tool_semantics_admitted': False, 'source_graph_admitted_by_this_reader': False, 'live_process_or_fixture_required': False,
        'artifacts': len(capture.artifacts), 'artifact_bytes': {name: pin['bytes'] for name, pin in sorted(capture.artifacts.items())},
        'artifact_sha256': {name: pin['sha256'] for name, pin in sorted(capture.artifacts.items())}, 'new_native_calls': 0, 'new_rust_processes': 0}
    return proof, responses
