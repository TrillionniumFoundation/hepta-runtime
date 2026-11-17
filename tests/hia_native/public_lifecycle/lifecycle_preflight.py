# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Actual SDK Read pairs with complete streams and ordinary owned filesystem state."""
from pathlib import Path
import argparse
import copy
import gzip
import json
import os
import selectors
import stat
import subprocess
import sys
import time
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lifecycle_cases as cases
import lifecycle_inputs as inputs
import lifecycle_projection as projection

q = projection.q
J = lambda value: (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def root_stat(path):
    st = path.stat()
    return dict(mode=stat.S_IMODE(st.st_mode), device=st.st_dev, inode=st.st_ino,
                nlink=st.st_nlink, uid=st.st_uid, gid=st.st_gid)


def receive(stream, buffered, complete):
    deadline = time.monotonic() + 30
    with selectors.DefaultSelector() as selector:
        selector.register(stream, selectors.EVENT_READ)
        while b'\n' not in buffered:
            left = deadline - time.monotonic()
            assert left > 0 and selector.select(left), 'normal public response deadline'
            raw = os.read(stream.fileno(), 65536)
            complete.extend(raw)
            assert raw, 'unexpected public EOF'
            buffered += raw
            assert len(buffered) <= 134217728
    end = buffered.index(b'\n') + 1
    return buffered[:end], buffered[end:]


def check_expected(response, expected):
    if expected == 'catalog':
        tools = response['result']['tools']
        assert [tool['name'] for tool in tools] == ['effective_config', 'execution_shadow_admit', 'host_health', 'host_list', 'request_cancel', 'request_history', 'request_result', 'request_start', 'request_status']
        assert len(tools) == 9
        return
    if expected in ('invalid_id', 'unavailable'):
        error = response['error']
        want = (-32602, 'request unavailable to this scope or current policy') if expected == 'invalid_id' else (-32603, 'request audit unavailable; dispatch refused')
        assert (error['code'], error['message']) == want
        return
    result = response['result']
    assert result['isError'] is (expected != 'success')
    if expected == 'typed_error':
        assert result['content'][0]['text'].startswith('failed to deserialize parameters: ')
    if expected == 'cursor_error':
        assert result['content'][0]['text'] == 'request history cursor expired or unavailable to this session'


def run_side(binary, side, folder, version, update, *, retained_common=None):
    target = folder / side
    target.mkdir(mode=0o700)
    common = folder / 'common' if retained_common is None else Path(retained_common)
    common.mkdir(mode=0o700, exist_ok=True)
    state = common / 'state'
    state.mkdir(mode=0o700)
    config = common / 'config.json'
    configuration = dict(state_dir=str(state), hosts={'fixture': dict(
        ssh_target='unused-local-fixture', remote_state_dir='/unused-private-state', allow_write=False)})
    raw_config = q.compact(configuration)
    if config.exists():
        assert config.read_bytes() == raw_config
    else:
        config.write_bytes(raw_config)
        config.chmod(0o600)
    command = [str(binary), '--runtime-config', str(config)]
    row = dict(side=side, status='RUNNING', command=command, cwd=str(target),
               response_timeout_seconds=30, requests_entered=0, responses_received=0, responses_completed=0)
    update(row)
    started = time.monotonic()
    child = None
    raw_input, raw_output = bytearray(), bytearray()
    buffered = b''
    requests, responses, bounds = {}, {}, {}
    provenance = dict(owner=None, request_ids={})
    normalized_wires, normalized_requests, snapshots = [], [], []
    ident, payload_bytes = None, None
    last_id, page_cursor, last_response_ms = None, None, -1
    try:
        with (target / 'stderr').open('xb') as stderr, gzip.open(target / 'observations.jsonl.gz', 'wb') as log:
            child = subprocess.Popen(command, cwd=target, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=stderr, close_fds=True, bufsize=0,
                env={'PATH': '', 'LC_ALL': 'C', 'HEPTA_REQUEST_AUDIT_TRACE': '0'})
            row['pid'] = child.pid
            update(row)
            events = [(None, None, 'initialize', None)] + cases.CASES
            for frame, (tool, template, label, expected) in enumerate(events, 1):
                if tool is None:
                    request = dict(jsonrpc='2.0', id=0, method='initialize', params=dict(
                        protocolVersion=version, capabilities={}, clientInfo=dict(name='unified-public-pairs', version='1')))
                elif tool == '__catalog__':
                    request = dict(jsonrpc='2.0', id=frame - 1, method='tools/list', params={})
                else:
                    arguments = cases.materialize(template, ident, payload_bytes, last_id, page_cursor)
                    request = dict(jsonrpc='2.0', id=frame - 1, method='tools/call',
                                   params=dict(name=tool, arguments=arguments))
                wire = q.compact(request) + b'\n'
                pacing_deadline=time.monotonic()+1
                while time.time_ns()//1000000 <= last_response_ms:
                    assert time.monotonic()<pacing_deadline, 'controlled request pacing deadline'
                    time.sleep(0.001)
                before = dict(wall_before=time.time_ns(), mono_before=time.monotonic_ns())
                row['requests_entered'] += 1
                update(row)
                raw_input.extend(wire)
                assert child.stdin.write(wire) == len(wire)
                response_raw, buffered = receive(child.stdout, buffered, raw_output)
                row['responses_received'] += 1
                before.update(wall_after=time.time_ns(), mono_after=time.monotonic_ns())
                last_response_ms=before['wall_after']//1000000
                response = q.checked_json(response_raw[:-1])
                assert response['id'] == request['id']
                requests[frame], responses[frame], bounds[frame] = request, response, before
                q.observe_identities(state, frame, request, response, provenance)
                if provenance['request_ids']:
                    last_id=provenance['request_ids'][max(provenance['request_ids'])]
                if tool == 'request_history':
                    assert frame not in provenance['request_ids'], 'metadata observation admitted a Ticket'
                full, logical, counts = q.snapshot(state, requests, responses, bounds, provenance)
                _, projected = projection.wire(response_raw, frame, request, state, provenance)
                normalized_request = projection.request_projection(request, provenance)
                log.write(q.compact(dict(frame=frame, label=label, input_hex=wire.hex(), output_hex=response_raw.hex(),
                    normalized_input=normalized_request, normalized_output_hex=projected.hex(), bounds=before,
                    identity_relation=copy.deepcopy(provenance), root_stat=root_stat(state), filesystem=full, logical=logical)) + b'\n')
                if tool == 'request_history' and 'result' in response and response['result']['isError'] is False:
                    history=q.checked_json(response['result']['content'][0]['text'].encode())
                    page_cursor=history['next_after_id']
                normalized_wires.append(projected)
                normalized_requests.append(normalized_request)
                snapshots.append(logical)
                if tool is not None:
                    check_expected(response, expected)
                if label == 'retain-host-list':
                    ident = response['result']['_meta'][q.ID_META]['request_id']
                    _, audit = projection.selected_record(state, ident, provenance)
                    _, payload = projection.retained_payload(state, ident, audit)
                    payload_bytes = len(payload)
                row.update(responses_completed=frame, counts=counts, last_label=label)
                update(row)
            child.stdin.close()
            child.wait(timeout=30)
            extra = child.stdout.read()
            raw_output.extend(extra)
            assert child.returncode == 0 and extra == b'' and buffered == b''
            assert not Path('/proc', str(child.pid)).exists()
            full, logical, counts = q.snapshot(state, requests, responses, bounds, provenance)
            (target / 'eof-filesystem.json').write_bytes(J(dict(root_stat=root_stat(state), full=full, logical=logical, counts=counts)))
            assert (target / 'stderr').read_bytes() == b''
            row.update(status='PASS', exit_code=0, reaped=True, counts=counts)
        os.rename(state, target / 'final-state')
        return dict(wire_hex=b''.join(normalized_wires).hex(), requests=normalized_requests,
                    snapshots=snapshots, eof=logical, counts=counts)
    except BaseException as error:
        row.update(status='FAIL', error=repr(error))
        raise
    finally:
        if child is not None:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=3)
            row['exit_code'] = child.returncode
            if child.stdout is not None:
                child.stdout.close()
        (target / 'input.bin').write_bytes(raw_input)
        (target / 'stdout.bin').write_bytes(raw_output)
        for name in ('input.bin', 'stdout.bin', 'stderr', 'observations.jsonl.gz', 'eof-filesystem.json'):
            path = target / name
            if path.exists():
                row[name] = inputs.pin(path)
        row['elapsed_seconds'] = time.monotonic() - started
        update(row)

