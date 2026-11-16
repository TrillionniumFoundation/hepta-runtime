"""Read all original SDK frames and compare complete tool text to fresh originals."""
from __future__ import annotations
from pathlib import Path
import argparse
import copy
import gzip
import hashlib
import io
import json
import math
import random
import re
import struct
import sys
import tarfile
import time
import tomllib
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from original_reader import source, verify_original, packets, pin, get, read
from wire_cases import rows, frame, domain

TIME = re.compile(rb'("native_operation_wall_seconds":)(-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)(?=[,}])')

def normalized(text):
    value = json.loads(text)
    assert len(value) == 36 and math.isfinite(value['native_operation_wall_seconds'])
    assert value['native_operation_wall_seconds'] >= 0
    matches = list(TIME.finditer(text)); assert len(matches) == 1
    match = matches[0]
    return text[:match.start(2)] + b'0' + text[match.end(2):]

def process(root, label, limit):
    row = read(root / 'processes' / (label + '.json'))
    assert row['started'] is True and row['timed_out'] is False and row['returncode'] == 0
    assert row['pid'] == row['pgid'] and row['pid'] > 0 and row['parent_pid'] > 0
    assert row['timeout_seconds'] == limit and 0 <= row['elapsed_ns'] <= (limit + 1) * 1_000_000_000
    for key in ['stdout', 'stderr']:
        assert pin((root / 'processes' / (label + '.' + key)).read_bytes()) == {k: row[key][k] for k in ['bytes', 'sha256']}
    return row

def source_proof(package):
    proof = read(package / 'original-source.json')
    assert proof['target_commit'] == 'd3d75c30719db966b004756f610007a7c723729e'
    assert proof['target_tree'] == '612e145513961556ac8844b5cc978f9b5175e4d4'
    def checked(raw, expected):
        assert pin(raw) == {k: expected[k] for k in ['bytes', 'sha256']}
        assert hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == expected['git_blob']
    server = (package / 'original-source/src/mcp/server.rs').read_bytes()
    checked(server, proof['server'])
    checked((package / 'reference/weight_bellman.rs').read_bytes(), proof['weight_bellman'])
    assert proof['weight_bellman']['sha256'] == '254de61b7a169ab0a01583feb9562051fa9d477d89d98683263c52ea5545a4a7'
    for name in ['Cargo.toml', 'Cargo.lock']:
        checked((package / 'original-source' / name).read_bytes(), proof[name])
    fragments = {}
    for name, row in proof['fragments'].items():
        raw = server[row['start']:row['end']]; checked(raw, row); fragments[name] = raw
    assert (package / 'reference/full_plan/original_methods.inc').read_bytes() == b'impl OctofsServer {\n' + fragments['weight_bellman_plan'] + b'\n}\n'
    assert (package / 'reference/full_plan/original_get_info.inc').read_bytes() == b'trait OriginalInfo { fn get_info(&self) -> ServerConfig; }\nimpl OriginalInfo for OctofsServer {\n' + fragments['get_info'] + b'\n}\n'
    for key in ['runtime_source_changed', 'full_server_router_qualified', 'audit_qualified', 'async_pending_registry_qualified']:
        assert proof[key] is False
    return proof

def stream_records(raw):
    at = 0
    while at < len(raw):
        assert len(raw) - at >= 96 and raw[at:at + 8] == b'HBPORES1'
        header = struct.unpack_from('<11Q', raw, at + 8)
        size = header[4]
        assert size <= len(raw) - at - 96
        yield header, raw[at + 96:at + 96 + size]
        at += 96 + size
    assert at == len(raw)

def file_pin(path):
    with path.open('rb') as stream:
        return dict(bytes=path.stat().st_size, sha256=hashlib.file_digest(stream, 'sha256').hexdigest())

def stream_file(path, *, model=False):
    with path.open('rb') as stream:
        while raw := stream.read(96):
            assert len(raw) == 96 and raw[:8] == (b'HBPMOR01' if model else b'HBPORES1')
            header = struct.unpack_from('<11Q', raw, 8)
            length = header[5] + header[6] if model else header[4]
            payload = stream.read(length); assert len(payload) == length
            yield header, payload

def error(message, identifier, code, text):
    expected = {'jsonrpc': '2.0', 'error': {'code': code, 'message': text}}
    if identifier is not None:
        expected['id'] = identifier
    assert message == expected

def verify_public(package, original, output):
    report = read(output / 'report.json')
    frozen = read(package / 'wire-domain.json')
    assert frozen == domain() and frozen['public_cases'] == 1366 and frozen['records'] == 1394
    assert report['status'] == 'PUBLIC_SDK_BYTES_OBSERVED_READER_REQUIRED'
    assert report['source_manifest'] == source(package) and report['domain'] == pin((package / 'wire-domain.json').read_bytes())
    assert report['binary'] == pin((original / 'original-public').read_bytes())
    assert report['model_binary'] == pin((original / 'original-public-model').read_bytes())
    for name in ['full_server_router_qualified', 'audit_qualified', 'async_pending_registry_qualified',
                 'native_executed', 'whole_runtime_replaced', 'old_stack_removal_qualified']:
        assert report[name] is False
    observed_process = process(output, 'public-original', 180)
    model_process = process(output, 'public-model', 60)
    input_pin = file_pin(output / 'public.stdin')
    assert input_pin == report['input'] and observed_process['stdin_sha256'] == model_process['stdin_sha256'] == input_pin['sha256']
    with (output / 'public.stdin').open('rb') as stream:
        for row, wire in rows():
            expected = frame(row, wire); assert stream.read(len(expected)) == expected
        assert stream.read(1) == b''
    actual_pin = file_pin(output / 'processes/public-original.stdout')
    assert actual_pin == report['output']
    assert file_pin(output / 'processes/public-model.stdout') == report['model_output']
    originals = packets((original / 'processes/original.stdout').read_bytes())
    counts = [[0, 0, 0], [0, 0, 0]]
    closed = [False, False]; seen = [0, 0]; results = {str(s): {'success': 0, 'business': 0, 'typed': 0, 'model': 0} for s in range(2)}
    response_count = 0; last_after = 0; model_last_after = 0; full_wire_bytes = 0; evidence = []
    parameter_model_differences = []; model_equal_private = 0
    for (declared, wire), (header, body), (model_header, model_payload) in zip(rows(),
            stream_file(output / 'processes/public-original.stdout'),
            stream_file(output / 'processes/public-model.stdout', model=True), strict=True):
        sequence, opcode, session, input_length, output_length, before, after, dispatch, started, completed, reserved = header
        assert (sequence, opcode, session, input_length) == (declared['sequence'], declared['opcode'], declared['session'], len(wire))
        assert reserved == 0 and output_length == len(body) and not closed[session]
        assert last_after <= before <= after and after - before <= 61_000_000_000
        last_after = after
        model_seq, model_op, model_session, model_kind, model_status, canonical_length, text_length, model_before, model_after, zero0, zero1 = model_header
        assert (model_seq, model_op, model_session, zero0, zero1) == (sequence, opcode, session, 0, 0)
        assert model_last_after <= model_before <= model_after and model_after - model_before <= 61_000_000_000
        model_last_after = model_after
        canonical = model_payload[:canonical_length]; model_text = model_payload[canonical_length:]
        assert len(model_text) == text_length
        if model_kind == 1:
            assert model_status in [0, 1, 2] and isinstance(json.loads(canonical), dict)
            model_text.decode('utf-8')
            if model_status == 0:
                normalized(model_text)
                assert json.loads(model_text)['native_operation_wall_seconds'] <= (model_after - model_before) / 1e9
        elif model_kind == 2:
            assert model_status == 3 and canonical == b'' and model_text == b'tools/call'
        else:
            assert model_kind == 0 and model_status == 3 and canonical == model_text == b''
        assert int(model_kind == 1) == declared['expected_dispatch']
        actual_started = int(model_kind == 1 and model_status in [0, 2])
        counts[session][0] += declared['expected_dispatch']
        counts[session][1] += actual_started
        counts[session][2] += actual_started
        assert [dispatch, started, completed] == counts[session], (declared['name'], [dispatch, started, completed], counts[session])
        if declared['frames']:
            assert body.endswith(b'\n')
            lines = body[:-1].split(b'\n')
        else:
            assert body == b''; lines = []
        assert len(lines) == declared['frames']
        messages = [json.loads(line) for line in lines]
        assert len(messages) == len(declared['response_ids'])
        for message, identifier in zip(messages, declared['response_ids'], strict=True):
            if identifier is None:
                assert 'id' not in message and set(message) == {'jsonrpc', 'error'}
            else:
                assert type(message['id']) is type(identifier) and message['id'] == identifier
                assert set(message) in ({'jsonrpc', 'id', 'result'}, {'jsonrpc', 'id', 'error'})
            assert message['jsonrpc'] == '2.0'
        response_count += len(messages); full_wire_bytes += len(body)
        name = declared['name']; result_kind = declared['kind']
        if declared['kind'] == 'case':
            index = declared['case_index']; seen[session] += 1
            reference = originals[index]
            private_status, private_canonical_length, private_text_length = struct.unpack_from('<3Q', reference, 8)
            private_canonical = reference[64:64 + private_canonical_length]
            private_text = reference[64 + private_canonical_length:]
            assert len(private_text) == private_text_length
            assert model_kind in [1, 2]
            if model_kind == 1 and canonical == private_canonical:
                assert model_status == private_status
                assert (normalized(model_text) == normalized(private_text)) if model_status == 0 else (model_text == private_text)
                model_equal_private += 1
            else:
                parameter_model_differences.append(dict(sequence=sequence, name=declared['name'],
                    private_canonical=pin(private_canonical), public_canonical=pin(canonical),
                    private_status=private_status, public_model_kind=model_kind, public_status=model_status))
            status = model_status; text = model_text
            message = messages[0]; identifier = declared['response_ids'][0]
            if model_kind == 2:
                error(message, identifier, -32601, 'tools/call'); result_kind = 'model'
            elif status == 1:
                error(message, identifier, -32602, text.decode()); result_kind = 'typed'
            else:
                assert status in [0, 2]
                result = message['result']; wanted = {'content', 'isError'} | ({'resultType'} if session else set())
                assert set(result) == wanted and result['isError'] is (status == 2)
                if session: assert result['resultType'] == 'complete'
                assert len(result['content']) == 1 and set(result['content'][0]) == {'type', 'text'} and result['content'][0]['type'] == 'text'
                observed = result['content'][0]['text'].encode()
                if status == 0:
                    assert normalized(observed) == normalized(text), (name, 'complete original text')
                    elapsed = json.loads(observed)['native_operation_wall_seconds']
                    assert 0 <= elapsed <= (after - before) / 1e9
                    result_kind = 'success'
                else:
                    assert observed == text, (name, 'complete original business error'); result_kind = 'business'
            results[str(session)][result_kind] += 1
        elif declared['kind'] == 'initialize':
            value = messages[0]['result']
            assert value['protocolVersion'] == '2025-11-25'
            assert value['serverInfo'] == {'name': 'rmcp', 'version': '3.9.0'}
            assert value['capabilities'] == {'experimental': {'claude/channel': {}}, 'tools': {}, 'resources': {'subscribe': True}}
            assert isinstance(value['instructions'], str) and len(value['instructions']) > 300
        elif declared['kind'] == 'close':
            closed[session] = True
        elif declared['kind'] == 'control':
            if name.endswith(('arguments-omitted', 'arguments-null')):
                error(messages[0], declared['response_ids'][0], -32602, 'failed to deserialize parameters: missing field `states`')
            elif name.endswith(('arguments-array', 'arguments-number')):
                error(messages[0], declared['response_ids'][0], -32601, 'tools/call')
            else:
                for position, message in enumerate(messages):
                    identifier = declared['response_ids'][position]
                    if identifier is None:
                        error(message, None, -32600, 'Invalid request')
                    elif session:
                        error(message, identifier, -32602,
                            'request _meta is missing or has malformed required fields: '
                            'io.modelcontextprotocol/protocolVersion, io.modelcontextprotocol/clientCapabilities')
                    else:
                        assert message == {'jsonrpc': '2.0', 'id': identifier, 'result': {}}
        else:
            assert declared['kind'] == 'notification' and not messages
        evidence.append(dict(sequence=sequence, name=name, session=session, result_kind=result_kind,
            input=pin(wire), output=pin(body), dispatch=dispatch, started=started, completed=completed,
            before_ns=before, after_ns=after, model_kind=model_kind, model_status=model_status,
            model_canonical=pin(canonical), model_text=pin(model_text), model_before_ns=model_before, model_after_ns=model_after))
    assert len(evidence) == report['records'] == frozen['records']
    assert closed == [True, True] and seen == [683, 683] and results['0'] == results['1']
    assert sum(results['0'].values()) == 683 and counts[0] == counts[1]
    return dict(status='COMPLETE_PUBLIC_SDK_REFERENCE_PASS', records=len(evidence), public_cases=sum(seen),
        response_count=response_count, protocols=results, per_session_counts=counts,
        normal_closes=2, remaining_close_output_bytes=0, all_public_wire_bytes=full_wire_bytes,
        complete_output=actual_pin, model_output=report['model_output'],
        private_and_sdk_model_equal_cases=model_equal_private, parameter_model_differences=parameter_model_differences,
        whole_runtime_replaced=False, full_server_router_qualified=False,
        audit_qualified=False, async_pending_registry_qualified=False, native_executed=False,
        only_normalized_field='native_operation_wall_seconds', cases=evidence)

def verify(package, run):
    source_manifest = source(package); source_proof(package)
    assert source(run / 'recipe-source') == source_manifest
    original = verify_original(package, run / 'original')
    public = verify_public(package, run / 'original', run / 'public')
    process(run, 'original', 600); process(run, 'public', 180)
    files = {}; total = 0
    for path in sorted(run.rglob('*')):
        assert not path.is_symlink()
        if path.is_file():
            with path.open('rb') as stream: digest = hashlib.file_digest(stream, 'sha256').hexdigest()
            size = path.stat().st_size; total += size
            files[path.relative_to(run).as_posix()] = dict(bytes=size, sha256=digest)
    return dict(status='COMPLETE_BELLMAN_PUBLIC_ORIGINAL_REFERENCE_PASS', original=original, public=public,
        complete_files=len(files), complete_logical_bytes=total, source_manifest=source_manifest,
        all_files=files, public_handler_qualified=False, full_server_router_qualified=False,
        async_pending_registry_qualified=False, whole_runtime_replaced=False, old_stack_removal_qualified=False)

def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['package', 'run']: parser.add_argument('--' + name, type=Path, required=True)
    return parser.parse_args()

if __name__ == '__main__':
    args = arguments(); print(json.dumps(verify(args.package.resolve(), args.run.resolve()), sort_keys=True))
