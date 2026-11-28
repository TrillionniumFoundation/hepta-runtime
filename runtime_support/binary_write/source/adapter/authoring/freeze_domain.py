#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Extract complete existing inputs and actual ready packets from verified DATA."""
import argparse
import base64
import collections
import gzip
import hashlib
import json
import lzma
import struct
from pathlib import Path

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
PACK = lambda *words: struct.pack('<' + 'Q' * len(words), *words)
WORD = lambda raw, at: struct.unpack_from('<Q', raw, at)[0]
B64 = lambda raw: base64.b64encode(raw).decode('ascii')
PINS = {
    'planner/results.json': '2d127d8a1519b990d79eb56f32aa84b2f87b0b8f660735c855ac95d88171f6f0',
    'reference/calls.bin.gz': '2dd0669850189b8d096d120066abdcb3a11c38f5a40010da8f4c92e81b441976',
    'reference/calls.jsonl': 'ce31960d7d793fd3cde0531dd52e3de2bc1e4325b1c4bf9f18093091e182db61',
    'typed/results.json': '00793dc6a19f4e270fe5bb19121a867bda87cf17ab6de854f5f3cbc6142d11f2',
    'typed/input.jsonl': 'dc5cca8108cce58ac9718a8d661218bc306ec0b61f6613f3c9a3d649cade3a9c',
}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--retained', type=Path, required=True)
    p.add_argument('--guarded-read', type=Path, required=True)
    p.add_argument('--parent-domain', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    assert not a.output.exists()
    guard_raw = a.guarded_read.read_bytes()
    guard = json.loads(guard_raw)
    assert guard['status'] == 'READONLY_PASS' and guard['before'] == guard['after']
    assert guard['native_executed'] is False and guard['rust_executed'] is False
    root_index = guard['roots'].index(str(a.retained.resolve(strict=True)))
    declared = {r['path']: r for r in guard['after'] if r['root'] == root_index}
    raw = {}
    for name, sha in PINS.items():
        data = (a.retained / name).read_bytes()
        assert SHA(data) == sha == declared[name]['sha256'] and len(data) == declared[name]['bytes']
        if name != 'reference/calls.bin.gz':
            raw[name] = data
    plans = json.loads(raw['planner/results.json'])
    typed = json.loads(raw['typed/results.json'])
    typed_inputs = [json.loads(line) for line in raw['typed/input.jsonl'].splitlines()]
    index = [json.loads(line) for line in raw['reference/calls.jsonl'].splitlines()]
    assert len(plans) == 433 and len(typed) == len(typed_inputs) == 1388 and len(index) == 12350
    assert collections.Counter(row['kind'] for row in plans) == {1: 63, 2: 89, 3: 59, 4: 110, 5: 112}
    needed = {stage['plan_calls'][-1] for row in plans for stage in row['stages']}
    for row in typed:
        if row['kind'] == 3:
            needed.add(row['value_calls'][-1])
            if row['params_calls']:
                needed.add(row['params_calls'][-1])
    completed = {}
    offset = 0
    with gzip.open(a.retained / 'reference/calls.bin.gz', 'rb') as stream:
        for ordinal, row in enumerate(index, 1):
            data = stream.read(row['bytes'])
            assert len(data) == row['bytes'] and SHA(data) == row['record_sha256']
            assert row['call'] == ordinal and row['offset'] == offset
            fields = struct.unpack_from('<8Q', data)
            assert fields == (ordinal, row['owner'], row['case_id'], row['return_code'], row['input_bytes'], row['output_capacity'], row['workspace_capacity'], 0)
            at, arrays = 64, {}
            for size, label in [(fields[4], 'input'), (fields[6], 'before'), (fields[5], 'output_before'), (fields[5], 'output'), (fields[6], 'after')]:
                part = data[at:at + size]
                assert len(part) == size and SHA(part) == row[label + '_sha256']
                arrays[label] = part
                at += size
            assert at == len(data) and arrays['output_before'] == b'\xa5' * fields[5]
            if ordinal in needed:
                completed[ordinal] = row, arrays['input'], arrays['output']
            offset += len(data)
        assert stream.read(1) == b''
    assert offset == 1627490313 and len(completed) == len(needed)
    plan_cases, write_ready = [], 0
    for row in plans:
        typed_frame = bytes.fromhex(row['typed_frame_hex'])
        feedback = b''
        stages = []
        for stage in row['stages']:
            observed, wire, result = completed[stage['plan_calls'][-1]]
            assert observed['owner'] == 7 and observed['case_id'] == row['case_id']
            expected = bytes.fromhex(stage['frame_hex'])
            assert observed['return_code'] == len(expected) and result[:len(expected)] == expected
            assert result[len(expected):] == b'\xa5' * (len(result) - len(expected))
            assert wire[:8] == b'HBPLQ001' and WORD(wire,8) == stage['phase']
            assert WORD(wire,24) == len(typed_frame) and wire[48:48 + len(typed_frame)] == typed_frame
            assert WORD(wire,32) == len(feedback) and wire[48 + len(typed_frame):] == feedback
            eligible = row['kind'] == 3 and stage['phase'] == 2 and WORD(expected,8) == 3
            write_ready += int(eligible)
            stages.append(dict(phase=stage['phase'], request=B64(wire), actual_result=B64(expected),
                               eligible=eligible, original_call=observed['call'],
                               original_record_sha256=observed['record_sha256']))
            feedback = bytes.fromhex(stage['root_hex']) if stage['root_hex'] is not None else b''
        plan_cases.append(dict(case_id=row['case_id'], name=row['name'], group=row['group'], kind=row['kind'],
                               typed_frame=B64(typed_frame), stages=stages))
    assert write_ready == 19
    typed_by_id = {row['case_id']: row for row in typed}
    typed_cases = []
    for item in typed_inputs:
        if item['kind'] != 3:
            continue
        row = typed_by_id[item['case_id']]
        assert [row[k] for k in ('case_id','kind','name')] == [item[k] for k in ('case_id','kind','name')]
        vrow, vwire, value = completed[row['value_calls'][-1]]
        raw_json = item['raw_json'].encode()
        assert vwire == b'HJSMS002' + PACK(1,len(raw_json)) + raw_json and vrow['return_code'] == 32
        value_size = 32 + WORD(value,16)
        assert value[value_size:] == b'\xa5' * (len(value) - value_size)
        value = value[:value_size]
        frame = None
        if row['params_calls']:
            trow, twire, result = completed[row['params_calls'][-1]]
            frame = bytes.fromhex(row['typed_frame_hex'])
            assert trow['return_code'] == 256 and result[:len(frame)] == frame
            assert result[len(frame):] == b'\xa5' * (len(result)-len(frame))
            assert WORD(value,8) == 0 and twire == b'HBPRQ001' + PACK(len(value)-32,3) + value[32:]
        typed_cases.append(dict(case_id=row['case_id'], name=row['name'], raw_json=B64(raw_json),
                                actual_map=B64(value), actual_typed=None if frame is None else B64(frame)))
    assert len(typed_cases) == 196
    parent_raw = a.parent_domain.read_bytes()
    assert SHA(parent_raw) == '0dc9c300dab0380e746ead00b3a8338db7abf9b8c15190208436377838999114'
    parent = json.loads(parent_raw)
    assert len(parent['cases']) == 256 and parent['case_count'] == 256
    result = dict(schema='hepta.runtime.binary-write-adapter.inputs.v1', plan_cases=plan_cases,
                  typed_write_cases=typed_cases, parent_interface_cases=parent['cases'])
    encoded = (json.dumps(result,sort_keys=True,separators=(',',':')) + '\n').encode()
    compressed = lzma.compress(encoded,preset=6)
    a.output.mkdir(parents=True)
    (a.output/'INPUTS.json.xz').write_bytes(compressed)
    source = dict(schema='hepta.runtime.binary-write-adapter.retained-inputs.v1',
        parent_commit='43426460fda1f7576127281a114306f4ae95e64b', retained_root=str(a.retained.resolve()),
        guarded_read=dict(bytes=len(guard_raw),sha256=SHA(guard_raw)), original_files=PINS,
        original_complete_native_records=12350, original_complete_native_bytes=offset,
        all_plan_cases=433, all_plan_groups=24, write_plan_cases=59, write_ready_cases=19,
        retained_typed_total=1388, all_write_typed_cases=196, parent_interface_cases=256,
        parent_interface_missing_version_cases=2, parent_domain_sha256=SHA(parent_raw),
        inputs=dict(bytes=len(compressed),sha256=SHA(compressed),decoded_bytes=len(encoded),decoded_sha256=SHA(encoded)),
        parent_effects_executed=0, new_application_executions=0, whole_runtime_replaced=False)
    (a.output/'DOMAIN.json').write_text(json.dumps(source,sort_keys=True,indent=2)+'\n')
    print(json.dumps(source,sort_keys=True))


if __name__ == '__main__':
    main()
