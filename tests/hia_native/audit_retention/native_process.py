"""Run the actual HIA continuation policy with mechanical external-effect fixtures."""
from pathlib import Path
import argparse
import ctypes
import gzip
import json
import struct
import sys

ROOT = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path[:0] = [str(ROOT), str(ROOT / 'scripts')]
from common import encoded, loads, pin, read, require
from hia_native_loader import NativeModule
from protocol import (CAPACITY, INVALID, Fixture, START_PROBES, RESUME_PROBES,
                      completed, frame_record, get, probe, response, workspace_frame)


def run(manifest, output):
    output.mkdir(parents=True, exist_ok=False)
    cases = [loads(line) for line in sys.stdin.buffer]
    states = []
    for case in cases:
        wire = bytes.fromhex(case['initial_hex'])
        extent = 128 + 8 * get(wire, 16) + len(wire)
        work_size = extent + case['workspace_extra']
        storage = b'\xa7' * work_size + b'\x5a' * 16
        states.append(dict(wire=wire, workspace=ctypes.create_string_buffer(storage, len(storage)),
                           extent=extent, workspace_size=work_size, step=0, seen=set(),
                           fixture=Fixture(case), complete=None))
    report = dict(schema='hepta.audit-retention.actual-native-process.v1', status='INCOMPLETE',
                  native_image=pin(read(manifest.parent / 'module.image.bin')),
                  semantic_host_fallback=False, observed_buffers_complete=True,
                  schedule='round-robin-independent-workspaces')
    invocations, logical_bytes, switches, previous_case = [], 8, 0, None
    results = [None] * len(cases)
    try:
        with (output / 'buffers.bin.gz').open('xb') as physical:
            with gzip.GzipFile(filename='', mode='wb', fileobj=physical, mtime=0, compresslevel=6) as journal:
                journal.write(b'HATLOG01')
                with NativeModule(manifest, manifest_sha256=pin(read(manifest))['sha256']) as module:
                    def invoke(case_index, wire, output_size, work_size, work_storage, probe_name):
                        nonlocal logical_bytes, switches, previous_case
                        state = states[case_index]
                        require(len(wire) <= module.metadata['input_capacity']
                                and output_size <= module.metadata['output_capacity']
                                and work_size <= module.metadata['workspace_capacity'], 'declared native capacities')
                        before = [wire + b'\xc3' * 16, b'\x69' * output_size + b'\xa5' * 16, work_storage.raw]
                        require(len(before[2]) == work_size + 16, 'complete workspace physical extent')
                        source = ctypes.create_string_buffer(before[0], len(before[0]))
                        result = ctypes.create_string_buffer(before[1], len(before[1]))
                        code = module._entry(source, len(wire), result, output_size, work_storage, work_size)
                        after = [source.raw, result.raw, work_storage.raw]
                        ordinal = len(invocations)
                        header = b'HATCAL01' + struct.pack('<8Q', ordinal, case_index, state['step'],
                            int(probe_name != ''), code, len(wire), output_size, work_size)
                        journal.write(header)
                        logical_bytes += len(header)
                        for left, right in zip(before, after, strict=True):
                            journal.write(left); journal.write(right)
                            logical_bytes += len(left) + len(right)
                        invocations.append(dict(ordinal=ordinal, case=case_index, step=state['step'],
                                                probe=probe_name, result=code, source_size=len(wire),
                                                output_size=output_size, workspace_size=work_size))
                        if previous_case is not None and previous_case != case_index:
                            switches += 1
                        previous_case = case_index
                        require(after[0] == before[0] and after[1][-16:] == b'\xa5' * 16
                                and after[2][-16:] == b'\x5a' * 16, 'all borrowed input and physical buffer guards')
                        require(code in (128, INVALID, CAPACITY), 'actual private ABI return')
                        if code in (INVALID, CAPACITY):
                            require(after[1:] == before[1:], 'refusal leaves all mutable bytes unchanged')
                        else:
                            require(after[1][128:] == before[1][128:], 'complete untouched output suffix')
                            require(after[2][state['extent']:] == before[2][state['extent']:],
                                    'complete untouched workspace suffix')
                        return code, after[1][:128], after[2]

                    remaining = len(states)
                    while remaining:
                        for case_index, (case, state) in enumerate(zip(cases, states, strict=True)):
                            if state['complete'] is not None:
                                continue
                            wire = state['wire']
                            names = ()
                            if state['step'] == 0 and case['start_probes']:
                                names = START_PROBES
                            elif state['step'] and case['resume_probes']:
                                kind = get(wire, 24)
                                if kind not in state['seen']:
                                    names = RESUME_PROBES
                                    state['seen'].add(kind)
                            for name in names:
                                altered, out_size, work_size, wanted = probe(name, wire, case['output_capacity'],
                                    state['workspace_size'], state['extent'])
                                storage = state['workspace'].raw[:work_size] + b'\x5a' * 16
                                probe_work = ctypes.create_string_buffer(storage, len(storage))
                                code, _, _ = invoke(case_index, altered, out_size, work_size, probe_work, name)
                                require(code == wanted, 'declared protocol refusal: ' + name)
                            code, reply, work = invoke(case_index, wire, case['output_capacity'],
                                state['workspace_size'], state['workspace'], '')
                            require(code == 128 and reply[:8] == b'HATRS001', 'actual valid policy continuation')
                            kind = get(reply, 8)
                            if kind == 4:
                                value = completed(work[:-16], reply, state['fixture'].trace)
                                state['complete'] = value
                                results[case_index] = case['name'].encode().hex().encode() + b':' + value.hex().encode() + b'\n'
                                remaining -= 1
                                if case['after_completion_probe']:
                                    altered = response(1, get(reply, 16))
                                    storage = state['workspace'].raw
                                    probe_work = ctypes.create_string_buffer(storage, len(storage))
                                    refused, _, _ = invoke(case_index, altered, case['output_capacity'],
                                        state['workspace_size'], probe_work, 'after-completion')
                                    require(refused == INVALID, 'terminal actor refuses resume')
                            else:
                                require(kind in (1, 2, 3) and get(reply, 40) == 0 and get(reply, 48) == 0,
                                        'actual external-effect request')
                                frame = workspace_frame(work[:-16])
                                record = frame_record(frame, get(reply, 24))
                                state['wire'] = state['fixture'].consume(kind, get(reply, 16), record, get(reply, 32))
                                require(state['fixture'].sequence <= case['max_effects'], 'frozen per-case effect budget')
                            state['step'] += 1
        require(all(value is not None for value in results), 'every concrete native scenario completes')
        sys.stdout.buffer.write(b''.join(results))
        sys.stdout.buffer.flush()
        report.update(status='PASS', cases=len(cases), native_calls=len(invocations),
            policy_calls=sum(row['probe'] == '' for row in invocations),
            protocol_refusals=sum(row['probe'] != '' for row in invocations),
            effects=sum(state['fixture'].sequence for state in states), context_switches=switches,
            independent_contexts=len(states), logical_physical_bytes=logical_bytes,
            journal=pin(read(output / 'buffers.bin.gz')))
    finally:
        (output / 'INVOCATIONS.json').write_bytes(encoded(invocations))
        report.update(completed_calls=len(invocations), completed_cases=sum(value is not None for value in results),
                      invocations=pin(read(output / 'INVOCATIONS.json')))
        (output / 'NATIVE.json').write_bytes(encoded(report))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    run(args.manifest.resolve(strict=True), args.output.absolute())
