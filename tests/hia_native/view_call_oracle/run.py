"""Fresh locked Rust actual-filesystem and rmcp reference execution.

Reference-only runs are marked REFERENCE_READY. A native comparison is PASS
only after all independently generated inputs, visible results and observed
cache/I/O values match complete retained native artifacts.
"""
from __future__ import annotations
import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import struct
import time

ROOT = Path(__file__).resolve().parent

def sibling(name):
    spec = importlib.util.spec_from_file_location('_view_call_original_' + name, ROOT / (name + '.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module

cases, sdk, source, parameter, wide, router, info, replay = (sibling(name) for name in (
    'cases', 'sdk_cases', 'verify_sources', 'parameter_sdk_cases', 'wide_endpoint_case',
    'router_sdk_cases', 'info_sdk_cases', 'replay_compare'))

def identity(path):
    digest = hashlib.sha256(); size = 0
    with Path(path).open('rb') as stream:
        while block := stream.read(1 << 20): digest.update(block); size += len(block)
    return dict(bytes=size, sha256=digest.hexdigest())

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode() + b'\n'



def reference_summary(output):
    inputs = cases.iter_cases(); counts = dict(cases=0, successful=0, errors=0, cancelled=0, body_bytes=0,
                                                     metadata_calls=0, read_calls=0, successful_read_bytes=0)
    with (output / 'original.stdout').open('rb') as stream:
        records = cases.read_records(stream, cases.OUTPUT_MAGIC)
        for expected in inputs:
            row = next(records); meta, blobs = row['metadata'], row['blobs']; request = expected['metadata']
            assert (meta['case_id'], meta['name'], meta['session']) == (request['case_id'], request['name'], request['session'])
            assert sorted(meta['fired_hooks']) == list(range(len(request['hooks'])))
            assert meta['outside_scope_hints_empty'] is True
            counts['cases'] += 1; outcome = meta['outcome']
            if outcome.get('cancelled'):
                assert request['cancel_after_render'] and outcome['publication_bytes'] == 0
                counts['cancelled'] += 1
            else:
                assert type(outcome['ok']) is bool
                assert len(blobs[outcome['blob']]) == outcome['bytes']
                counts['successful' if outcome['ok'] else 'errors'] += 1
                counts['body_bytes'] += outcome['bytes']
            counts['metadata_calls'] += meta['io_counts'].get('metadata', 0)
            counts['read_calls'] += meta['io_counts'].get('read', 0)
            for event in meta['events']:
                if event['kind'] == 'io' and event['event'] == 'read' and event['result']['ok']:
                    result = event['result']; assert len(blobs[result['snapshot_blob']]) == result['bytes']
                    counts['successful_read_bytes'] += result['bytes']
        assert next(records, None) is None
    sdk_rows = [json.loads(line) for line in (output / 'sdk.stdout').read_bytes().split(b'\n') if line]
    expected_sdk = list(sdk.iter_sdk_cases()); assert len(sdk_rows) == len(expected_sdk)
    for row, expected in zip(sdk_rows, expected_sdk):
        assert row['case_id'] == expected['case_id'] and row['name'] == expected['name']
        assert len(row['responses']) == sum('id' in request for request in expected['messages'])
        assert type(row['service']['initialized']) is bool
    return dict(actual_io=counts, actual_sdk=dict(cases=len(sdk_rows),
                requests=sum(len(row['responses']) for row in sdk_rows),
                handler_observations=sum(len(row['handler_observations']) for row in sdk_rows)),
                actual_tokio_io=True, actual_rmcp_transport=True, whole_view_migrated=False)

def sdk_reference(output, name, inputs, expected_count):
    rows=[json.loads(line) for line in (output/(name+'.stdout')).read_bytes().split(b'\n') if line]
    expected=list(inputs);assert len(rows)==len(expected)==expected_count
    for row,request in zip(rows,expected):
        assert (row['case_id'],row['name'])==(request['case_id'],request['name'])
        assert len(row['responses'])==sum('id' in item for item in request['messages'])
        assert type(row['service']['initialized']) is bool
        if name=='router':
            assert row['actual_sdk_parameters_extractor'] is True and row['actual_sdk_async_method_adapter'] is True
            assert row['original_view_body_executed'] is False and row['ensure_session_method_executed'] is False
            assert type(row['outer_call_tool_entries']) is int and row['outer_call_tool_entries']>=len(row['handler_observations'])
        if name=='info':
            assert row['actual_original_get_info'] is True and row['actual_original_cache_hint_predicate'] is True
            assert row['empty_tool_list_fixture'] is True and row['original_full_list_tools_executed'] is False
    return dict(cases=len(rows),responses=sum(len(row['responses']) for row in rows),
                handler_observations=sum(len(row['handler_observations']) for row in rows),
                original_view_body_executed=False)

def additional_reference_summary(output):
    parameter_inputs=[json.loads(line) for line in parameter.encoded_cases().split(b'\n') if line]
    result=dict(parameter=sdk_reference(output,'parameter',parameter_inputs,39),
                router=sdk_reference(output,'router',router.iter_router_sdk_cases(),54),
                info=sdk_reference(output,'info',info.iter_info_sdk_cases(),13))
    lines=(output/'public-schema.stdout').read_bytes().split(b'\n');assert len(lines)==3 and lines[-1]==b''
    assert all(type(json.loads(line)) is dict for line in lines[:2])
    for name,raw in zip(('raw-input-schema.json','public-input-schema.json'),lines[:2]):
        (output/name).write_bytes(raw+b'\n')
    result['schema']=dict(raw=identity(output/'raw-input-schema.json'),
        published=identity(output/'public-input-schema.json'),original_functions_executed=True,
        original_full_list_tools_executed=False)
    with (output/'wide.stdout').open('rb') as stream:
        records=cases.read_records(stream,cases.OUTPUT_MAGIC);row=next(records);assert next(records,None) is None
        meta,blobs=row['metadata'],row['blobs'];assert meta['case_id']==wide.CASE_ID
        assert meta['outcome']['ok'] is False and meta['io_counts']=={'exists':1,'is_dir':1}
        body=blobs[meta['outcome']['blob']];assert len(body)==meta['outcome']['bytes']>16<<20
        result['wide']=dict(cases=1,case_id=wide.CASE_ID,error_body=source.pin(body),actual_tokio_io=True,ordinary_58_cases_counted=0)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cargo', type=Path, required=True)
    parser.add_argument('--rustc', type=Path, required=True)
    parser.add_argument('--offline', action='store_true', help='explicit cached-host build; default permits dependency downloads')
    parser.add_argument('--native-corpus', type=Path)
    parser.add_argument('--params-corpus', type=Path)
    parser.add_argument('--wide-corpus', type=Path)
    parser.add_argument('--reference-only', action='store_true')
    args = parser.parse_args()
    corpora=(args.native_corpus,args.params_corpus,args.wide_corpus)
    if args.reference_only:
        if any(corpora):parser.error('reference-only cannot accept native corpora')
    elif not all(corpora):parser.error('native comparison requires caller, params and wide corpora')
    output = args.output.resolve(); output.mkdir(parents=True, exist_ok=False)
    inputs_before = {str(path.relative_to(ROOT)): identity(path) for path in ROOT.rglob('*') if path.is_file() and '__pycache__' not in path.parts}
    materialized = source.materialize(args.runtime_root.resolve(), output / 'crate')
    with (output/'input.bin').open('xb') as stream:
        stream.write(cases.INPUT_MAGIC+struct.pack('<Q',58));count=0
        for case in cases.iter_cases():stream.write(cases.blob_record(case['metadata'],case['blobs']));count+=1
        assert count==58
    (output / 'sdk-input.jsonl').write_bytes(sdk.encode_cases())
    (output / 'parameter-input.jsonl').write_bytes(parameter.encoded_cases())
    (output / 'wide-input.bin').write_bytes(wide.original_input())
    (output / 'router-input.jsonl').write_bytes(b''.join(canonical(row) for row in router.iter_router_sdk_cases()))
    (output / 'info-input.jsonl').write_bytes(b''.join(canonical(row) for row in info.iter_info_sdk_cases()))
    env = dict(os.environ); env['RUSTC'] = str(args.rustc.absolute()); env['CARGO_TARGET_DIR'] = str(output / 'target'); env['CARGO_BUILD_JOBS'] = '2'
    env['PATH'] = str(args.cargo.absolute().parent) + os.pathsep + env.get('PATH', '')
    records = []
    def run(name, command, stdin_path=None):
        started = time.monotonic(); returncode = None; timed_out = False; spawn_error = None
        with contextlib.ExitStack() as stack:
            stdin = stack.enter_context(stdin_path.open('rb')) if stdin_path else subprocess.DEVNULL
            stdout = stack.enter_context((output / (name + '.stdout')).open('xb'))
            stderr = stack.enter_context((output / (name + '.stderr')).open('xb'))
            try:
                process = subprocess.run(command, cwd=output / 'crate', env=env, stdin=stdin,
                                         stdout=stdout, stderr=stderr, timeout=180)
                returncode = process.returncode
            except subprocess.TimeoutExpired:
                timed_out = True
            except OSError as error:
                spawn_error = str(error)
        records.append(dict(name=name, command=command, cwd=str(output / 'crate'), timeout_seconds=180,
                            elapsed_seconds=time.monotonic()-started, exit_code=returncode,
                            timed_out=timed_out, spawn_error=spawn_error, stdout=identity(output / (name + '.stdout')),
                            stderr=identity(output / (name + '.stderr'))))
        (output / 'process-receipts.json').write_bytes(canonical(records))
        if timed_out or spawn_error or returncode != 0:
            raise AssertionError(f'{name} failed (exit={returncode}, timeout={timed_out}, spawn={spawn_error}); complete streams retained')
    run('rust-version', [str(args.rustc.absolute()), '--version'])
    build_command=[str(args.cargo.absolute()),'build','--locked']
    if args.offline:build_command.append('--offline')
    build_command += ['--manifest-path',str(output/'crate/Cargo.toml'),'--release']
    run('build', build_command)
    run('original', [str(output / 'target/release/hepta-view-call-original-oracle'), str(output / 'fixtures')], output / 'input.bin')
    run('sdk', [str(output / 'target/release/view_call_sdk')], output / 'sdk-input.jsonl')
    run('parameter', [str(output / 'target/release/view_call_sdk')], output / 'parameter-input.jsonl')
    run('wide', [str(output / 'target/release/hepta-view-call-original-oracle'), str(output / 'wide-fixtures')], output / 'wide-input.bin')
    run('router', [str(output / 'target/release/view_call_router_sdk')], output / 'router-input.jsonl')
    run('public-schema', [str(output / 'target/release/view_call_public_schema')])
    run('info', [str(output / 'target/release/view_call_info_sdk')], output / 'info-input.jsonl')
    summary = reference_summary(output)
    additional=additional_reference_summary(output)
    comparison = None if args.reference_only else dict(
        caller=replay.compare_native(args.native_corpus.resolve(),output),
        params=replay.compare_params(args.params_corpus.resolve(),output),
        wide=replay.compare_wide(args.wide_corpus.resolve(),output))
    inputs_after = {str(path.relative_to(ROOT)): identity(path) for path in ROOT.rglob('*') if path.is_file() and '__pycache__' not in path.parts}
    assert inputs_before == inputs_after
    report = dict(schema='hepta.runtime.view-call-original-reference.v1', status='REFERENCE_READY' if args.reference_only else 'PASS',
                  materialization=materialized, reference=summary, additional_reference=additional, native_comparison=comparison,
                  processes=records, harness_inputs=inputs_before, harness_unchanged=True,
                  build_environment={key:env[key] for key in ('RUSTC','CARGO_TARGET_DIR','CARGO_BUILD_JOBS','CARGO_NET_OFFLINE') if key in env},
                  explicit_offline=args.offline,
                  independent_input=identity(output / 'input.bin'), sdk_input=identity(output / 'sdk-input.jsonl'),
                  original_output=identity(output / 'original.stdout'), sdk_output=identity(output / 'sdk.stdout'),
                  additional_inputs={name:identity(output/name) for name in (
                      'parameter-input.jsonl','wide-input.bin','router-input.jsonl','info-input.jsonl')},
                  additional_outputs={name:identity(output/name) for name in (
                      'parameter.stdout','wide.stdout','router.stdout','public-schema.stdout','info.stdout')},
                  binaries={name: identity(output / 'target/release' / name) for name in (
                      'hepta-view-call-original-oracle', 'view_call_sdk', 'view_call_router_sdk',
                      'view_call_public_schema', 'view_call_info_sdk')},
                  whole_view_migrated=False, whole_runtime_replaced=False)
    (output / 'result.json').write_bytes(canonical(report)); print(json.dumps(report, sort_keys=True))

if __name__ == '__main__': main()
