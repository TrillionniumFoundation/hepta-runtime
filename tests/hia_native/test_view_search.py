#!/usr/bin/env python3
"""Actual HIA literal-search execution; expectations are unchanged Rust bytes.

The synchronized fixture performs real following stat/open/read/close effects.
The host schedules only requested file changes and compares retained complete
records. It does not implement matching, lossy decoding, rendering or a result
size gate. Native execution and original-reference replay are separate counts.
"""
from __future__ import annotations
import gzip, hashlib, importlib.util, json, os, stat, struct, sys, time, traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result

base = module('_view_search_existing_fixture_helpers', HERE / 'test_view_call_sync.py')
support = base.support
cases = module('_view_search_original_inputs', HERE / 'view_search_oracle' / 'cases.py')
CANCELLED = 0xffffffcf
FIRST, COUNT = 10000, 72
EXPECTED_INPUT = dict(bytes=47345844, sha256='1b2f8661ee9fde9b1a362a8a866a921645c36dbc5d821f916e91183c34b59742')
artifact, control, probes = base.artifact, base.control, base.probes
identity, write_json, receive = base.identity, base.write_json, base.receive

def request(case):
    metadata = case['metadata']; path = bytes.fromhex(metadata['path_hex'])
    assert metadata['raw_path'] is False
    path.decode('utf-8')
    params = metadata['params']
    if metadata['domain'] == 'whole-prime':
        assert metadata['case_id'] == 10064
        return support.call_frame(path, path, params)
    assert metadata['domain'] == 'literal-search' and params['regex'] is False
    pattern = params['content'].encode('utf-8'); context = params['context']
    assert pattern and type(context) is int and 0 <= context < (1 << 64)
    flags = 4 if params.get('full', False) else 0
    return struct.pack('<8s7Q', b'HVCSQ001', flags, len(path), len(path),
                       len(pattern), context, 0, 0) + path + path + pattern

def observation(kind, occurrence, body, path, output, prefix, domain):
    assert len(body) >= 80 and body[:8] == b'HVRDR001'
    names = ('generation','operation','outcome','errno','mode','metadata_size',
             'snapshot_offset','snapshot_length','read_attempts')
    native = dict(zip(names, struct.unpack_from('<9Q', body, 8)))
    operation = (5 if domain == 'literal-search' else 2) if kind == 5 else 1
    assert native['generation'] > 0 and native['operation'] == operation
    assert native['outcome'] in ((0,1,2) if operation == 5 else (0,1,2,3))
    assert 0 <= native['errno'] <= 4095
    assert len(body) == 80 + native['snapshot_length']
    if operation == 1 or native['outcome'] != 0:
        assert native['snapshot_offset'] == native['snapshot_length'] == 0
    else:
        assert native['snapshot_offset'] == 8192
    row = dict(event=base.EVENT_NAMES[kind], occurrence=occurrence,
               operation=native['operation'], native_reader=native,
               reader_result_path=artifact(output, prefix+'.reader.bin.gz', body))
    if kind <= 3:
        value = native['outcome'] == 0
        if kind == 2: value = value and stat.S_ISDIR(native['mode'])
        if kind == 3: value = value and stat.S_ISREG(native['mode'])
        row.update(ok=True, value=value)
    elif native['outcome'] != 0:
        if native['outcome'] == 3:
            assert operation == 2
            detail = 'stream did not contain valid UTF-8'
        elif native['outcome'] == 2:
            detail = 'file name contained an unexpected NUL byte'
        else:
            detail = os.strerror(native['errno']) + f" (os error {native['errno']})"
        row.update(ok=False,
            error=f"Failed to {'read' if kind==5 else 'stat'} '{path.decode('utf-8',errors='replace')}': {detail}",
            error_text_origin='diagnostic translation of retained native typed outcome')
    elif kind == 4:
        row.update(ok=True, size=native['metadata_size'],
                   is_file=stat.S_ISREG(native['mode']), is_dir=stat.S_ISDIR(native['mode']))
    else:
        row.update(ok=True, snapshot_path=artifact(output, prefix+'.snapshot.bin.gz', body[80:]))
    return row

def execute_case(process, case, filesystem, output):
    metadata=case['metadata']; cid=metadata['case_id']; prefix=f'case-{cid:05d}'
    path=bytes.fromhex(metadata['path_hex']); wire=request(case)
    assert all(hook['when']=='after' for hook in metadata['hooks'])
    row=dict(case_id=cid,name=metadata['name'],session=metadata['session'],
             domain=metadata['domain'],cancelled=False,
             input_path=artifact(output,prefix+'.input.bin.gz',cases.encode_cases([case])),
             call_path=artifact(output,prefix+'.call.bin.gz',wire),
             io=[],events=[],cache_before=[],cache_after=[],cache_observations_complete=True)
    assert control(process,1,int(metadata['context']))==b''
    if metadata['reset_cache']: assert control(process,2)==b''
    row['cache_before']=probes(process,metadata,output,prefix+'.cache-before')
    process.send_frame(wire)
    counts={}; previous_sequence=0; generation=None; gates=0
    while True:
        payload=receive(process)
        if payload[:8]==b'HVCLOR01':
            assert len(payload)>=32
            code,size,reserved=struct.unpack_from('<3Q',payload,8)
            assert reserved==0 and size==len(payload)-32
            row['native_return']=code
            row['result_path']=artifact(output,prefix+'.result.bin.gz',payload)
            if code==CANCELLED:
                assert metadata['cancel_after_render'] and size==0 and gates==1
                row.update(cancelled=True,body_bytes=0,
                           body_path=artifact(output,prefix+'.body.bin.gz',b''))
            else:
                result=payload[32:]
                assert code==size==len(result) and size>=32 and result[:8]==b'HRCFGM01',(cid,code,size)
                status,zero,length=struct.unpack_from('<3Q',result,8)
                assert status in (0,1) and zero==0 and length==size-32
                result[32:].decode('utf-8')
                row.update(ok=status==0,body_bytes=length,
                           body_path=artifact(output,prefix+'.body.bin.gz',result[32:]))
            assert gates==1
            filesystem.complete();row['mutations']=filesystem.events
            row['cache_after']=probes(process,metadata,output,prefix+'.cache-after')
            return row
        assert len(payload)>=64 and payload[:8]==b'HVCLIO01'
        gen,sequence,kind,slot,code,size,reserved=struct.unpack_from('<7Q',payload,8)
        assert kind in range(1,7) and reserved==0 and size==len(payload)-64
        if generation is None:generation=gen
        assert gen==generation>0 and sequence>previous_sequence
        previous_sequence=sequence;body=payload[64:];index=len(row['events'])
        event=dict(generation=gen,sequence=sequence,kind=kind,child_slot=slot,
                   child_return=code,payload_path=artifact(output,f'{prefix}.event-{index:02d}.bin.gz',payload))
        row['events'].append(event);action=0
        if kind==6:
            assert code in (0,1);gates+=1
            row.update(after_render_status=code,after_render_bytes=len(body),
                       after_render_path=artifact(output,prefix+'.after-render.bin.gz',body))
            if metadata['cancel_after_render']:action=1
        else:
            assert code==80 and slot==(3 if kind==5 else 1)
            name=base.EVENT_NAMES[kind];occurrence=counts.get(name,0)+1;counts[name]=occurrence
            row['io'].append(observation(kind,occurrence,body,path,output,
                            f'{prefix}.io-{len(row["io"]):02d}',metadata['domain']))
            before=len(filesystem.events);filesystem.hooks('after',name,occurrence)
            for mutation in filesystem.events[before:]:
                mutation['actual_gate']=dict(event=name,occurrence=occurrence,generation=gen,sequence=sequence)
        ack=struct.pack('<8s3Q',b'HVCLACK1',gen,sequence,action)
        event['ack_path']=artifact(output,f'{prefix}.ack-{index:02d}.bin.gz',ack)
        process.send(ack)

def main():
    started=time.monotonic()
    output=Path(os.environ['HIA_VIEW_SEARCH_CAPTURE_DIR']).resolve()
    output.mkdir(parents=True,exist_ok=False)
    manifest=Path(os.environ['HIA_VIEW_SEARCH_FIXTURE_MANIFEST']).resolve()
    reference_value=os.environ.get('HIA_VIEW_SEARCH_REFERENCE_ROOT')
    reference=Path(reference_value).resolve() if reference_value else None
    elf,pins=base.build_inputs(manifest)
    for path in (Path(__file__),Path(base.__file__),Path(support.__file__),Path(cases.__file__),
                 HERE/'view_call_oracle/cases.py'):
        pins[str(path.resolve())]=identity(path)
    originals=None;source=None;reference_report=None
    if reference:
        reference_report=json.loads((reference/'result.json').read_bytes())
        assert reference_report['independent_input']==EXPECTED_INPUT
        for name,key in (('input.bin','independent_input'),('original.stdout','original_output')):
            assert identity(reference/name)==reference_report[key]
            pins[str(reference/name)]=identity(reference/name)
        pins[str(reference/'result.json')]=identity(reference/'result.json')
        source=(reference/'original.stdout').open('rb')
        originals=cases.read_records(source,cases.OUTPUT_MAGIC)
    generated=hashlib.sha256(cases.INPUT_MAGIC+struct.pack('<Q',COUNT));generated_bytes=16
    rows=[];processes=[];failures=[];process=None;session=None;seen=0
    totals=dict(body_bytes=0,cache_bytes=0,read_snapshot_bytes=0,cancelled_base_bytes=0)
    def fail(where,error):
        item=dict(where=where,error=repr(error),traceback=traceback.format_exc())
        failures.append(item);print(json.dumps(item),file=sys.stderr,flush=True)
    def finish():
        nonlocal process
        if process is None:return
        current=process;process=None
        try:current.finish()
        except BaseException as error:fail(f'session-{session}:process',error)
        receipt=current.receipt
        try:receipt['observed_kernel_receipts']=base.receipt_counts(bytes(current.stderr))
        except BaseException as error:fail(f'session-{session}:kernel-receipts',error)
        processes.append(receipt);write_json(output/'processes.json',processes)
    try:
        for case in cases.iter_cases():
            metadata=case['metadata'];cid=metadata['case_id']
            assert cid==FIRST+seen;seen+=1
            encoded=cases.blob_record(metadata,case['blobs'])
            generated.update(encoded);generated_bytes+=len(encoded);del encoded
            original=next(originals) if originals is not None else None
            if original is not None:
                assert (original['metadata']['case_id'],original['metadata']['name'])==(cid,metadata['name'])
            if metadata['session']!=session:
                finish();session=metadata['session']
                directory=output/f'files-{session}';directory.mkdir()
                process=support.RecordedElf([elf,'--sync'],directory,output,f'session-{session}',timeout=60)
            filesystem=support.CaseFilesystem(directory,case);filesystem.setup()
            try:row=execute_case(process,case,filesystem,output)
            except BaseException as error:
                fail(f'case-{cid}:actual-protocol',error);break
            rows.append(row)
            with (output/'native-cases.jsonl').open('a') as stream:
                stream.write(json.dumps(row,sort_keys=True,ensure_ascii=False,allow_nan=False)+'\n')
            if original is not None:
                try:
                    for key,value in base.compare_observed(original,row,output).items():totals[key]+=value
                except BaseException as error:fail(f'case-{cid}:original-comparison',error)
        assert seen==COUNT
        if originals is not None:assert next(originals,None) is None
    except BaseException as error:fail('complete-original-stream',error)
    finally:
        finish()
        if source:source.close()
    try:
        assert len(rows)==COUNT and [row['case_id'] for row in rows]==list(range(FIRST,FIRST+COUNT))
        assert len(processes)==len({row['session'] for row in rows})==65
        assert dict(bytes=generated_bytes,sha256=generated.hexdigest())==EXPECTED_INPUT
        assert sum(row['domain']=='literal-search' for row in rows)==71
        assert sum(row['domain']=='whole-prime' for row in rows)==1
        shared=[row for row in rows if row['session']==20000]
        assert [row['case_id'] for row in shared]==list(range(10064,10072))
        assert sum(row['cancelled'] for row in rows)==1 and shared[3]['cancelled']
        assert {p:identity(p) for p in pins}==pins
    except BaseException as error:fail('complete-corpus-source-and-lifetime',error)
    kernel={}
    for process_receipt in processes:
        for key,value in process_receipt.get('observed_kernel_receipts',{}).items():
            kernel[key]=kernel.get(key,0)+value
    summary=dict(schema='hepta.runtime.view-search-native.v1',
        status='FAIL' if failures else 'NATIVE_COMPLETE_RUST_REPLAY_REQUIRED',
        groups=1,test_groups=1,errors=len(failures),failures=len(failures),skipped=0,
        requested_cases=COUNT,completed_cases=len(rows),
        literal_search_cases=sum(row['domain']=='literal-search' for row in rows),
        whole_preparation_cases=sum(row['domain']=='whole-prime' for row in rows),
        actual_elf_processes=len(processes),logical_io=sum(len(row['io']) for row in rows),
        actual_io_comparison=totals if reference else None,
        observed_output_bytes=dict(
            body_bytes=sum(row['body_bytes'] for row in rows),
            cache_bytes=sum(item['content_bytes'] for row in rows for field in ('cache_before','cache_after') for item in row[field]),
            read_snapshot_bytes=sum(item['native_reader']['snapshot_length'] for row in rows for item in row['io']),
            cancelled_base_bytes=sum(row['after_render_bytes'] for row in rows if row['cancelled'])),
        observed_kernel_receipts=kernel,
        successful=sum(row.get('ok') is True for row in rows),
        original_errors=sum(row.get('ok') is False for row in rows),
        after_render_cancelled=sum(row['cancelled'] for row in rows),
        common_cache_session=20000,unbound_context_kept_same_process=True,
        raw_read_magic='HVRDB001',raw_read_operation=5,
        pinned_inputs=pins,reference_report=str(reference/'result.json') if reference else None,
        independent_input=dict(bytes=generated_bytes,sha256=generated.hexdigest()),
        elapsed_seconds=time.monotonic()-started,new_rust_processes=0,
        public_mcp_route_replaced=False,regex_search_replaced=False,
        directory_search_replaced=False,alternative_path_search_replaced=False,
        whole_view_replaced=False,whole_runtime_replaced=False)
    write_json(output/'failures.json',failures);write_json(output/'result.json',summary)
    print(json.dumps(summary,sort_keys=True,allow_nan=False),flush=True)
    return bool(failures)

if __name__=='__main__':raise SystemExit(main())
