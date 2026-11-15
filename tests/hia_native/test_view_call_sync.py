#!/usr/bin/env python3
"""Actual synchronized caller. Original expectations are real Rust artifacts."""
from __future__ import annotations
import argparse, gzip, hashlib, importlib.util, json, os, stat, struct, sys, time, traceback
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result
support = module('_view_call_support', Path(__file__).with_name('test_view_call_support.py'))
cases = module('_view_call_input_cases', Path(__file__).with_name('view_call_oracle') / 'cases.py')
CANCELLED = 0xffffffcf
EVENT_NAMES = {1:'exists',2:'is_dir',3:'is_file',4:'metadata',5:'read'}
def artifact(output, name, raw):
    return support.save_gzip(output, name, raw)['path']
def captured(output, name):
    with gzip.open(output / name, 'rb') as source: return source.read()
def receive(process):
    length, = struct.unpack('<Q', process.read_exact(8))
    return process.read_exact(length)
def control(process, operation, value=0, payload=b''):
    process.send_frame(struct.pack('<8s3Q', b'HVCFIX01', operation, value, len(payload)) + payload)
    result = receive(process)
    assert len(result)>=32 and result[:8]==b'HVCFXR01'
    returned,status,size=struct.unpack_from('<3Q',result,8)
    assert returned==operation and status==0 and size==len(result)-32
    return result[32:]
def probes(process, metadata, output, prefix):
    result=[]
    for index,path_hex in enumerate(metadata['cache_probes']):
        raw=control(process,3,payload=bytes.fromhex(path_hex))
        assert len(raw)>=64 and raw[:8]==b'HRLKY001'
        status,key_size,zero=struct.unpack_from('<3Q',raw,8)
        assert status==1 and zero==0 and key_size<=len(raw)-64
        at=32+key_size; assert raw[at:at+8]==b'HVCAR001'
        found,size,zero=struct.unpack_from('<3Q',raw,at+8)
        assert found in (0,1) and zero==0 and size==len(raw)-at-32
        if not found: assert size==0
        result.append(dict(path_hex=path_hex,present=bool(found),content_bytes=size,
            probe_path=artifact(output,f'{prefix}-{index}.probe.bin.gz',raw),
            content_path=artifact(output,f'{prefix}-{index}.value.bin.gz',raw[at+32:]) if found else None))
    return result
def reader_result(raw):
    assert len(raw)>=80 and raw[:8]==b'HVRDR001'
    names=('generation','operation','outcome','errno','mode','metadata_size','snapshot_offset','snapshot_length','read_attempts')
    result=dict(zip(names,struct.unpack_from('<9Q',raw,8)))
    assert result['generation']>0 and result['operation'] in (1,2)
    assert result['outcome'] in (0,1,2,3) and 0<=result['errno']<=4095
    assert len(raw)==80+result['snapshot_length']
    if result['operation']!=2 or result['outcome']!=0:
        assert result['snapshot_offset']==result['snapshot_length']==0
    return result
def observation(kind, occurrence, body, path, output, prefix):
    # Diagnostic translations of retained typed I/O are separate from the
    # actual, complete user-visible error bytes received in HRCFGM01.
    result=reader_result(body); event=EVENT_NAMES[kind]
    assert result['operation']==(2 if kind==5 else 1)
    row=dict(event=event,occurrence=occurrence,
        reader_result_path=artifact(output,prefix+'.reader.bin.gz',body),native_reader=result)
    if kind<=3:
        value=result['outcome']==0
        if kind==2: value=value and stat.S_ISDIR(result['mode'])
        if kind==3: value=value and stat.S_ISREG(result['mode'])
        row.update(ok=True,value=value)
    elif result['outcome']!=0:
        shown=path.decode('utf-8',errors='replace')
        if result['outcome']==3:
            assert kind==5; detail='stream did not contain valid UTF-8'
        elif result['outcome']==2: detail='file name contained an unexpected NUL byte'
        else: detail=os.strerror(result['errno'])+f" (os error {result['errno']})"
        row.update(ok=False,error=f"Failed to {'read' if kind==5 else 'stat'} '{shown}': {detail}",
            error_text_origin='diagnostic translation of retained native typed outcome')
    elif kind==4:
        row.update(ok=True,size=result['metadata_size'],is_file=stat.S_ISREG(result['mode']),is_dir=stat.S_ISDIR(result['mode']))
    else: row.update(ok=True,snapshot_path=artifact(output,prefix+'.snapshot.bin.gz',body[80:]))
    return row

def execute_case(process, case, filesystem, output, *, wire_override=None, original_input_override=None):
    metadata=case['metadata']; cid=metadata['case_id']; prefix=f'case-{cid:03d}'
    path=bytes.fromhex(metadata['path_hex'])
    displayed=path.decode('utf-8',errors='replace').encode('utf-8') if metadata['raw_path'] else path
    displayed.decode('utf-8')
    wire=support.call_frame(displayed,path,metadata['params']) if wire_override is None else wire_override
    if metadata['raw_path']:
        assert wire_override is None
        wire=b'HVCPI001'+wire[8:]
    row=dict(case_id=cid,name=metadata['name'],session=metadata['session'],
        domain='raw_path_source_private' if metadata['raw_path'] else 'public_prelude_fixture',
        cancelled=False,input_path=artifact(output,prefix+'.input.bin.gz',
            cases.encode_cases([case]) if original_input_override is None else original_input_override),
        call_path=artifact(output,prefix+'.call.bin.gz',wire),io=[],events=[],
        cache_before=[],cache_after=[],cache_observations_complete=True)
    assert control(process,1,int(metadata['context']))==b''
    if metadata['reset_cache']: assert control(process,2)==b''
    row['cache_before']=probes(process,metadata,output,prefix+'.cache-before')
    process.send_frame(wire)
    counts={}; previous_sequence=0; generation=None; render_gates=0; next_observation=None
    while True:
        payload=receive(process)
        if payload[:8]==b'HVCLOR01':
            assert len(payload)>=32
            code,size,reserved=struct.unpack_from('<3Q',payload,8)
            assert reserved==0 and size==len(payload)-32
            row['native_return']=code; row['result_path']=artifact(output,prefix+'.result.bin.gz',payload)
            if code==CANCELLED:
                assert metadata['cancel_after_render'] and size==0 and render_gates==1
                row.update(cancelled=True,body_bytes=0,body_path=artifact(output,prefix+'.body.bin.gz',b''))
            else:
                result=payload[32:]
                assert code==size==len(result) and size>=32 and result[:8]==b'HRCFGM01',(cid,code,size)
                status,zero,text_size=struct.unpack_from('<3Q',result,8)
                assert status in (0,1) and zero==0 and text_size==size-32
                result[32:].decode('utf-8')
                row.update(ok=status==0,body_bytes=text_size,body_path=artifact(output,prefix+'.body.bin.gz',result[32:]))
            assert render_gates==1 and next_observation is None
            filesystem.complete(); row['mutations']=filesystem.events
            row['cache_after']=probes(process,metadata,output,prefix+'.cache-after')
            return row
        assert payload[:8]==b'HVCLIO01' and len(payload)>=64
        gen,sequence,kind,slot,code,size,reserved=struct.unpack_from('<7Q',payload,8)
        assert kind in range(1,7) and reserved==0 and size==len(payload)-64
        if generation is None: generation=gen
        assert generation==gen>0 and sequence>previous_sequence
        previous_sequence=sequence; body=payload[64:]; event_index=len(row['events'])
        event=dict(generation=gen,sequence=sequence,kind=kind,child_slot=slot,child_return=code,
            payload_path=artifact(output,f'{prefix}.event-{event_index:02d}.bin.gz',payload))
        row['events'].append(event); action=0
        if kind==6:
            assert code in (0,1)
            render_gates+=1; row['after_render_status']=code; row['after_render_bytes']=len(body)
            row['after_render_path']=artifact(output,prefix+'.after-render.bin.gz',body)
            if metadata['cancel_after_render']: action=1
        else:
            assert code==80 and slot in ((2,3) if kind==5 else (1,))
            name=EVENT_NAMES[kind]; occurrence=counts.get(name,0)+1; counts[name]=occurrence
            if next_observation is not None:
                assert (name,occurrence)==next_observation
                next_observation=None
            row['io'].append(observation(kind,occurrence,body,path,output,f'{prefix}.io-{len(row["io"]):02d}'))
            before=len(filesystem.events); filesystem.hooks('after',name,occurrence)
            for mutation in filesystem.events[before:]:
                mutation['actual_gate']=dict(event=name,occurrence=occurrence,generation=gen,sequence=sequence)
            # The sole before-metadata hook uses the preceding is_dir ACK;
            # require no intervening filesystem operation in the real trace.
            if (name,occurrence)==('is_dir',1):
                hooks=[h for h in metadata['hooks'] if h['when']=='before']
                if hooks:
                    assert len(hooks)==1 and (hooks[0]['event'],hooks[0]['occurrence'])==('metadata',1)
                    before=len(filesystem.events); filesystem.hooks('before','metadata',1)
                    for mutation in filesystem.events[before:]:
                        mutation['actual_gate']=dict(event=name,occurrence=occurrence,generation=gen,
                            sequence=sequence,next_observation=['metadata',1])
                    next_observation=('metadata',1)
        ack=struct.pack('<8s3Q',b'HVCLACK1',gen,sequence,action)
        event['ack_path']=artifact(output,f'{prefix}.ack-{event_index:02d}.bin.gz',ack)
        process.send(ack)

def compare_observed(original, native, output):
    meta, blobs = original['metadata'], original['blobs']; cid = meta['case_id']
    def equal(actual, expected, what):
        if actual != expected:
            if isinstance(actual, bytes) and isinstance(expected, bytes):
                first = next((i for i, pair in enumerate(zip(actual, expected)) if pair[0] != pair[1]), min(len(actual), len(expected)))
                raise AssertionError((cid, what, 'byte mismatch', len(actual), len(expected), first,
                                      actual[max(0,first-40):first+100], expected[max(0,first-40):first+100]))
            raise AssertionError((cid, what, actual, expected))
    outcome = meta['outcome']; cancelled = bool(outcome.get('cancelled'))
    assert type(native['cancelled']) is bool
    equal(native['cancelled'], cancelled, 'cancelled')
    counts = dict(body_bytes=0, cache_bytes=0, read_snapshot_bytes=0, cancelled_base_bytes=0)
    actual = captured(output, native['body_path'])
    if cancelled:
        equal(actual, b'', 'cancel publishes no result')
        before = meta['before_cancel']; equal(native['after_render_status'], 0 if before['ok'] else 1, 'cancel gate status')
        expected = blobs[before['blob']] if before['ok'] else before['error'].encode()
        equal(captured(output, native['after_render_path']), expected, 'complete result before actual cancel')
        counts['cancelled_base_bytes'] += len(expected)
    else:
        assert type(native['ok']) is bool
        equal(native['ok'], outcome['ok'], 'outcome status')
        equal(actual, blobs[outcome['blob']], 'complete visible body')
        counts['body_bytes'] += len(actual)
    for name in ('cache_before', 'cache_after'):
        equal(len(native[name]), len(meta[name]), name+' count')
        for actual, expected in zip(native[name], meta[name]):
            equal(actual['path_hex'], expected['path_hex'], name+' path')
            assert type(actual['present']) is bool
            equal(actual['present'], expected['present'], name+' presence')
            if expected['present']:
                raw = captured(output, actual['content_path'])
                equal(raw, blobs[expected['blob']], name+' complete value')
                counts['cache_bytes'] += len(raw)
            else: equal(actual['content_path'], None, name+' absent payload')
    expected_io = [row for row in meta['events'] if row['kind']=='io']
    equal(len(native['io']), len(expected_io), 'logical I/O count')
    for index, (actual, expected) in enumerate(zip(native['io'], expected_io)):
        equal(actual['event'], expected['event'], f'I/O {index} kind')
        equal(actual['occurrence'], expected['occurrence'], f'I/O {index} occurrence')
        result = expected['result']
        for key in ('ok', 'value', 'size', 'is_file', 'is_dir', 'error'):
            if key in result:
                assert type(actual[key]) is type(result[key])
                equal(actual[key], result[key], f'I/O {index} {key}')
        if 'snapshot_blob' in result:
            raw = captured(output, actual['snapshot_path'])
            equal(raw, blobs[result['snapshot_blob']], f'I/O {index} complete snapshot')
            counts['read_snapshot_bytes'] += len(raw)
    return counts

def identity(path):
    digest=hashlib.sha256(); size=0
    with Path(path).open('rb') as stream:
        while block:=stream.read(1<<20): digest.update(block); size+=len(block)
    return dict(bytes=size,sha256=digest.hexdigest())
def write_json(path,value):
    path.write_text(json.dumps(value,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n')
def build_inputs(manifest_path):
    manifest=json.loads(manifest_path.read_text()); build=manifest_path.parent.parent
    elf=manifest_path.parent/manifest['elf']; raw=elf.read_bytes()
    assert support.sha(raw)==manifest['elf_sha256']
    paths={str(manifest_path):identity(manifest_path),str(elf):identity(elf)}
    assert len(manifest['members'])==len(manifest['image_offsets'])
    for member,offset in zip(manifest['members'],manifest['image_offsets']):
        path=build/member['manifest']; module=json.loads(path.read_text())
        assert identity(path)['sha256']==member['manifest_sha256']
        for field in ('source','image'):
            p=path.parent/module[field]; item=identity(p)
            assert item['sha256']==module[field+'_sha256']==member[field+'_sha256']
            paths[str(p)]=item
            if field=='image': assert raw[offset:offset+item['bytes']]==p.read_bytes()
        paths[str(path)]=identity(path)
    packer=build/manifest['packer_manifest']; assert identity(packer)['sha256']==manifest['packer_manifest_sha256']
    paths[str(packer)]=identity(packer)
    return elf,paths

def receipt_counts(raw):
    assert len(raw)%128==0
    result=dict(reader_effects=0,key_effects=0,stat_attempts=0,open_attempts=0,
                read_attempts=0,close_attempts=0,read_bytes=0)
    for at in range(0,len(raw),128):
        receipt=raw[at:at+128]
        if receipt[:8]==b'HFLKEYFX': result['key_effects']+=1; continue
        assert receipt[:8]==b'HVRDACK1'
        seq,gen,kind,a,b,c,d,actual,normalized,errno,mode,size,before,after,completed=struct.unpack_from('<15Q',receipt,8)
        assert seq==completed>0 and gen>0 and kind in (1,2,3,4)
        result['reader_effects']+=1
        result[{1:'stat_attempts',2:'open_attempts',3:'read_attempts',4:'close_attempts'}[kind]]+=1
        signed=actual if actual<1<<63 else actual-(1<<64)
        assert -4095<=signed
        if signed<0: assert errno==-signed and normalized==actual
        elif kind==2: assert errno==0 and normalized==0
        else: assert errno==0 and normalized==actual
        if kind==3 and signed>=0:
            assert signed<=65536; result['read_bytes']+=signed
    return result

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    choice=parser.add_mutually_exclusive_group()
    choice.add_argument('--public-subset',action='store_true',
                        help='explicit development run of the 56 public-prelude original cases')
    choice.add_argument('--complete-original-domain',action='store_true',
                        help='56 public-prelude and two separate private Unix PathSource cases')
    args=parser.parse_args()
    output=Path(os.environ['HIA_VIEW_CALL_CAPTURE_DIR']).resolve(); output.mkdir(parents=True,exist_ok=False)
    manifest=Path(os.environ['HIA_VIEW_CALL_FIXTURE_MANIFEST']).resolve()
    reference_location=os.environ.get('HIA_VIEW_CALL_REFERENCE_ROOT')
    reference=Path(reference_location).resolve() if reference_location else None
    elf,pins=build_inputs(manifest)
    for path in (Path(__file__),Path(support.__file__),Path(cases.__file__)):
        pins[str(path.resolve())]=identity(path)
    if reference:
        reference_report=json.loads((reference/'result.json').read_text())
        for name,key in (('input.bin','independent_input'),('original.stdout','original_output')):
            assert identity(reference/name)==reference_report[key]
            pins[str(reference/name)]=identity(reference/name)
    source=(reference/'original.stdout').open('rb') if reference else None
    originals=cases.read_records(source,cases.OUTPUT_MAGIC) if source else None
    expected_count=56 if args.public_subset else 58
    generated_input=hashlib.sha256(cases.INPUT_MAGIC+struct.pack('<Q',58))
    generated_bytes=16; selected_ids=[]; original_count=0
    rows=[]; processes=[]; failures=[]; process=None; session=None
    totals=dict(body_bytes=0,cache_bytes=0,read_snapshot_bytes=0,cancelled_base_bytes=0)
    def failure(where,error):
        record=dict(where=where,error=repr(error),traceback=traceback.format_exc())
        failures.append(record); print(json.dumps(record,ensure_ascii=False),file=sys.stderr,flush=True)
    def finish_current():
        nonlocal process
        if process is None: return
        current=process; process=None
        try: current.finish()
        except BaseException as error: failure(f'session-{session}:process',error)
        receipt=current.receipt
        try: receipt['observed_kernel_receipts']=receipt_counts(bytes(current.stderr))
        except BaseException as error: failure(f'session-{session}:kernel-receipts',error)
        processes.append(receipt)
        write_json(output/'processes.json',processes)
    try:
        for case in cases.iter_cases():
            metadata=case['metadata']; cid=metadata['case_id']
            encoded=cases.blob_record(metadata,case['blobs'])
            generated_input.update(encoded); generated_bytes+=len(encoded); del encoded
            assert cid==original_count;original_count+=1
            if originals:
                original=next(originals)
                assert (original['metadata']['case_id'],original['metadata']['name'])==(cid,metadata['name'])
            if metadata['raw_path'] and args.public_subset: continue
            selected_ids.append(cid)
            if metadata['session']!=session:
                finish_current(); session=metadata['session']
                directory=output/f'files-{session}'; directory.mkdir()
                process=support.RecordedElf([elf,'--sync'],directory,output,f'session-{session}',timeout=60)
            filesystem=support.CaseFilesystem(directory,case); filesystem.setup()
            try: row=execute_case(process,case,filesystem,output)
            except BaseException as error:
                failure(f'case-{cid}:actual-protocol',error); break
            rows.append(row)
            with (output/'native-cases.jsonl').open('a') as stream:
                stream.write(json.dumps(row,sort_keys=True,ensure_ascii=False,allow_nan=False)+'\n')
            try:
                if originals:
                    counts=compare_observed(original,row,output)
                    for key,value in counts.items(): totals[key]+=value
            except BaseException as error: failure(f'case-{cid}:original-comparison',error)
        assert original_count==58
        if originals:
            assert next(originals,None) is None
            assert dict(bytes=generated_bytes,sha256=generated_input.hexdigest())==reference_report['independent_input']
    except BaseException as error: failure('complete-original-stream',error)
    finally:
        finish_current()
        if source:source.close()
    try:
        assert len(rows)==expected_count and [row['case_id'] for row in rows]==selected_ids
        assert len(processes)==len({row['session'] for row in rows})
        assert {path:identity(path) for path in pins}==pins
    except BaseException as error: failure('complete-corpus-and-input-pins',error)
    kernel={}
    for receipt in processes:
        for key,value in receipt.get('observed_kernel_receipts',{}).items(): kernel[key]=kernel.get(key,0)+value
    observed=dict(body_bytes=sum(row['body_bytes'] for row in rows),
        cache_bytes=sum(item['content_bytes'] for row in rows for name in ('cache_before','cache_after') for item in row[name]),
        read_snapshot_bytes=sum(item['native_reader']['snapshot_length'] for row in rows for item in row['io']),
        cancelled_base_bytes=sum(row['after_render_bytes'] for row in rows if row['cancelled']))
    summary=dict(schema='hepta.runtime.view-call-native.v1',
        groups=1,
        status='FAIL' if failures else 'NATIVE_COMPLETE_RUST_REPLAY_REQUIRED',requested_cases=expected_count,completed_cases=len(rows),
        public_prelude_cases=sum(row['domain']=='public_prelude_fixture' for row in rows),
        raw_path_source_cases=sum(row['domain']=='raw_path_source_private' for row in rows),
        full_58_case_domain_complete=len(rows)==58 and not failures,
        actual_elf_processes=len(processes),actual_io_comparison=totals if reference else None,
        observed_output_bytes=observed,observed_kernel_receipts=kernel,
        after_render_cancelled=sum(row['cancelled'] for row in rows),
        common_cache_session=1000,unbound_context_kept_same_process=True,
        pinned_inputs=pins,reference_report=str(reference/'result.json') if reference else None,
        independent_input=dict(bytes=generated_bytes,sha256=generated_input.hexdigest()),
        failures=len(failures),public_mcp_route_replaced=False,whole_view_replaced=False,whole_runtime_replaced=False)
    write_json(output/'failures.json',failures); write_json(output/'result.json',summary)
    print(json.dumps(summary,sort_keys=True,ensure_ascii=False,allow_nan=False),flush=True)
    return bool(failures)

if __name__=='__main__': raise SystemExit(main())
