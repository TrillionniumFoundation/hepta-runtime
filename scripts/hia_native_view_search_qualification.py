"""Strict native search evidence; no HIA or Rust execution occurs here.

The reader binds all 72 logical inputs to complete actual ELF streams and
kernel receipts, plus the exact ten-image composition and B3 compile records.
Original method equivalence is admitted by the separate reference consumer.
Live test files can be archived/removed after execution; no fixture is read.
"""
from __future__ import annotations
from collections import Counter
import gzip,hashlib,io,json,os,re,stat,struct,sys
from pathlib import Path
import hia_native_view_call_qualification as base
from hia_native_view_call_qualification import (
 Evidence,require,integer,duration,canonical,same,json_value,digest,pin,inside,
 load_module,exact_read,frame,eof,_module,_event,_cache,_control,_process,_kernel,
 MEMBERS,SLOTS,READER_FIELDS,EVENTS,CANCELLED,
)
NATIVE_SUITE='test_view_search.py'
EVIDENCE_SUITE='test_view_search_native_evidence.py'
EXPECTED_INPUT=dict(bytes=47345844,sha256='1b2f8661ee9fde9b1a362a8a866a921645c36dbc5d821f916e91183c34b59742')
BOUNDARIES=('scripts/view_call_adapter.S','scripts/view_call_fixture_controls.S','scripts/view_call_engine.S',
 'scripts/view_call_read_bridge.S','scripts/view_call_key_bridge.S','scripts/view_call_scope_bridge.S')
CONTROLS=tuple(sorted(('check-command','check-bool-exit','check-timeout-budget','check-timed-out',
 'check-nonfinite-elapsed','check-duplicate','module-image','compiler-output',
 'process-stdin-gzip','logical-operation','event-ack-gzip','native-case-omitted')))

def _object_prefix(evidence, folder, prefix, proof):
    same(sorted(proof['sources']),sorted(BOUNDARIES),'fixed boundary source inventory')
    combined='\n'.join((evidence.root/name).read_text() for name in BOUNDARIES)
    exports=re.findall(r'^\.global ([A-Za-z_][A-Za-z_0-9]*)$',combined,re.M)
    for name in exports:
        if name=='_start':continue
        alias=name+'_flat'
        if '\n'+alias+':' not in combined:combined=combined.replace('\n'+name+':','\n'+name+':\n'+alias+':')
        combined=re.sub(r'\b(call|jmp) '+re.escape(name)+r'\b',lambda m:m[1]+' '+alias,combined)
        combined=combined.replace('[rip + '+name+']','[rip + '+alias+']')
    require(evidence.raw(folder/'combined.S')==combined.encode(),'assembled source is not the exact six current boundaries')
    raw=evidence.raw(folder/'adapter.o')
    require(len(raw)>=64 and raw[:6]==b'\x7fELF\x02\x01','assembler object is not little-endian ELF64')
    require(struct.unpack_from('<HH',raw,16)==(1,62),'assembler object type/machine')
    offset=struct.unpack_from('<Q',raw,40)[0]
    width,count,strings=struct.unpack_from('<HHH',raw,58)
    require(width==64 and count>0 and strings<count and offset<=len(raw)-64*count,'object section table')
    sections=[struct.unpack_from('<IIQQQQIIQQ',raw,offset+i*64) for i in range(count)]
    def payload(index):
        require(0<=index<count,'object section index')
        item=sections[index];at,size=item[4:6]
        require(at<=len(raw) and size<=len(raw)-at,'object section extent')
        return raw[at:at+size]
    names=payload(strings)
    def string(table,index):
        require(index<len(table),'object string offset')
        end=table.find(b'\0',index);require(end>=index,'unterminated object string')
        return table[index:end].decode('ascii')
    by_name={}
    for index,item in enumerate(sections):
        name=string(names,item[0])
        if name:require(name not in by_name,'duplicate object section');by_name[name]=index
        if item[1] in (4,9):require(item[5]==0,'unresolved object relocation')
    require('.text' in by_name and '.symtab' in by_name,'missing assembler code/symbol table')
    text_index=by_name['.text'];text=payload(text_index)
    require(sections[text_index][1]==1 and sections[text_index][2]==6,'unexpected text section type/permissions')
    require(text==evidence.raw(folder/'adapter.bin')==prefix[176:],'object code differs from actual ELF prefix')
    index=by_name['.symtab'];item=sections[index];table=payload(index)
    require(item[9]==24 and len(table)%24==0,'object symbol entry size')
    names=payload(item[6]);symbols={}
    for at in range(0,len(table),24):
        name,info,other,section,value,size=struct.unpack_from('<IBBHQQ',table,at)
        if not name or section!=text_index:continue
        name=string(names,name)
        require(value<=len(text),'symbol beyond code')
        require(name not in symbols,'duplicate object symbol')
        symbols[name]=value
    same(proof['callable_symbols'],{name:176+symbols[name] for name in exports},'callable object/source symbols')
    require(proof['table_offset']==176+symbols['view_image_table'],'actual private image table')
    require(prefix[:16]==b'\x7fELF\x02\x01\x01'+bytes(9),'ELF identity')
    require(struct.unpack_from('<HHIQQQIHHHHHH',prefix,16)==(2,62,1,0x4000b0,64,0,0,64,56,2,0,0,0),'closed ELF header')
    require(struct.unpack_from('<IIQQQQQQ',prefix,64)==(1,5,0,0x400000,0x400000,0,0,4096),'closed RX load segment')
    require(struct.unpack_from('<IIQQQQQQ',prefix,120)==(0x6474e551,6,0,0,0,0,0,16),'non-executable stack header')

def _raw_reader_result(raw):
    require(len(raw)>=80 and raw[:8]==b'HVRDR001','reader result magic/length')
    result=dict(zip(READER_FIELDS,struct.unpack_from('<9Q',raw,8)))
    require(result['generation']>0 and result['operation'] in (1,2,5),'reader generation/operation')
    require(result['outcome'] in ((0,1,2) if result['operation']==5 else (0,1,2,3)) and result['errno']<=4095,'reader outcome/errno')
    require(len(raw)==80+result['snapshot_length'],'complete raw read snapshot extent')
    if result['operation']==1 or result['outcome']!=0:
        require(result['snapshot_offset']==result['snapshot_length']==0,'failed/stat snapshot exposure')
    else:
        require(result['snapshot_offset']==8192,'owned snapshot start')
        if result['operation']==2:raw[80:].decode('utf-8')
    return result

def request(case,support):
    meta=case['metadata'];path=bytes.fromhex(meta['path_hex']);path.decode('utf-8')
    require(meta['raw_path'] is False,'unexpected private raw-path domain')
    if meta['domain']=='whole-prime':
        require(meta['case_id']==10064,'unexpected whole preparation')
        return support.call_frame(path,path,meta['params'])
    require(meta['domain']=='literal-search' and meta['params']['regex'] is False,'non-literal search case')
    content=meta['params']['content'].encode();context=integer(meta['params']['context'],'typed context')
    return struct.pack('<8s7Q',b'HVCSQ001',4 if meta['params'].get('full',False) else 0,len(path),len(path),len(content),context,0,0)+path+path+content


def _caller_build(evidence, manifest_path):
    caller = evidence.json(manifest_path); build = manifest_path.parent.parent
    require(caller.get('schema') == 'hepta.runtime.view-call-build.v1', 'caller manifest schema')
    same(caller.get('slot_image_indices'), SLOTS, 'closed caller slot table')
    same(len(caller.get('members', [])), 10, 'caller image count')
    same(len(caller.get('image_offsets', [])), 10, 'caller image offsets')
    elf_path = evidence.path(caller['elf'], manifest_path.parent); elf = evidence.raw(elf_path)
    require(digest(elf) == caller['elf_sha256'], 'caller ELF identity')
    proof = json_value((evidence.root / 'native/view_call_adapter.json').read_bytes())
    evidence.source('native/view_call_adapter.json')
    same(caller['sources'], proof['sources'], 'boundary source set')
    for source, sha in caller['sources'].items(): require(evidence.source(source)['sha256'] == sha, 'boundary source changed')
    for key in ('prefix_bytes', 'prefix_sha256', 'table_offset'): same(caller[key], proof[key], 'boundary ' + key)
    size, table = integer(caller['prefix_bytes'], 'prefix bytes', 176), integer(caller['table_offset'], 'slot offset', 176)
    require(table + 96 <= size <= len(elf), 'prefix/slot containment')
    prefix = bytearray(elf[:size]); require(struct.unpack_from('<2Q', prefix, 96) == (len(elf), len(elf)), 'ELF extent')
    prefix[96:112] = bytes(16); prefix[table:table + 96] = bytes(96)
    require(digest(prefix) == proof['prefix_sha256'], 'actual ELF prefix/source proof')
    end = size; images = []
    for (name, source), member, offset in zip(MEMBERS, caller['members'], caller['image_offsets']):
        same(member['name'], name, 'member order'); same(member['source'], 'native/' + source + '.hepta', 'member source')
        metadata, image = _module(evidence, evidence.path(member['manifest'], build), member['source'], expected=member)
        integer(offset, 'image offset'); padded = end + (-end) % 16
        require(offset == padded and elf[end:offset] == bytes(offset - end), 'image alignment/padding')
        require(elf[offset:offset + len(image)] == image, 'actual ELF embedded HIA image')
        end = offset + len(image); images.append(image)
    require(end == len(elf), 'trailing caller ELF payload')
    same(list(struct.unpack_from('<12Q', elf, table)), [0x400000 + caller['image_offsets'][i] for i in SLOTS], 'actual ELF slot addresses')
    packer = evidence.path(caller['packer_manifest'], build)
    require(evidence.file(packer)['sha256'] == caller['packer_manifest_sha256'], 'caller packer manifest')
    _module(evidence, packer, 'native/view_call_packer.hepta')
    _object_prefix(evidence, manifest_path.parent, bytes(prefix), proof)
    require(caller['fixed_total_read_limit'] is None, 'invented search read quota')
    for flag in ('whole_view_replaced','whole_runtime_replaced','public_mcp_route_replaced'):
        require(caller[flag] is False, 'component fixture scope inflated')
    for source in ('scripts/hia_native_view_call_build.py','scripts/hia_native_loader.py'):
        evidence.source(source)
    return dict(manifest=manifest_path,elf=elf_path,build=build,members=caller['members'],packer=packer)


def _literal_case(evidence, folder, row, case, stdin, stdout, expected_wire, expected_input):
    meta = case['metadata']; cid = meta['case_id']; path = bytes.fromhex(meta['path_hex'])
    same(row['domain'],meta['domain'],'literal/whole-prime domain')
    for key in ('case_id', 'name', 'session'): same(row[key], meta[key], 'case identity ' + key)
    require(evidence.zipped(folder, row['input_path']) == expected_input, 'complete original logical input differs')
    require(evidence.zipped(folder, row['call_path']) == expected_wire, 'actual HIA request differs from original input/projection')
    require(row['cache_observations_complete'] is True, 'incomplete cache observation flag')
    require(_control(stdin, stdout, 1, int(meta['context'])) == b'', 'context selection payload')
    if meta['reset_cache']: require(_control(stdin, stdout, 2, 0) == b'', 'cache reset payload')
    counts = dict(body_bytes=0, cache_bytes=0, read_snapshot_bytes=0, cancelled_base_bytes=0)
    counts['cache_bytes'] += _cache(evidence, folder, meta, row['cache_before'], stdin, stdout)
    require(frame(stdin) == expected_wire, 'actual stdin does not contain the exact RUN frame')
    previous = 0; generation = None; logical = []; occurrence = Counter(); gates = 0; io_index = 0
    event_gates = {}
    for saved in row['events']:
        payload = frame(stdout); ack = exact_read(stdin, 32)
        require(payload == evidence.zipped(folder, saved['payload_path']) and ack == evidence.zipped(folder, saved['ack_path']),
                'event/ACK artifact differs from actual complete process streams')
        fields, body = _event(payload, ack, previous, generation, meta['cancel_after_render'])
        for key, value in fields.items(): same(saved[key], value, 'saved logical ' + key)
        previous, generation = fields['sequence'], fields['generation']; kind = fields['kind']
        if kind == 6:
            gates += 1; require(gates == 1 and saved is row['events'][-1], 'render gate must be unique and last')
            require(body == evidence.zipped(folder, row['after_render_path']), 'complete render gate body')
            same(row['after_render_bytes'], len(body), 'render gate body length')
            same(row['after_render_status'], fields['child_return'], 'render gate status')
        else:
            require(gates == 0, 'I/O after render gate')
            result = _raw_reader_result(body)
            operation = (5 if meta['domain']=='literal-search' else 2) if kind==5 else 1
            require(result['operation'] == operation, 'reader/logical search operation')
            observation = row['io'][io_index]; io_index += 1; occurrence[EVENTS[kind]] += 1
            same(observation['event'], EVENTS[kind], 'I/O name'); same(observation['occurrence'], occurrence[EVENTS[kind]], 'I/O occurrence')
            same(observation['operation'], result['operation'], 'declared operation from actual header')
            same(observation['native_reader'], result, 'complete typed reader result')
            require(evidence.zipped(folder, observation['reader_result_path']) == body, 'retained reader bytes')
            if kind <= 3:
                value = result['outcome'] == 0
                if kind == 2: value = value and stat.S_ISDIR(result['mode'])
                if kind == 3: value = value and stat.S_ISREG(result['mode'])
                same(observation['ok'], True, 'boolean I/O result'); same(observation['value'], value, 'boolean I/O value')
            else:
                same(observation['ok'], result['outcome'] == 0, 'I/O success')
                if result['outcome'] == 0 and kind == 4:
                    for key, value in (('size', result['metadata_size']), ('is_file', stat.S_ISREG(result['mode'])), ('is_dir', stat.S_ISDIR(result['mode']))):
                        same(observation[key], value, 'metadata ' + key)
                if result['outcome'] == 0 and kind == 5:
                    require(evidence.zipped(folder, observation['snapshot_path']) == body[80:], 'complete successful read snapshot')
            logical.append((fields['child_slot'], result, len(path)))
            counts['read_snapshot_bytes'] += result['snapshot_length']
            event_gates[(EVENTS[kind], occurrence[EVENTS[kind]])] = (generation, previous)
    require(gates == 1 and io_index == len(row['io']), 'render/I/O count')
    result = frame(stdout); require(result == evidence.zipped(folder, row['result_path']), 'actual final response bytes')
    require(len(result) >= 32 and result[:8] == b'HVCLOR01', 'final response header')
    code, size, zero = struct.unpack_from('<3Q', result, 8)
    require(zero == 0 and size == len(result) - 32, 'final response extent')
    same(row['native_return'], code, 'final native return'); same(row['cancelled'], meta['cancel_after_render'], 'actual cancellation')
    body = evidence.zipped(folder, row['body_path']); same(row['body_bytes'], len(body), 'complete published body length')
    if meta['cancel_after_render']:
        require(code == CANCELLED and size == len(body) == 0, 'cancel published output')
        counts['cancelled_base_bytes'] = row['after_render_bytes']
    else:
        require(code == size >= 32 and result[32:40] == b'HRCFGM01', 'final owner response')
        status, reserved, length = struct.unpack_from('<3Q', result, 40)
        require(status in (0, 1) and reserved == 0 and length == len(body) == size - 32 and body == result[64:], 'actual complete visible body')
        body.decode('utf-8'); same(row['ok'], status == 0, 'visible result status'); counts['body_bytes'] = len(body)
        require(body == evidence.zipped(folder,row['after_render_path']), 'literal/prime gate body changed before publication')
        same(row['after_render_status'],status,'gate status changed before publication')
    counts['cache_bytes'] += _cache(evidence, folder, meta, row['cache_after'], stdin, stdout)
    require(len(row['mutations']) == len(meta['hooks']), 'missing actual filesystem mutation hook')
    for mutation, hook in zip(row['mutations'], meta['hooks']):
        require(mutation['when'] == hook['when'] and mutation['event'] == hook['event'] and mutation['occurrence'] == hook['occurrence'], 'mutation hook identity')
        same(mutation['actions'], hook['actions'], 'complete filesystem mutation actions')
        gate = mutation['actual_gate']; key = (gate['event'], gate['occurrence'])
        require(event_gates.get(key) == (gate['generation'], gate['sequence']), 'mutation not at observed ACK gate')
        if hook['when'] == 'before':
            same((gate['event'], gate['occurrence'], gate.get('next_observation')), ('is_dir', 1, ['metadata', 1]), 'before-metadata synchronization')
            names = [(x['event'], x['occurrence']) for x in row['io']]
            require(names[names.index(key) + 1] == ('metadata', 1), 'I/O intervened before metadata mutation')
        else: same(key, (hook['event'], hook['occurrence']), 'after-I/O mutation synchronization')
    return counts, logical


def _corpus(evidence,folder,summary,elf):
    cases=load_module('literal_input',evidence.root/'tests/hia_native/view_search_oracle/cases.py')
    support=load_module('literal_support',evidence.root/'tests/hia_native/test_view_call_support.py')
    rows=evidence.rows(folder/'native-cases.jsonl');processes=evidence.json(folder/'processes.json')
    require(len(rows)==72 and len(processes)==65,'complete literal native case/process inventory')
    same(evidence.json(folder/'failures.json'),[],'native search failures')
    totals=Counter();kernel=Counter();process_at=0;current=None;logical=[];streams=None;generation_by_context={}
    generated=hashlib.sha256(cases.INPUT_MAGIC+struct.pack('<Q',72));generated_size=16;seen=0
    def finish():
        nonlocal logical
        if streams is None:return
        eof(stdin);eof(stdout)
        values=_kernel(streams['stderr'],logical)
        same(values,process['observed_kernel_receipts'],'complete actual kernel receipt recount')
        kernel.update(values);logical=[]
    for case in cases.iter_cases():
        meta=case['metadata'];row=rows[seen];require(meta['case_id']==10000+seen,'case ID order');seen+=1
        same(row['domain'],meta['domain'],'case domain')
        record=cases.blob_record(meta,case['blobs']);generated.update(record);generated_size+=len(record)
        if current!=meta['session']:
            finish();process=processes[process_at];process_at+=1;current=meta['session'];generation_by_context={}
            same(process['name'],'session-'+str(current),'actual native session identity')
            require(evidence.rebase(process['cwd'])==folder/('files-'+str(current)),'native fixture working directory')
            streams=_process(evidence,folder,process,elf,60)
            stdin,stdout=io.BytesIO(streams['input']),io.BytesIO(streams['stdout'])
        values,observations=_literal_case(evidence,folder,row,case,stdin,stdout,request(case,support),cases.encode_cases([case]))
        context=meta['context'];require(type(context) is bool,'bound scope selector type')
        generation=row['events'][0]['generation']
        require(generation==generation_by_context.get(context,0)+1,'independent bound/unbound generation')
        generation_by_context[context]=generation
        totals.update(values);logical.extend(observations)
    finish()
    require(seen==len(rows)==72 and process_at==len(processes)==65,'extra/missing complete search input or process')
    actual=dict(bytes=generated_size,sha256=generated.hexdigest())
    same(actual,EXPECTED_INPUT,'independent literal input corpus');same(summary['independent_input'],actual,'producer input digest')
    same(summary['observed_output_bytes'],dict(totals),'complete search output recount')
    same(summary['observed_kernel_receipts'],dict(kernel),'complete kernel output recount')
    same([row['case_id'] for row in rows if row['session']==20000],list(range(10064,10072)),'shared real cache session domain')
    same([row['case_id'] for row in rows if row['cancelled']],[10067],'actual after-gate cancellation')
    observed={'successful':sum(row.get('ok') is True for row in rows),'original_errors':sum(row.get('ok') is False for row in rows),
              'logical_io':sum(len(row['io']) for row in rows)}
    same(observed,dict(successful=58,original_errors=13,logical_io=401),'complete observed outcome/I/O inventory')
    for name,value in observed.items():same(summary[name],value,'native summary '+name)
    return dict(cases=72,literal_search_cases=71,whole_preparation_cases=1,actual_elf_processes=65,logical_io=401,
                output_bytes=dict(totals),kernel=dict(kernel),independent_input=actual)

def native_evidence(root,output,report):
    evidence=Evidence(root,output);descriptor=report.get('view_search')
    require(type(descriptor) is dict and set(descriptor)=={'manifest','corpus'},'search descriptor inventory')
    manifest=evidence.path(descriptor['manifest']);folder=evidence.path(descriptor['corpus'])
    summary=evidence.json(folder/'result.json')
    expected={'schema':'hepta.runtime.view-search-native.v1','status':'NATIVE_COMPLETE_RUST_REPLAY_REQUIRED',
      'groups':1,'test_groups':1,'errors':0,'failures':0,'skipped':0,'requested_cases':72,'completed_cases':72,
      'literal_search_cases':71,'whole_preparation_cases':1,'actual_elf_processes':65,'logical_io':401,
      'successful':58,'original_errors':13,'after_render_cancelled':1,'common_cache_session':20000,
      'unbound_context_kept_same_process':True,'raw_read_magic':'HVRDB001','raw_read_operation':5,'new_rust_processes':0,
      'public_mcp_route_replaced':False,'regex_search_replaced':False,'directory_search_replaced':False,
      'alternative_path_search_replaced':False,'whole_view_replaced':False,'whole_runtime_replaced':False}
    for name,value in expected.items():same(summary.get(name),value,'native search summary '+name)
    duration(summary['elapsed_seconds'],180,'native search summary')
    check=base._check(evidence,report,NATIVE_SUITE,summary,'tests/hia_native/'+NATIVE_SUITE)
    same(check['command'][0],sys.executable,'isolated native suite Python')
    manifest_pin=evidence.file(manifest);relative=manifest.relative_to(evidence.output)
    candidates=[Path(path) for path,value in summary['pinned_inputs'].items()
                if value==manifest_pin and Path(path).parts[-len(relative.parts):]==relative.parts]
    require(len(candidates)==1,'cannot bind actual native output root to manifest')
    old_output=candidates[0]
    for _ in relative.parts:old_output=old_output.parent
    evidence.old_roots.append((old_output,evidence.output))
    actual=_caller_build(evidence,manifest)
    source_paths=('tests/hia_native/test_view_search.py','tests/hia_native/test_view_call_sync.py',
                  'tests/hia_native/test_view_call_support.py','tests/hia_native/view_search_oracle/cases.py',
                  'tests/hia_native/view_call_oracle/cases.py')
    expected_paths={manifest,actual['elf'],actual['packer'],*[evidence.root/name for name in source_paths]}
    for member in actual['members']:
        path=evidence.path(member['manifest'],actual['build']);module=evidence.json(path)
        expected_paths.update((path,path.parent/module['source'],path.parent/module['image']))
    reference=summary.get('reference_report');external={}
    if reference is not None:
        require(type(reference) is str and Path(reference).is_absolute() and Path(reference).name=='result.json','optional development reference descriptor')
        parent=Path(reference).parent
        external={str(parent/name):summary['pinned_inputs'][str(parent/name)] for name in ('input.bin','original.stdout','result.json')}
    native_pins={path:value for path,value in summary['pinned_inputs'].items() if path not in external}
    require({evidence.rebase(path) for path in native_pins}==expected_paths,'missing/extra executed native source/image pins')
    evidence.pins(native_pins)
    observed=_corpus(evidence,folder,summary,actual['elf'])
    if reference is None:require(summary['actual_io_comparison'] is None,'native-only suite invented original comparison')
    else:same(summary['actual_io_comparison'],observed['output_bytes'],'development comparison recount only')
    for path in (*source_paths,'scripts/hia_native_view_call_qualification.py','scripts/hia_native_view_search_qualification.py'):
        evidence.source(path)
    return dict(schema='hepta.runtime.view-search-native-evidence.v1',status='PASS',
      native_execution_complete=True,fresh_original_comparison=False,complete_input_output_buffers_retained=True,
      actual_kernel_receipts_recounted=True,native_suites=1,native_groups=1,corpus=str(folder.relative_to(evidence.output)),
      manifest=str(manifest.relative_to(evidence.output)),**observed,
      transient_fixture_directories=[str((folder/('files-'+str(i))).relative_to(evidence.output)) for i in [*range(10000,10064),20000]],
      artifact_sha256=dict(sorted(evidence.artifacts.items())),source_sha256=dict(sorted(evidence.sources.items())),
      optional_development_original_pins=external,new_native_calls=0,new_rust_processes=0,native_cases_added_by_replay=0,
      standalone_fixture_is_public_mcp=False,whole_view_replaced=False,whole_runtime_replaced=False)

def qualification_evidence(root,output,report,completed=None):
    native=native_evidence(root,output,report);evidence=Evidence(root,output)
    checks=[row for row in report.get('checks',[]) if row.get('name')==EVIDENCE_SUITE]
    require(len(checks)==1,'exactly one native evidence refusal suite required')
    summary=checks[0].get('summary')
    require(type(summary) is dict,'missing native evidence test summary')
    check=base._check(evidence,report,EVIDENCE_SUITE,summary,'tests/hia_native/'+EVIDENCE_SUITE)
    same(check['command'][0],sys.executable,'isolated evidence suite Python')
    if completed is not None:
        actual=completed(Path(output),report,EVIDENCE_SUITE)
        same(list(actual),[check,summary],'completed evidence selector')
    expected=dict(schema='hepta.runtime.view-search-evidence-tests.v1',status='PASS',groups=2,test_groups=2,
      refusal_controls=12,failures=0,errors=0,skipped=0,new_native_calls=0,new_rust_processes=0,native_cases_added_by_replay=0,
      controls=list(CONTROLS),native_evidence_sha256=digest(canonical(native)),
      reader_sha256=evidence.source('scripts/hia_native_view_search_qualification.py')['sha256'],
      test_sha256=evidence.source('tests/hia_native/'+EVIDENCE_SUITE)['sha256'],
      relocated_source_and_output_replay=True,live_fixture_directories_required=False,process_receipts_rewritten=False,
      whole_view_replaced=False,whole_runtime_replaced=False)
    for name,value in expected.items():same(summary.get(name),value,'evidence refusal summary '+name)
    directory=evidence.path(report.get('check_artifact_directories',{}).get(EVIDENCE_SUITE,'.'))
    stderr=evidence.raw(directory/(EVIDENCE_SUITE+'.stderr')).decode()
    require(len(re.findall(r'\.\.\. ok\n',stderr))==2 and re.search(r'\nRan 2 tests in [0-9.]+s\n\nOK\n\Z',stderr),'both evidence unittest groups did not finish')
    native['artifact_sha256'].update(evidence.artifacts);native['source_sha256'].update(evidence.sources)
    native['artifact_sha256']=dict(sorted(native['artifact_sha256'].items()));native['source_sha256']=dict(sorted(native['source_sha256'].items()))
    native['evidence_controls']=dict(groups=2,refusals=12,controls=list(CONTROLS),
      stdout_sha256=check['stdout_sha256'],stderr_sha256=check['stderr_sha256'])
    return native
