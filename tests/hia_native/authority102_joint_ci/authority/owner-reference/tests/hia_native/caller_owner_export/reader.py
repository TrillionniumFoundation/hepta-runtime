"""Strictly read-only complete source, native-buffer and original evidence."""
from __future__ import annotations
import gzip
import hashlib
import json
from pathlib import Path
import struct
import sys

from common import BASE,ORACLE,COMPILER_COMMIT,COMPILER_TREE,SOURCE_SHA,IMAGE_SHA,document,encoded,read,require,safe_relative,sha,source_evidence,tree_files
from custody import compiler_sources,compile_receipt,registry_evidence
from cases import plan,wire,CAPACITY,INVALID,LEGACY_COUNTS,TOKEN,GOOD,FORBIDDEN,UNAUTHORIZED

# Load source-bound data-only validators before the independent write/execution
# guard. Their imports define functions; none builds, maps or runs an image.
sys.path.insert(0,str(Path(__file__).resolve().parents[3]/'scripts'))
from hia_native_authority_layout import validate_authority_layout
from hia_native_entropy_qualification import inspect_elf

LIMITS={'native-build':300,'native-replay':60,'legacy-replay':60,'kernel-replay':60,
    'rustc-version':30,'cargo-version':30,'cargo-build':300,'cargo-metadata':120,
    'original-replay':60,'original-legacy':60,'original-kernel':60,'kernel-http':60,'kernel-stdio':60}

def lines(path):
    raw=read(path)
    rows=raw.splitlines(keepends=True)
    require(all(r.endswith(b'\n') for r in rows),'incomplete JSON line stream')
    return [json.loads(r) for r in rows]

def process(capture,label):
    row=document(capture/'processes'/(label+'.json'))
    require(row['schema']=='hepta.runtime.owner-export-process.v1' and row['label']==label,'actual process identity')
    require(row['started'] is True and row['start_new_session'] is True and row['timed_out'] is False and
        type(row['returncode']) is int and row['returncode']==0 and 'failure' not in row,'actual process failed')
    require(row['timeout_seconds']==LIMITS[label] and type(row['elapsed_ns']) is int and
        0<row['elapsed_ns']<=(LIMITS[label]+1)*1_000_000_000,'process deadline')
    require(type(row['pid']) is int and row['pid']>1 and row['pgid']==row['pid'] and
        type(row['parent_pid']) is int and row['parent_pid']>1,'actual process custody')
    for key in ('stdout','stderr'):
        rel='processes/'+label+'.'+key;raw=read(capture/rel)
        require(row[key]=={'path':rel,'bytes':len(raw),'sha256':sha(raw)},'complete process stream differs')
    argv=row['command'];require(type(argv)is list and all(type(v)is str for v in argv),'actual process argv')
    if label in ('native-build','native-replay','legacy-replay','kernel-replay'):
        script={'native-build':'build.py','native-replay':'native.py','legacy-replay':'legacy.py','kernel-replay':'kernel.py'}[label]
        require(argv[1:4]==['-I','-S','-B'] and argv[4].endswith('/'+BASE+'/'+script) and
            '--source-pins-sha256' in argv,'bound native process source')
    elif label=='rustc-version':require(argv[1:]==['+1.95.0','--version','--verbose'],'actual rustc command')
    elif label=='cargo-version':require(argv[1:]==['+1.95.0','--version'],'actual cargo command')
    elif label=='cargo-build':require(argv[1:]==['+1.95.0','build','--locked','--bin','hia-caller-owner-export-reference'],'locked build command')
    elif label=='cargo-metadata':require(argv[1:]==['+1.95.0','metadata','--locked','--format-version','1'],'locked metadata command')
    elif label.startswith('original-'):
        require(len(argv)==1 and argv[0].endswith('/cargo-target/debug/hia-caller-owner-export-reference'),'fresh original replay command')
    elif label in ('kernel-http','kernel-stdio'):
        require(argv[0].endswith('/native-authority.elf'),'actual fixed ELF command')
        if label=='kernel-http':require(len(argv)==3 and argv[1]=='--authority-http-token' and
            argv[2]==row['cwd']+'/kernel-http-token','actual HTTP token fixture command')
        else:require(len(argv)==2 and argv[1]=='--authority-stdio','actual stdio command')
    if label.startswith('original-'):
        domain={'original-replay':'native','original-legacy':'legacy','original-kernel':'kernel'}[label]
        rel=domain+'/original-input.jsonl'
        require(row['stdin']==rel and row['stdin_sha256']==sha(read(capture/rel)),'full original input custody')
    elif label.startswith('kernel-') and label!='kernel-replay':
        require(row['stdin']==label+'.stdin' and row['stdin_sha256']==sha(read(capture/(label+'.stdin'))),'native ELF input custody')
    else:require(row['stdin'] is None and row['stdin_sha256'] is None,'unexpected actual stdin')
    return row

def attributed(summary,outer):
    require((summary['pid'],summary['ppid'],summary['pgid'])==
        (outer['pid'],outer['parent_pid'],outer['pgid']),'actual process attribution')

def build_evidence(capture,source):
    outer=process(capture,'native-build');actual=document(capture/'native-build.json');attributed(actual,outer)
    require(actual['schema']=='hepta.runtime.owner-export-build.v2' and actual['source_pins_sha256']==source['pins_sha256'],'build source identity')
    require(type(actual['fresh_bootstrap'])is bool and actual['reused_bootstrap'] is not actual['fresh_bootstrap'] and
        actual['matching_source_cold_qualified'] is False,'build claim scope')
    boot=document(capture/'build/bootstrap/bootstrap.json')
    require(boot['schema']=='hepta.runtime.native-bootstrap.v1' and boot['qualification']=='development_fixed_point' and
        boot['matching_source_cold_qualified'] is False and boot['dependency']==actual['compiler_source_identity'],'bootstrap identity')
    compiler_sources(capture,boot['dependency'])
    compiler_source=read(capture/'compiler-source/examples/hia_bootstrap/selfhost.hepta')
    require(boot['compiler_source_sha256']==sha(compiler_source),'compiler self source')
    seed=read(capture/'build/bootstrap/B0.so');require(seed.startswith(b'\x7fELF'),'explicit B0 seed')
    seed_receipt=document(capture/'build/bootstrap/B0.receipt.json')
    require(seed_receipt==boot['seed_receipt'] and seed_receipt['seed_only'] is True and
        seed_receipt['source_sha256']==sha(compiler_source),'B0 source custody')
    for path,digest in seed_receipt['loaded_seed_modules'].items():require(boot['dependency']['files'].get(path)==digest,'seed source closure')
    previous=seed;generations=[];receipts=[]
    for name in ('B1','B2','B3'):
        receipts.append(compile_receipt(capture,'build/bootstrap',name,previous,compiler_source,name+'.image.bin',
            'seed-shared' if name=='B1' else 'flat-x86-64'))
        previous=read(capture/'build/bootstrap'/(name+'.image.bin'));generations.append(previous)
    require(generations[0]==generations[1]==generations[2] and sha(previous)==boot['generation_sha256'] and
        receipts==boot['generation_receipts'],'full actual fixed point')
    profile=document(capture/'source/native/caller_owner_export_profile.json')
    provenance=document(capture/'source/native/caller_owner_export_packer_provenance.json')
    expected_names={r['source'] for r in profile['members']}|{'native/caller_owner_export_packer.hepta','tests/hia_native/scope_entropy_fixture.hepta'}
    require(set(actual['modules'])==expected_names and len(expected_names)==11,'exact eleven compiled module sources')
    loaded={};modules={}
    for relative,path in actual['modules'].items():
        safe_relative(path);manifest_raw=read(capture/path);manifest=json.loads(manifest_raw)
        folder=Path(path).parent;name=folder.name
        owner=read(capture/'source'/relative);image=read(capture/folder/'module.image.bin')
        expected={'schema':'hepta.runtime.native-module.v1','name':name,
            'abi':'hepta.runtime.borrowed-bytes.linux-x86_64.v1','target':'linux-x86_64',
            'compiler_commit':COMPILER_COMMIT,'compiler_sha256':sha(previous),'source':name+'.hepta',
            'source_sha256':sha(owner),'image':'module.image.bin','image_sha256':sha(image),
            'input_capacity':8<<20,'output_capacity':8<<20,'workspace_capacity':32<<20,
            'qualification':'development_fixed_point','standalone':None}
        require(manifest==expected and read(capture/folder/(name+'.hepta'))==owner,'complete native module identity')
        receipt=compile_receipt(capture,folder,'module',previous,owner,'module.image.bin','flat-x86-64')
        record=document(capture/folder/'build.json')
        require(record['compile_receipt']==receipt and record['compiler_dependency']==boot['dependency'] and
            record['whole_runtime_replaced'] is False,'actual module compile custody')
        loaded[relative]={'manifest_sha256':sha(manifest_raw),'source_sha256':sha(owner),'image_sha256':sha(image),'image_bytes':len(image)}
        modules[relative]=(manifest,image)
    require(loaded['native/caller_authority.hepta']['source_sha256']==SOURCE_SHA and
        loaded['native/caller_authority.hepta']['image_sha256']==IMAGE_SHA,'new root identity')
    graph_path=safe_relative(actual['manifest']);graph_raw=read(capture/graph_path);graph=json.loads(graph_raw);folder=Path(graph_path).parent
    require(sha(graph_raw)==actual['manifest_sha256'] and graph['schema']=='hepta.runtime.native-composition.v1' and len(graph['members'])==9,'complete graph identity')
    keys=('id','name','source_sha256','flags','call_mask','input_capacity','output_capacity','workspace_capacity')
    table=[{k:r[k] for k in keys} for r in profile['members']]
    require(graph['profile']==table,'exact graph capabilities')
    frame=bytearray(b'HIABND01'+struct.pack('<3Q',9,0,0))
    copied=[]
    for index,row in enumerate(profile['members']):
        metadata,image=modules[row['source']]
        require(sha(image)==row['image_sha256'] and len(image)==row['image_bytes'],'fixed member image')
        stem='module_%02d'%index
        renamed=dict(metadata,source=stem+'.hepta',image=stem+'.image.bin')
        raw=read(capture/folder/(stem+'.json'))
        require(json.loads(raw)==renamed and read(capture/folder/renamed['source'])==read(capture/'source'/row['source']) and
            read(capture/folder/renamed['image'])==image,'copied graph member bytes')
        require(graph['members'][index]=={'manifest':stem+'.json','manifest_sha256':sha(raw),
            'source_sha256':row['source_sha256'],'image_sha256':row['image_sha256']},'copied graph member mapping')
        frame.extend(struct.pack('<8Q',len(image),row['input_capacity'],row['output_capacity'],row['workspace_capacity'],row['flags'],row['call_mask'],0,0))
        frame.extend(bytes.fromhex(row['source_sha256']+row['image_sha256']));frame.extend(image)
        copied.append({'id':index,'manifest_sha256':sha(raw),**{k:loaded[row['source']][k] for k in ('source_sha256','image_sha256','image_bytes')}})
    metadata,image=modules['native/caller_owner_export_packer.hepta']
    renamed=dict(metadata,source='packer.hepta',image='packer.image.bin');raw=read(capture/folder/'packer.json')
    require(json.loads(raw)==renamed and read(capture/folder/'packer.hepta')==read(capture/'source/native/caller_owner_export_packer.hepta') and
        read(capture/folder/'packer.image.bin')==image,'copied actual packer')
    require(graph['packer']=={'manifest':'packer.json','manifest_sha256':sha(raw),'source_sha256':metadata['source_sha256'],'image_sha256':sha(image)},'packer graph binding')
    executable=read(capture/folder/graph['executable'])
    require(sha(executable)==graph['executable_sha256'] and graph['frame_sha256']==sha(frame) and graph['frame_bytes']==len(frame),'actual graph and packing frame')
    layout=validate_authority_layout(executable,bytes(frame),profile,provenance)
    require(graph['layout']==layout and graph['inspection']==inspect_elf(executable),'entire native ELF layout')
    require(graph['whole_runtime_replaced'] is False and graph['runtime_python_required'] is False and graph['runtime_libc_required'] is False,'native graph runtime scope')
    pack=document(capture/'pack/call.json');out=read(capture/'pack/full-output.bin');workspace=read(capture/'pack/full-workspace.bin')
    require(read(capture/'pack/full-input.bin')==bytes(frame) and pack['pid']==outer['pid'] and pack['code']==len(executable),'actual HIA pack input/result')
    require(len(out)==8<<20 and out[:len(executable)]==executable and out[len(executable):]==b'\xcc'*(len(out)-len(executable)) and
        len(workspace)==1<<20 and pack['input_sha256']==sha(frame) and pack['output_sha256']==sha(out) and
        pack['workspace_sha256']==sha(workspace) and pack['layout']==layout,'complete HIA pack buffers')
    require(pack['packer_manifest_sha256']==loaded['native/caller_owner_export_packer.hepta']['manifest_sha256'] and
        pack['complete_observed_packer_calls']==1 and pack['builder_packer_calls']==1,'actual HIA pack counts')
    fixture=loaded['tests/hia_native/scope_entropy_fixture.hepta'];copied[7]={'id':7,**fixture}
    observed={'schema':'hepta.runtime.owner-export.loaded-fixture.v2','profile_sha256':sha(read(capture/'source/native/caller_owner_export_profile.json')),
        'graph_manifest_sha256':sha(graph_raw),'fixture_entropy':True,'members':copied}
    return {'image_sha256':IMAGE_SHA,'source_sha256':SOURCE_SHA,'executable_sha256':sha(executable),'executable_bytes':len(executable),
        'manifest_sha256':sha(graph_raw),'modules':loaded,'loaded_fixture':observed,'fresh_bootstrap':actual['fresh_bootstrap'],
        'matching_source_cold_qualified':False}

def native_evidence(folder,build,outer=None):
    summary=document(folder/'summary.json')
    if outer is not None:attributed(summary,outer)
    require(summary['schema']=='hepta.runtime.owner-export.native.v2' and summary['status']=='PASS','native completion')
    require(summary['loaded']==build['loaded_fixture'],'actual nine loaded native identities')
    rows=lines(folder/'rows.jsonl');calls=lines(folder/'calls.jsonl');index=document(folder/'buffers.json')
    require(len(rows)==len(plan())==120 and len(calls)==summary['native_calls']==493,'full native case/call domain')
    require([row['id'] for row in calls]==list(range(1,494)),'native call stream order')
    used=set();offsets={};total=0
    for call in calls:
        require(type(call['code']) is int and 0<=call['code']<=0xffffffff and 0<=call['module']<9,'native return/module')
        require(call['before']['input']==call['after']['input'],'native input mutation')
        for phase in ('before','after'):
            for field in ('input','output','workspace'):
                ref=call[phase][field];key=ref['sha256'];used.add(key);total+=ref['bytes']
                require(index[key]['sha256']==key and index[key]['bytes']==ref['bytes'],'buffer index reference')
                wanted=call['input_bytes'] if field=='input' else call[field+'_capacity']+16
                require(ref['bytes']==wanted,'complete native borrowed extent')
                if field=='output':
                    at=call['code'] if call['code']<=call['output_capacity'] else call['output_capacity']
                    offsets.setdefault(key,set()).add(at)
    require(used==set(index) and set(tree_files(folder/'buffers'))=={key+'.gz' for key in used},'unclaimed/omitted complete buffers')
    metrics={}
    for key,row in index.items():
        packed=read(folder/'buffers'/(key+'.gz'));raw=gzip.decompress(packed)
        require(len(packed)==row['compressed_bytes'] and sha(packed)==row['compressed_sha256'] and len(raw)==row['bytes'] and sha(raw)==key,'complete retained native buffer changed')
        metrics[key]={'head':raw[:512],'tail':raw[-16:],'suffix':{at:sha(raw[at:]) for at in offsets.get(key,())},
            'retired':len(raw)==(16<<20)+16 and raw[8:(16<<20)-256]==bytes((16<<20)-264)}
    for call in calls:
        before,after=call['before'],call['after'];code=call['code']
        require(metrics[before['workspace']['sha256']]['tail']==b'\x6b'*16==metrics[after['workspace']['sha256']]['tail'],'workspace canary changed')
        a,b=metrics[before['output']['sha256']],metrics[after['output']['sha256']]
        require(a['tail']==b['tail'],'output borrowed boundary changed')
        if code<=call['output_capacity']:require(a['suffix'][code]==b['suffix'][code],'native output suffix changed')
    by_id={row['id']:row for row in calls};claimed=[];original=lines(folder/'original-input.jsonl');expected=lines(folder/'expected-original.jsonl');reference=0
    for number,(wanted,row) in enumerate(zip(plan(),rows,strict=True),1):
        for k,v in wanted.items():require(row.get(k)==v,'planned native case changed: '+str(number)+' '+k)
        require(row['id']==number,'native case order')
        these=[by_id[i] for i in row['calls']];claimed.extend(row['calls'])
        require(all(c['row']==number and c['context']==wanted['context'] for c in these),'native call attribution')
        roots=[c for c in these if c['module']==0]
        if wanted['operation'] in ('replace_verified_extension','restore_verified_extension'):require(not these,'fixture transfer fabricated native execution')
        else:
            require(roots,'missing actual root entry')
            last=roots[-1];require(last['code']==row['code'],'actual final return')
            output=metrics[last['after']['output']['sha256']]['head'];actual=bytes.fromhex(row['output_hex'])
            require(output[:len(actual)]==actual and (last['code']>last['output_capacity'] or len(actual)==last['code']),'actual final full semantic result')
            work=metrics[last['after']['workspace']['sha256']];head=work['head'];bound=struct.unpack_from('<Q',head,80)[0]
            state=None if bound==0 else {'owner':head[352:384].hex(),'authenticated':bool(struct.unpack_from('<Q',head,88)[0])}
            require(bound in (0,1) and struct.unpack_from('<Q',head,88)[0] in (0,1) and state==row['binding'],'actual private bound state differs')
            if wanted['operation']=='shutdown':require(work['retired'],'native retirement did not clear complete private state')
            if wanted['operation'] in ('request','abi-control'):
                frame_raw=bytes.fromhex(wanted['wire_hex']) if wanted['operation']=='abi-control' else wire(wanted['request_op'],[(bytes.fromhex(a),bytes.fromhex(b)) for a,b in wanted['headers']],bytes.fromhex(wanted['payload_hex']))
                require(row['wire_hex']==frame_raw.hex() and all(c['before']['input']=={'bytes':len(frame_raw),'sha256':sha(frame_raw)} for c in roots),'complete request replay changed')
                if wanted['operation']=='abi-control':require(actual==struct.pack('<I',INVALID).hex().encode() and row['binding']==row['binding_before'],'ABI refusal changed binding/result')
                elif wanted['expected_semantic_code']==0 and wanted['request_op']==3:
                    expected_owner=b'HROWR001'+struct.pack('<Q',int(row['binding']['authenticated']))+row['binding']['owner'].encode()
                    require(len(expected_owner)==80,'complete projected owner extent')
                    if wanted['capacity']>=168:require(actual==(struct.pack('<I',0)+expected_owner).hex().encode(),'private result is not actual bound state')
                    else:require(row['code']==CAPACITY and actual==b'','capacity refusal result')
        if row['original_row'] is not None:
            reference+=1;require(row['original_row']==reference,'original case mapping')
            ref=original[reference-1];exp=expected[reference-1]
            for k,v in wanted.items():require(ref.get(k)==v,'complete original input changed')
            require(exp=={'context':wanted['context'],'code':ref['code'],'output_hex':ref['output_hex'],'binding':row['binding']},'original comparison differs from native observed state')
            if wanted['operation']=='start' and wanted['mode']==1:
                present=struct.unpack_from('<Q',head,64)[0]
                require(present in (0,1) and ref['stdio_fallback_source']=='native-os-observation' and
                    ref['observed_stdio_fallback']==(head[320:352].hex() if present else None),'original fallback is not the complete observed private native fallback')
            if wanted['operation']=='request' and wanted['expected_semantic_code']==0 and wanted['request_op']==3:
                require(bytes.fromhex(ref['output_hex'])==expected_owner,'original projection comparison changed')
        else:require(wanted['operation']=='abi-control','omitted original semantic case')
    require(claimed==list(range(1,494)) and reference==105==len(original)==len(expected),'complete call/reference coverage')
    require(summary['rows']==120 and summary['original_rows']==105 and summary['native_abi_rows']==15 and summary['complete_buffer_bytes']==total,'native summary domain')
    for key in ('whole_runtime_replaced','current_http_listener_qualified','concurrent_session_binding_qualified','public_route_qualified'):require(summary[key] is False,'native scope overclaim')
    return {'rows':120,'original_rows':105,'abi_refusals':15,'native_calls':493,'complete_buffer_bytes':total}

def original_evidence(capture):
    records={name:process(capture,name) for name in ('rustc-version','cargo-version','cargo-build','cargo-metadata','original-replay','original-legacy','original-kernel')}
    rustc=read(capture/'processes/rustc-version.stdout')
    require(rustc.startswith(b'rustc 1.95.0 ') and b'\nrelease: 1.95.0\n' in rustc and b'\nhost: x86_64-unknown-linux-gnu\n' in rustc,'actual compiler version')
    require(read(capture/'processes/cargo-version.stdout').startswith(b'cargo 1.95.0 '),'actual cargo version')
    for row in records.values():require(row['environment']['RUSTUP_TOOLCHAIN']=='1.95.0' and row['environment']['CARGO_ENCODED_RUSTFLAGS']=='','controlled Rust build flags')
    build=document(capture/'original-build.json');binary=read(capture/'original/oracle.bin')
    require(binary.startswith(b'\x7fELF') and build['binary_sha256']==sha(binary)==build['binary_after_replay_sha256'] and
        build['binary_bytes']==len(binary) and build['fresh_build'] is True and build['locked'] is True,'fresh original binary custody')
    fixture_names={'tests/hia_native/oracle_caller_owner_export.rs',*(ORACLE+'/'+name for name in
        ('Cargo.toml','Cargo.lock','build.rs','original_access.rs','crypto_access.rs'))}
    require(set(build['workspace_sources'])==fixture_names and
        set(tree_files(capture/'original/workspace'))==fixture_names,'exact fresh original fixture sources')
    require(build['original_function_substitution'] is False and build['actual_request_context'] is True and
        build['observed_stdio_fallback_input'] is True,'original substitution/input scope')
    reference_prefix=BASE+'/reference/'
    reference_files={name[len(reference_prefix):]:row for name,row in
        source_evidence(capture/'source')['original']['source_inputs']['files'].items() if name.startswith(reference_prefix)}
    require(build['reference_sources']==reference_files,'original target source custody')
    for name,row in build['workspace_sources'].items():
        raw=read(capture/'original/workspace'/safe_relative(name));require(raw==read(capture/'source'/name) and row=={'bytes':len(raw),'sha256':sha(raw)},'actual reference build source')
    sys.path.insert(0,str(capture/'source/scripts'))
    import hia_native_owner_export_reference as original
    generated=original.generated_source(capture/'source')
    require(set(tree_files(capture/'original/generated'))==set(generated),'generated original source set')
    for name,raw in generated.items():require(read(capture/'original/generated'/name)==raw,'unchanged complete original extraction')
    registry=registry_evidence(capture);outputs={}
    for label,domain,count in [('original-replay','native',105),('original-legacy','legacy',122),('original-kernel','kernel',16)]:
        out=read(capture/'processes'/(label+'.stdout'));wanted=read(capture/domain/'expected-original.jsonl')
        require(out==wanted and len(lines(capture/domain/'original-input.jsonl'))==count==len(lines(capture/domain/'expected-original.jsonl')),'complete unchanged original replay mismatch')
        report=document(capture/'processes'/(label+'.stderr'))
        attributed(report,records[label])
        require(report['status']=='PASS' and report['rows']==count and report['output_sha256']==sha(out) and report['native_cases_added_by_replay']==0,'actual original completion')
        require(report['original_middleware_executed'] is True and all(report[k] is False for k in
            ('paired_rust_random_owner_generator','optional_http_startup_qualified','current_http_listener_qualified',
             'concurrent_session_binding_qualified','whole_runtime_replaced')),'original domain overclaim')
        require(type(report['original_resolve_calls']) is int and report['original_resolve_calls']>0 and
            type(report['actual_router_dispatch_calls']) is int and report['actual_router_dispatch_calls']>0,'actual resolver/router execution missing')
        outputs[domain]={'rows':count,'output_sha256':sha(out),'seconds':records[label]['elapsed_ns']/1e9}
    return {'rows':243,'domains':outputs,'registry':registry,'binary_sha256':sha(binary)}

def read_capture(capture,source_root,pins_sha):
    capture=Path(capture).absolute();source=source_evidence(source_root,pins_sha)
    index=document(capture/'CAPTURE.json');require(index['schema']=='hepta.runtime.owner-export-capture.v1' and index['source_pins_sha256']==pins_sha,'capture identity')
    actual=tree_files(capture);actual.pop('CAPTURE.json',None);require(actual==index['files'],'complete capture tree changed')
    require(source_evidence(capture/'source',pins_sha)==source,'relocated source closure differs')
    require(set(tree_files(capture/'source'))==set(source['files'])|{BASE+'/source-pins.json'},'unclaimed or omitted capture source')
    labels={'native-build','native-replay','legacy-replay','kernel-replay','rustc-version','cargo-version',
        'cargo-build','cargo-metadata','original-replay','original-legacy','original-kernel'}
    require(set(tree_files(capture/'processes'))=={name+'.'+suffix for name in labels for suffix in ('json','stdout','stderr')},'exact actual process inventory')
    # Reject source/registry/original custody changes before decompressing the
    # independently retained full native arrays; neither check is omitted.
    original=original_evidence(capture)
    build=build_evidence(capture,source)
    native=native_evidence(capture/'native',build,process(capture,'native-replay'))
    legacy=document(capture/'legacy/summary.json');outer=process(capture,'legacy-replay');attributed(legacy,outer)
    require(legacy['schema']=='hepta.runtime.owner-export.legacy.v2' and legacy['status']=='PASS' and legacy['tests_run']==8 and
        legacy['counts']==LEGACY_COUNTS and legacy['original_rows']==122 and legacy['loaded']==build['loaded_fixture'],'unchanged eight-group legacy domain')
    require(legacy['native_test_source_sha256']==sha(read(capture/'source/tests/hia_native/test_caller_authority.py')) and
        legacy['harness_source_sha256']==sha(read(capture/'source/tests/hia_native/authority_native_harness.py')),'unchanged legacy source custody')
    kernel=document(capture/'kernel/summary.json');outer=process(capture,'kernel-replay');attributed(kernel,outer)
    require(kernel['status']=='PASS' and kernel['requests']==12 and kernel['original_rows']==16 and kernel['executable_sha256']==build['executable_sha256'],'actual native ELF domain')
    require(kernel['schema']=='hepta.runtime.owner-export.kernel.v2' and kernel['runtime_python_required'] is False and
        kernel['current_http_listener_qualified'] is False and kernel['public_route_qualified'] is False,'kernel scope')
    require([r['label'] for r in kernel['rows']]==['kernel-http','kernel-stdio'],'kernel process inventory')
    require(set(tree_files(capture/'kernel/processes'))=={name+'.'+suffix for name in ('kernel-http','kernel-stdio')
        for suffix in ('json','stdout','stderr')},'exact kernel child process files')
    originals=[];observations=[]
    for index,row in enumerate(kernel['rows'],101):
        child=process(capture/'kernel',row['label']);require(child['pid']==row['pid'] and child['parent_pid']==outer['pid'],'native executable process custody')
        require(row['requests']==6 and row['input_sha256']==sha(read(capture/'kernel'/(row['label']+'.stdin'))) and
            row['output_sha256']==sha(read(capture/'kernel/processes'/(row['label']+'.stdout'))),'complete kernel streams')
        argv=outer['command'];manifest=Path(argv[argv.index('--manifest')+1])
        require(Path(child['command'][0])==manifest.parent/'native-authority.elf','executed ELF is not the actually built graph')
        mode=2 if index==101 else 1;headers=GOOD if mode==2 else []
        require(row['context']==index and row['mode']==mode and row['authenticated'] is (mode==2),'kernel fixture identity')
        requests=[(0,headers),(3,headers),(3,headers),(1,headers),(3,[]),(3,headers+[(b'origin',b'null')])]
        require(read(capture/'kernel'/(row['label']+'.stdin'))==b''.join(wire(op,h)+b'\n' for op,h in requests),'complete kernel request domain changed')
        raw=read(capture/'kernel/processes'/(row['label']+'.stdout'));chunks=raw.splitlines(keepends=True)
        require(len(chunks)==6 and all(x.endswith(b'\n') for x in chunks) and
            read(capture/'kernel/processes'/(row['label']+'.stderr'))==b'','kernel response count/stderr')
        responses=[bytes.fromhex(x[:-1].decode()) for x in chunks]
        require(all(v.hex().encode()+b'\n'==r for v,r in zip(responses,chunks,strict=True)),'kernel response canonical framing')
        owner=row['owner'];require(len(owner)==64 and all(c in '0123456789abcdef' for c in owner),'complete kernel owner')
        if mode==2:require(owner==sha(b'hepta-runtime/private-operator-credential/v1\0'+TOKEN),'current original token-to-owner projection')
        scope=b'HROWR001'+struct.pack('<Q',int(mode==2))+owner.encode()
        start={'context':index,'operation':'start','mode':mode,'token_file_hex':(TOKEN+b'\n').hex(),
            'file_mode':0o600,'entropy_seed':7,'entropy_fail':0,'owner_failure':False,'missing_file':False,'code':0,'output_hex':''}
        if mode==1:start.update(stdio_fallback_source='native-os-observation',observed_stdio_fallback=owner)
        originals.append(start);observations.append({'context':index,'code':0,'output_hex':'','binding':None})
        state=None
        for ordinal,((op,h),response) in enumerate(zip(requests,responses,strict=True)):
            status=UNAUTHORIZED if mode==2 and ordinal==4 else FORBIDDEN if mode==2 and ordinal==5 else 0
            body=b'' if status or op==0 else bytes((int(mode==2),)) if op==1 else scope
            require(response==struct.pack('<I',status)+body,'complete actual kernel response changed')
            if not status and op!=0:state={'owner':owner,'authenticated':mode==2}
            originals.append({'context':index,'operation':'request','request_op':op,'headers':[[a.hex(),b.hex()] for a,b in h],
                'payload_hex':'','code':status,'output_hex':body.hex()})
            observations.append({'context':index,'code':status,'output_hex':body.hex(),'binding':state})
        originals.append({'context':index,'operation':'shutdown','code':0,'output_hex':''})
        observations.append({'context':index,'code':0,'output_hex':'','binding':None})
    require(lines(capture/'kernel/original-input.jsonl')==originals and
        lines(capture/'kernel/expected-original.jsonl')==observations,'kernel original comparison omitted or changed a request')
    return {'schema':'hepta.runtime.owner-export-evidence.v2','status':'PASS','capture_sha256':sha(read(capture/'CAPTURE.json')),
        'source_pins_sha256':pins_sha,'build':build,'native':native,'legacy_groups':8,'kernel_processes':2,'original':original,
        'current_http_listener_qualified':False,'concurrent_session_binding_qualified':False,'public_route_qualified':False,
        'whole_runtime_replaced':False,'production_activated':False,'old_stack_removal_qualified':False}
