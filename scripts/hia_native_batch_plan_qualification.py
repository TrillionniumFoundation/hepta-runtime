"""Bind full batch planning streams, actual images and unchanged Rust owners."""
from __future__ import annotations
from collections import Counter
import copy
import gzip
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import struct
import sys
import tomllib

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from hia_native_batch_plan_build import (COMPILER,HEPTA_COMMIT,PACKER,SPECS,IMAGES,
    REFERENCE_FILES as BUILD_REFERENCE_FILES,inspect_bundle,read,require,sha,source_path)
FOLDER='batch-plan-rust-oracle'
SOURCE_HASH='4a59ed5ce7d451c064b22f192f84c3810e7eba1247aae65105ca7d1558ec1d80'
SOURCE_FILES=('native/batch_plan.hepta','native/batch_plan_composition.json','native/batch_plan_abi.md',
 'scripts/hia_native_build.py','scripts/hia_native_loader.py','scripts/hia_native_batch_plan_build.py',
 'scripts/hia_native_batch_plan_qualification.py','tests/hia_native/test_batch_plan.py',
 'tests/hia_native/batch_plan_harness.py','tests/hia_native/batch_plan_oracle_source.py',
 'tests/hia_native/oracle_batch_plan.rs','tests/hia_native/batch_plan_oracle/Cargo.toml',
 'tests/hia_native/batch_plan_oracle/Cargo.lock','tests/hia_native/compare_batch_plan_original.py',
 'tests/hia_native/test_batch_plan_evidence.py')
REFERENCE_FILES=tuple(sorted(set(BUILD_REFERENCE_FILES)|{'Cargo.lock','tests/hia_native/test_line_endpoint.py','tests/hia_native/test_line_verify.py'}))
ORIGINALS={'src/mcp/fs/text_editing.rs':{'sha256':'e55ce4df73d6e0b70e4065900d317f6b7329670ab6fcba44979ca69dcac80590','blob':'4a8114e72a51238608201e108288294c6282ab20'},
 'src/utils/line_hash.rs':{'sha256':'904bc9a70e1ade3802213cd067ab7b75bce4dd075e4ab4965f32e9964293ba57','blob':'0e521656ba24869dbc05afc51d62aa4af79b5e44'}}
IMPORTS={'native/text_budget.hepta':{'f2':'f68','f9':'f69','f14':'f70','f15':'f71','f16':'f72'},
 'native/line_endpoint.hepta':{'f2':'f73','f3':'f74'},'native/line_verify.hepta':{'f1':'f75','f21':'f76'}}
COUNTS={'requests':3339,'native_controller_calls':53301,'native_endpoint_calls':40630,'native_verify_calls':9332}
DOMAINS={'all_100_hint_slots':1,'all_100_verification_slots':1,'all_targets_and_relocation':600,
 'capacity_refusal':15,'child_contract_refusal':17,'child_result_refusal':12,'early_admission':16,
 'endpoint_order':280,'exact_capacity':5,'frame_refusal':114,'full_operation_count':28,
 'maximum_50_double_plain':1,'maximum_50_double_stale':1,'maximum_empty_lines':1,
 'maximum_endpoint_text':1,'maximum_insert_content':1,'maximum_operation_text':1,
 'maximum_output_capacity_refusal':2,'ordered_malformed':1,'ordered_random':2200,
 'resolved_plans':36,'workspace_refusal':5}
CONTROL_DOMAINS={'capacity_refusal','child_contract_refusal','child_result_refusal','frame_refusal',
 'maximum_output_capacity_refusal','workspace_refusal'}
STREAMS={'requests':('requests.bin.gz',36628387,'ddad8f88c39e191e45996c84012b05ae797c649acfdd09853456bdad7cc13287'),
 'native_output':('native-output.bin.gz',1066976665,'5a054d4b59f92bf1d836b144e94552d10b1a1c0d747d81a6f857fee66f421d96'),
 'history':('history.jsonl.gz',33291753,'bceca93816e9c27f224510c98c0db18cd467e4d059093834072564a9b4a50573')}
REFERENCE_ROWS=3174
CONTROL_ROWS=165
CAPACITY=0xfffffffe
EVIDENCE_COUNTS={'accepted_complete_captures':1,'accepted_copied_bundles':1,
 'accepted_arbitrary_checkout_sources':1,'refused_mutations':44,'native_calls_added':0,'original_calls_added':0}
EVIDENCE_REFUSALS=tuple(
 ['summary.'+name for name in ('status','complete_domain','reference_rows','control_rows','seconds')]
 +['omitted.'+name for name in ('maximum_50_double_plain','maximum_50_double_stale','maximum_empty_lines','full_operation_count','child_contract_refusal')]
 +['native_calls.'+name for name in COUNTS]
 +['stream.'+kind+'.'+field for kind in STREAMS for field in ('raw_bytes','raw_sha256','gzip_sha256','file')]
 +['bundle.'+name for name in ('compiler_commit','buffer_profile','production_activated')]
 +['consistently_rehashed_wrong_wide_image','consistently_rehashed_wide_capacity','consistently_rehashed_compile_receipt']
 +['consistently_rehashed_elf.'+name for name in ('adapter_code','metadata_pointer','metadata_reserved','table_permission','table_source_digest','embedded_image')]
 +['composition.'+name for name in ('import_relocation','original_blob','semantic_operation_limit','static_complete_domain')]
 +['oracle_dependency_checksum','original_baseline_lock'])

def json_bytes(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def exact(actual,expected,message):require(json_bytes(actual)==json_bytes(expected),message)
def pin_sources(root,reference):
    return ({name:sha(read(root/name)) for name in SOURCE_FILES},
            {name:sha(read(reference/name)) for name in REFERENCE_FILES})
def oracle_dependencies(root,reference):
    require(sha(read(reference/'Cargo.lock'))=='7f39704b92d5fc762a98a5313949034db464ca9485827b19b5dde7aa69902d43','original baseline locked graph changed')
    packages=tomllib.loads(read(root/'tests/hia_native/batch_plan_oracle/Cargo.lock').decode())['package']
    baseline={(v['name'],v['version']):v for v in tomllib.loads(read(reference/'Cargo.lock').decode())['package']}
    require(len(packages)==12 and len({(v['name'],v['version']) for v in packages})==12,'batch oracle locked package inventory differs')
    registry=[]
    for row in packages:
        if 'source' not in row:
            require(row['name']=='hia-batch-plan-reference','unexpected local batch oracle dependency');continue
        original=baseline.get((row['name'],row['version']))
        require(original is not None and row['source']==original.get('source') and row.get('checksum')==original.get('checksum'),'batch oracle registry version/checksum differs from original baseline')
        registry.append({name:row[name] for name in ('name','version','source','checksum')})
    require(len(registry)==11,'batch oracle registry package count differs')
    return {'packages':registry,'all_registry_versions_and_checksums_match_baseline':True,
      'complete_feature_closure_identical':False,'test_recipe_has_reduced_feature_closure':True,
      'baseline_lock_sha256':sha(read(reference/'Cargo.lock')),'oracle_lock_sha256':sha(read(root/'tests/hia_native/batch_plan_oracle/Cargo.lock'))}
def source_composition(root,reference,hepta):
    proof=json.loads(read(root/'native/batch_plan_composition.json'))
    require(proof.get('source_sha256')==SOURCE_HASH==sha(read(root/'native/batch_plan.hepta')),'batch HIA owner source differs')
    exact(proof.get('original_sources'),ORIGINALS,'batch original ownership declaration differs')
    require(proof.get('original_runtime_commit')=='a0dcdda1991ec536d5e2d252c006a778993fa566','batch original baseline differs')
    for name,identity in ORIGINALS.items():
        raw=read(reference/name)
        require(sha(raw)==identity['sha256'] and hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==identity['blob'],'original batch source pin differs')
    require(proof.get('compiler_commit')==HEPTA_COMMIT and proof.get('compiler_sha256')==COMPILER and proof.get('packer_source_sha256')==PACKER,'batch compiler/packer pin differs')
    require(proof.get('complete_original_tool_parity') is False and proof.get('production_activated') is False and proof.get('static_adapter_complete_five_mib_domain') is False,'batch ownership boundary overstated')
    exact(proof.get('wide_buffer_profile'),{'name':'batch-plan.v1','input_capacity':512<<20,'output_capacity':1024<<20,'workspace_capacity':1152<<20,'image_only':True},'batch named wide profile differs')
    exact(proof.get('original_semantic_limits'),{'operations':50,'file_bytes':5<<20},'batch original semantic limits differ')
    members=[{'id':i,'name':s[0],'source':s[1],'source_sha256':sha(read(source_path(root,reference,i))),
      'image_sha256':IMAGES[i],'flags':s[2],'call_mask':s[3],'input_capacity':s[4],'output_capacity':s[5],'workspace_capacity':s[6]} for i,s in enumerate(SPECS)]
    exact(proof.get('members'),members,'batch static adapter profile differs')
    # The pinned compiler parser is used only to verify imported source graphs.
    sys.path.insert(0,str(Path(hepta).resolve(strict=True)))
    from hepta.hia_agent_assembly import assemble_program
    actual={f['name']:f for f in assemble_program(read(root/'native/batch_plan.hepta')).as_dict()['functions']}
    imports=proof.get('imports',[])
    require(len(imports)==3 and {row['path'] for row in imports}==set(IMPORTS),'batch imported owner set differs')
    functions=0
    for row in imports:
        raw=read(reference/row['path']);require(sha(raw)==row['sha256'],'batch imported HIA source differs')
        relocation=IMPORTS[row['path']];exact(row.get('function_relocation'),relocation,'batch imported graph relocation differs')
        original={f['name']:f for f in assemble_program(raw).as_dict()['functions']}
        require(row.get('functions')=={old:sha(json_bytes(original[old])) for old in relocation},'batch imported graph hashes differ')
        reverse={new:old for old,new in relocation.items()}
        for old,new in relocation.items():
            f=copy.deepcopy(actual[new]);f['name']=old
            for block in f['blocks']:
                for op in block['ops']:
                    if op['op']=='call':
                        require(op['attrs']['function'] in reverse,'batch imported call escaped its complete owner closure')
                        op['attrs']['function']=reverse[op['attrs']['function']]
            exact(f,original[old],'batch copied HIA helper body changed');functions+=1
    require(functions==9,'batch imported helper accounting differs')
    spec=importlib.util.spec_from_file_location('_qualified_batch_original_source',root/'tests/hia_native/batch_plan_oracle_source.py')
    generator=importlib.util.module_from_spec(spec);spec.loader.exec_module(generator)
    require(read(root/'tests/hia_native/oracle_batch_plan.rs')==generator.oracle_source(reference).encode(),'batch oracle original blocks differ')
    return {'source_sha256':SOURCE_HASH,'composition_sha256':sha(read(root/'native/batch_plan_composition.json')),
      'oracle_dependencies':oracle_dependencies(root,reference),
      'imported_functions':functions,'oracle_regions':{name:sha(raw.encode()) for name,raw in generator.regions(reference).items()}}

def verify_stream(folder,kind,metadata):
    name,size,digest=STREAMS[kind];record=metadata[kind];path=folder/name;packed=read(path)
    require(record.get('file')==name and type(record.get('gzip_bytes')) is int and record['gzip_bytes']==len(packed) and record.get('gzip_sha256')==sha(packed),'batch compressed corpus differs: '+kind)
    require(record.get('raw_bytes')==size and record.get('raw_sha256')==digest,'batch complete corpus domain differs: '+kind)
    h=hashlib.sha256();seen=0
    with gzip.open(path,'rb') as source:
        while raw:=source.read(1<<20):
            seen+=len(raw);require(seen<=size,'batch corpus exceeds declared complete capture');h.update(raw)
    require(seen==size and h.hexdigest()==digest,'batch full corpus bytes differ: '+kind)

def exact_summary(summary):
    require(summary.get('schema')=='hepta.runtime.batch-plan.native-tests.v1' and summary.get('status')=='PASS' and summary.get('complete_domain') is True,'complete batch native process did not pass')
    exact(summary.get('counts'),COUNTS,'batch actual native call accounting differs')
    exact(summary.get('domains'),DOMAINS,'batch complete domain accounting differs')
    require(type(summary.get('reference_rows')) is int and summary['reference_rows']==REFERENCE_ROWS and type(summary.get('control_rows')) is int and summary['control_rows']==CONTROL_ROWS,'batch reference/control rows differ')
    require(type(summary.get('seconds')) in (int,float) and math.isfinite(summary['seconds']) and summary['seconds']>0,'batch timing receipt differs')

def stream_rows(folder,metadata):
    """Check every capture ordinal and complete output; never materialize 500 MiB."""
    domains=Counter();calls=Counter(requests=0,native_controller_calls=0,native_endpoint_calls=0,native_verify_calls=0)
    wanted_elf=json.loads(read(folder/'elf-observation.json'));elf={row['input_hex']:row for row in wanted_elf['rows'] if row['reference']}
    matched=set();large=[];references=0;controls=0
    with gzip.open(folder/'requests.bin.gz','rb') as requests,gzip.open(folder/'native-output.bin.gz','rb') as outputs,gzip.open(folder/'history.jsonl.gz','rb') as history:
        for ordinal,line in enumerate(history):
            row=json.loads(line);require(type(row.get('ordinal')) is int and row['ordinal']==ordinal,'batch request ordinal missing or reordered')
            category=row['category'];require(category in DOMAINS,'batch undeclared request category');domains[category]+=1
            require(type(row.get('reference')) is bool and row['reference']==(category not in CONTROL_DOMAINS),'batch original and adapter-only domains mixed')
            trace=row['trace'];require(type(trace) is list and len(trace)<=200,'batch continuation trace exceeds original operation envelope')
            calls['requests']+=1;calls['native_controller_calls']+=len(trace)+1
            for call in trace:
                require(type(call['target']) is int and call['target'] in (2,3) and type(call['phase']) is int and call['phase'] in ((1,2) if call['target']==2 else (3,4)),'batch undeclared child target or phase')
                require(type(call['code']) is int and 0<=call['code']<=0xffffffff and type(call['input_bytes']) is int and call['input_bytes']>0,'batch child result accounting differs')
                for name in ('input_sha256','output_sha256'):require(type(call[name]) is str and len(call[name])==64 and bytes.fromhex(call[name]).hex()==call[name],'batch child byte identity differs')
                calls['native_endpoint_calls' if call['target']==2 else 'native_verify_calls']+=1
            if row['reference']:
                head=requests.read(8);require(len(head)==8,'batch original input capture truncated')
                size=struct.unpack('<Q',head)[0];wire=requests.read(size);require(len(wire)==size and size==row['input_bytes'] and sha(wire)==row['input_sha256'],'batch original input row differs')
                head=outputs.read(8);require(len(head)==8,'batch original output capture truncated')
                remaining=total=struct.unpack('<Q',head)[0];require(total==row['output_bytes']==row['code'] and total<=row['output_capacity'],'batch output length or capacity differs')
                result=hashlib.sha256();prefix=b''
                while remaining:
                    raw=outputs.read(min(1<<20,remaining));require(bool(raw),'batch complete output omitted bytes')
                    if len(prefix)<48:prefix+=raw[:48-len(prefix)]
                    result.update(raw);remaining-=len(raw)
                require(result.hexdigest()==row['output_sha256'] and prefix.hex()==row['prefix_hex'],'batch complete output row identity differs')
                require(len(prefix)==48 and prefix[:8]==b'HBPLR001' and struct.unpack_from('<Q',prefix,24)[0]+48==total and prefix[32:]==bytes(16),'batch output envelope differs')
                references+=1
                key=wire.hex() if len(wire)<1<<20 else None
                if key in elf:
                    code,payload=elf[key]['wire_output'].split(':');value=bytes.fromhex(payload)
                    require(int(code,16)==total and sha(value)==result.hexdigest(),'actual ELF differs from original-replay native row');matched.add(key)
                if category.startswith('maximum_'):
                    large.append({name:row[name] for name in ('category','input_bytes','input_sha256','output_bytes','output_sha256','output_capacity','workspace_capacity')})
                    if category in ('maximum_50_double_plain','maximum_50_double_stale'):
                        wanted=524298089 if category.endswith('plain') else 524301763
                        require(total==wanted and row['extra']['file_bytes']==5<<20 and row['extra']['operations']==50 and row['extra']['endpoint_diagnostic_copies']==100,'maximum batch diagnostics were reduced')
                        require(sum(t['target']==2 for t in trace)==100 and sum(t['target']==3 for t in trace)==(0 if category.endswith('plain') else 1),'batch repeated-target memoization trace differs')
            else:
                controls+=1;wire=bytes.fromhex(row['input_hex']);value=bytes.fromhex(row['output_hex'])
                require(len(wire)==row['input_bytes'] and sha(wire)==row['input_sha256'] and value==b'' and row['output_bytes']==0 and row['output_sha256']==sha(b'') and row['prefix_hex']=='','batch adapter refusal exposed partial output')
                require(row['code'] in (0xffffffff,0xfffffffe,0xfffffff8),'batch undeclared adapter result')
        require(requests.read(1)==outputs.read(1)==b'','batch original streams have unaccounted trailing rows')
    exact(dict(calls),COUNTS,'batch actual continuation trace counts differ');exact(dict(domains),DOMAINS,'batch capture domain counts differ')
    require(references==REFERENCE_ROWS and controls==CONTROL_ROWS and matched==set(elf),'batch complete original/ELF domain differs')
    return {'reference_rows':references,'control_rows':controls,'counts':dict(calls),'large_domain':large,'elf_reference_inputs_bound_to_rust_corpus':len(matched)}

def inspect_native(root,reference,bundle,folder,*,hepta):
    root=Path(root).resolve();reference=Path(reference).resolve();folder=Path(folder).resolve(strict=True)
    manifest=inspect_bundle(bundle,source_root=root,reference_root=reference);source=source_composition(root,reference,hepta)
    raw=read(folder/'native-corpus.json');metadata=json.loads(raw);summary=metadata['report'];exact_summary(summary)
    require(metadata.get('schema')=='hepta.runtime.batch-plan.native-corpus.v1','batch corpus schema differs')
    own,refs=pin_sources(root,reference);exact(metadata.get('sources'),own,'batch suite owner source closure changed');exact(metadata.get('reference_sources'),refs,'batch suite reference/helper closure changed')
    exact(metadata.get('original_sources'),ORIGINALS,'batch original baseline differs')
    exact(summary.get('loaded_artifacts'),manifest['loaded_artifacts'],'batch actual loaded native image differs')
    require(summary.get('bundle_manifest_sha256')==manifest['manifest_sha256'],'batch actual suite used a different source/image bundle')
    elf_raw=read(folder/'elf-observation.json');elf=json.loads(elf_raw)
    require(elf.get('schema')=='hepta.runtime.batch-plan.elf-observation.v1' and elf.get('status')=='PASS' and elf.get('exit_code')==0 and elf.get('stderr_hex')=='','actual batch ELF process did not complete')
    require(elf.get('manifest_sha256')==manifest['composition']['manifest_sha256'] and elf.get('executable_sha256')==manifest['composition']['executable_sha256'],'batch actual ELF image differs from compiled profile')
    require(type(elf.get('processes')) is int and elf['processes']==1 and type(elf.get('requests')) is int and elf['requests']==21 and type(elf.get('reference_requests')) is int and elf['reference_requests']==20 and len(elf.get('rows',[]))==21,'batch actual ELF accounting differs')
    exact(summary.get('actual_elf'),{'requests':21,'reference_requests':20,'processes':1,'observation_sha256':sha(elf_raw)},'batch completed ELF receipt changed')
    for i,row in enumerate(elf['rows']):
        code,payload=row['wire_output'].split(':');value=bytes.fromhex(payload)
        require(type(row['reference']) is bool and row['reference']==(i<20) and sha(value)==row['output_sha256'],'batch ELF response domain changed')
        require((i<20 and int(code,16)==len(value)) or (i==20 and int(code,16)==CAPACITY and value==b'' and row['category']=='static_adapter_capacity'),'batch ELF output/capacity result changed')
    for kind in STREAMS:verify_stream(folder,kind,metadata)
    captured=stream_rows(folder,metadata)
    return {'status':'PASS',**source,**captured,'bundle_manifest_sha256':manifest['manifest_sha256'],
      'loaded_artifacts':manifest['loaded_artifacts'],'composition':manifest['composition'],
      'wide_compilation_receipts':manifest['wide_compilation_receipts'],
      'corpus_metadata_sha256':sha(raw),'source_pins':{'owner':own,'reference':refs},
      'input_bytes':STREAMS['requests'][1],'input_sha256':STREAMS['requests'][2],
      'native_output_bytes':STREAMS['native_output'][1],'native_output_sha256':STREAMS['native_output'][2],
      'actual_elf_requests':21,'actual_elf_reference_requests':20,'actual_elf_adapter_refusals':1,
      'native_calls_added_by_evidence_check':0,'original_calls_added_by_evidence_check':0,
      'complete_original_tool_parity':False,'production_activated':False}

def batch_plan_evidence(root,output,report,completed,*,hepta):
    check,summary=completed(output,report,'test_batch_plan.py');exact_summary(summary)
    owner=report['modules']['batch_plan'];relative=Path(owner['manifest'])
    require(owner.get('builder')=='batch_plan' and owner.get('source')=='native/batch_plan.hepta' and not relative.is_absolute() and '..' not in relative.parts and relative.parts[:2]==('build','batch-plan'),'batch registry or build path differs')
    bundle=output/relative;require(sha(read(bundle))==owner['sha256'],'batch registered bundle changed')
    evidence=inspect_native(root,root,bundle,output/FOLDER,hepta=hepta)
    metadata=json.loads(read(output/FOLDER/'native-corpus.json'));exact(summary,metadata['report'],'batch process stdout differs from captured native corpus')
    control_check,controls=completed(output,report,'test_batch_plan_evidence.py')
    exact(controls.get('counts'),EVIDENCE_COUNTS,'batch evidence controls did not complete')
    require(controls.get('schema')=='hepta.runtime.batch-plan-evidence-tests.v1' and controls.get('status')=='PASS','batch evidence-control process did not pass')
    require(len(controls.get('refusals',[]))==44 and set(controls['refusals'])==set(EVIDENCE_REFUSALS),'batch required evidence refusals differ')
    require(controls.get('corpus_metadata_sha256')==evidence['corpus_metadata_sha256'] and controls.get('bundle_manifest_sha256')==evidence['bundle_manifest_sha256'],'batch evidence controls used another actual capture or image bundle')
    require(controls.get('test_sha256')==sha(read(root/'tests/hia_native/test_batch_plan_evidence.py')) and controls.get('qualification_sha256')==sha(read(root/'scripts/hia_native_batch_plan_qualification.py')),'batch evidence-control source identity changed')
    return dict(evidence,test_stdout_sha256=check['stdout_sha256'],test_stderr_sha256=check['stderr_sha256'],
      evidence_controls=EVIDENCE_COUNTS,evidence_stdout_sha256=control_check['stdout_sha256'],evidence_stderr_sha256=control_check['stderr_sha256'])

def compare_original(root,folder,directory,*,cargo=None,rustc=None,binary=None,build_receipt=None):
    spec=importlib.util.spec_from_file_location('_batch_actual_original_replay',Path(root)/'tests/hia_native/compare_batch_plan_original.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    result=module.compare(root,root,folder,directory,cargo=cargo,rustc=rustc,binary=binary,build_receipt=build_receipt)
    require(result.get('status')=='PASS' and result.get('original_rows')==REFERENCE_ROWS and result.get('output_complete') is True and result.get('stdout_bytes')==STREAMS['native_output'][1] and result.get('stdout_sha256')==STREAMS['native_output'][2],'actual unchanged original batch replay incomplete')
    return result
