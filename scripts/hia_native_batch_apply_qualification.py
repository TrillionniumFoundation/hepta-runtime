"""Strict source, image, complete-corpus and actual-reference evidence for batch apply."""
from __future__ import annotations
import collections
import copy
import gzip
import hashlib
import json
import os
from pathlib import Path
import struct
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from hia_native_batch_apply_build import inspect_bundle,read,sha,require

FOLDER='batch-apply'
CASES=14412
GROUPS={'empty_trailing_line':1,'literal_cr_normalization':1,'ordered_conflict_pairs':225,
 'first_conflict_priority':4,'line_endings_insert':791,'line_endings_replace':700,
 'duplicate_and_noise_domains':440,'reverse_apply_and_delta_anchors':240,'ordered_random':12000,
 'all_fifty_replacements':3,'all_fifty_insertions':3,'full_file_dense_empty_lines':1,
 'full_file_single_unicode_line':1,'full_file_escaped_duplicate_diagnostic':1,
 'full_fifty_five_mib_contents':1,'invalid_frames':140,'capacity_refusals':6}
NATIVE_COUNTS={'requests':14558,'native_controller_calls':36210,'native_editable_calls':21652}
CONTRACT_COUNTS={'requests':103,'native_controller_calls':304,'native_editable_calls':201}
REQUEST_SHA='246702e28073e6de3730c2b700c4b93d22bcf75dd3cfa48d91d11505733e96b2'
OUTPUT_SHA='2bbaac476c2147b1e2e54b8305d8dc7741ca25e20c85df9af51394ef546ec01e'
PROPERTIES_SHA='9f9925503f7b96a2f76aa3b14aace30332213a411d1df27f7dd11f083be40de0'
ORIGINALS={'src/mcp/fs/text_editing.rs':('e55ce4df73d6e0b70e4065900d317f6b7329670ab6fcba44979ca69dcac80590','4a8114e72a51238608201e108288294c6282ab20'),
 'src/utils/line_hash.rs':('904bc9a70e1ade3802213cd067ab7b75bce4dd075e4ab4965f32e9964293ba57','0e521656ba24869dbc05afc51d62aa4af79b5e44')}

def pairs(values):
    result={}
    for key,value in values:
        require(key not in result,'duplicate evidence field');result[key]=value
    return result
def json_file(path):return json.loads(read(path),object_pairs_hook=pairs)
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def file_record(path):return {'bytes':Path(path).stat().st_size,'sha256':sha(read(path))}
def exact(value,wanted,label):require(type(value) is type(wanted) and value==wanted,label)

OWN_EXECUTION_FILES=('scripts/hia_native_build.py','scripts/hia_native_loader.py',
 'scripts/hia_native_batch_apply_build.py','scripts/hia_native_batch_apply_qualification.py',
 'native/batch_apply.hepta','native/batch_apply_composition.json','native/batch_apply_fixtures.json',
 'native/editable_content.hepta','native/editable_content_composition.json','native/editable_bulk_composition.json',
 'tests/hia_native/test_batch_apply.py','tests/hia_native/test_batch_apply_contract.py',
 'tests/hia_native/test_batch_apply_artifacts.py','tests/hia_native/batch_apply_harness.py',
 'tests/hia_native/batch_apply_reference.py','tests/hia_native/batch_apply_hex_transport.hepta',
 'tests/hia_native/batch_debug_probe.hepta','tests/hia_native/rust_debug_properties.json',
 'tests/hia_native/rust_debug_properties.rs','tests/hia_native/oracle_batch_apply.rs',
 'tests/hia_native/compare_batch_apply_original.py','tests/hia_native/test_batch_apply_evidence.py')
REFERENCE_EXECUTION_FILES=tuple(ORIGINALS)+('tests/hia_native/test_editable_content.py',
 'tests/hia_native/test_batch_plan.py','tests/hia_native/batch_plan_harness.py',
 'tests/hia_native/test_line_endpoint.py','tests/hia_native/test_line_verify.py',
 'native/batch_plan.hepta','native/line_endpoint.hepta','native/line_verify.hepta','native/text_budget.hepta')
def execution_source_pins(root=ROOT,reference=None):
    root=Path(root);reference=Path(reference or root)
    return {'owner':{name:file_record(root/name) for name in OWN_EXECUTION_FILES},
        'reference':{name:file_record(reference/name) for name in REFERENCE_EXECUTION_FILES}}

def source_contract(root=ROOT,reference=None,hepta=None):
    root=Path(root);reference=Path(reference or root)
    hepta=Path(hepta or os.environ['HIA_HEPTA_DIR'])
    sys.path.insert(0,str(hepta))
    from hepta.hia_agent_assembly import assemble_program
    def functions(path):return {f['name']:f for f in assemble_program(read(path)).as_dict()['functions']}
    proof=json_file(root/'native/batch_apply_composition.json')
    exact(proof['schema'],'hepta.runtime.batch-apply-source-composition.v1','apply source schema differs')
    exact(proof['source_sha256'],sha(read(root/'native/batch_apply.hepta')),'apply source changed')
    exact(proof['original_runtime_commit'],'a0dcdda1991ec536d5e2d252c006a778993fa566','original runtime pin changed')
    require(set(proof['original_sources'])==set(ORIGINALS),'original source owner set differs')
    for relative,(digest,blob) in ORIGINALS.items():
        raw=read(reference/relative)
        exact(sha(raw),digest,'original runtime source changed')
        exact(hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),blob,'original runtime Git blob changed')
        exact(proof['original_sources'][relative],{'sha256':digest,'blob':blob},'original source declaration differs')
    actual=functions(root/'native/batch_apply.hepta');count=0
    require(len(actual)==75,'apply function owner set changed')
    exact({r['path'] for r in proof['imports']},{'native/text_budget.hepta','native/line_endpoint.hepta'},'imported owner set differs')
    for record in proof['imports']:
        path=reference/record['path'];exact(sha(read(path)),record['sha256'],'imported source changed')
        original=functions(path);reverse={new:old for old,new in record['function_relocation'].items()}
        for old,new in record['function_relocation'].items():
            value=copy.deepcopy(actual[new]);value['name']=old
            for block in value['blocks']:
                for operation in block['ops']:
                    if operation['op']=='call':operation['attrs']['function']=reverse[operation['attrs']['function']]
            exact(value,original[old],'imported function body changed')
            exact(sha(canonical(value)),record['functions'][old],'imported function digest changed');count+=1
    exact(count,7,'imported function count differs')
    child=proof['editable_child'];exact(child,{'id':5,'call_mask':32,'source':'native/editable_content.hepta',
        'source_sha256':sha(read(root/'native/editable_content.hepta'))},'fixed Editable child changed')
    bulk=json_file(root/'native/editable_bulk_composition.json');editable=functions(root/'native/editable_content.hepta')
    exact(bulk['schema'],'hepta.runtime.editable-bulk-source.v1','bulk source schema differs')
    exact(bulk['original_sha256'],'a774044ae7246bd9d447d39d479db16254afbb7e1cb10d4b2244a559a71cf65f','bulk historical source differs')
    exact(bulk['source_sha256'],child['source_sha256'],'bulk optimized source differs')
    require(set(bulk['changed_functions'])=={'3','5','8'} and len(bulk['preserved_functions'])==20,'bulk changed function set differs')
    require(set(editable)==set(bulk['preserved_functions'])|{'f3','f5','f8'},'Editable function closure differs')
    for name,digest in bulk['preserved_functions'].items():exact(sha(canonical(editable[name])),digest,'unmodified Editable function changed')
    for name,row in bulk['changed_functions'].items():exact(sha(canonical(editable['f'+name])),row['after'],'bulk copy body changed')
    editable_proof=json_file(root/'native/editable_content_composition.json')
    exact(editable_proof['bulk_optimization'],{'path':'native/editable_bulk_composition.json','sha256':sha(read(root/'native/editable_bulk_composition.json'))},'bulk composition binding changed')
    exact(editable_proof['source_sha256'],child['source_sha256'],'Editable source composition changed')
    properties=json_file(root/proof['debug_properties']['path'])
    exact(properties['unicode'],[17,0,0],'Debug Unicode version changed')
    exact(properties['scalars'],1112064,'Debug scalar domain changed')
    exact(properties['formatting_calls'],4448256,'Debug four-prefix target comparisons changed')
    exact(sha(read(root/proof['debug_properties']['path'])),proof['debug_properties']['sha256'],'Debug property bytes changed')
    exact(sha(read(root/proof['debug_properties']['probe_path'])),proof['debug_properties']['probe_sha256'],'Debug original probe changed')
    expected=bytearray(0x110000);previous=-1
    for first,last,flags in properties['ranges']:
        require(type(first) is int and type(last) is int and first==previous+1 and first<=last<=0x10ffff and flags in (0,15,16),'Debug interval partition differs')
        expected[first:last+1]=bytes([flags])*(last-first+1);previous=last
    exact(previous,0x10ffff,'Debug scalar partition is incomplete')
    exact(sha(expected),PROPERTIES_SHA,'Debug property values changed')
    fixtures=json_file(root/'native/batch_apply_fixtures.json')
    require(fixtures['schema']=='hepta.runtime.batch-apply-fixtures.v1','fixture source schema differs')
    record=fixtures['debug_probe'];exact(record['owner_source_sha256'],proof['source_sha256'],'Debug probe owner differs')
    probe=functions(root/'tests/hia_native/batch_debug_probe.hepta')
    exact(sha(read(root/'tests/hia_native/batch_debug_probe.hepta')),record['source_sha256'],'Debug probe source differs')
    require(set(probe)=={'f0'}|set(record['function_relocation'].values()),'Debug probe closure differs')
    reverse={new:old for old,new in record['function_relocation'].items()}
    for old,new in record['function_relocation'].items():
        value=copy.deepcopy(probe[new]);value['name']=old
        for block in value['blocks']:
            for operation in block['ops']:
                if operation['op']=='call':operation['attrs']['function']=reverse[operation['attrs']['function']]
        exact(value,actual[old],'Debug probe imported body changed')
        exact(sha(canonical(value)),record['function_sha256'][old],'Debug probe imported digest changed')
    transport=fixtures['hex_transport'];original=assemble_program(read(reference/transport['original_path'])).as_dict()
    exact(sha(read(reference/transport['original_path'])),transport['original_sha256'],'hex fixture source owner changed')
    f=original['functions'][0];block=next(b for b in f['blocks'] if b['id']=='b22')
    operation=next(o for o in block['ops'] if o.get('out')==[{'name':'v183','type':'u64'}])
    exact(operation['attrs'],{'value':1},'hex original dispatch constant differs');operation['attrs']['value']=4
    block=next(b for b in f['blocks'] if any(o.get('out')==[{'name':'v616','type':'u64'}] for o in b['ops']))
    index=next(i for i,o in enumerate(block['ops']) if o.get('out')==[{'name':'v616','type':'u64'}])
    exact(block['ops'][index]['args'],['v540','v615','v598'],'hex original target operand differs')
    block['ops'].insert(index,{'op':'const','args':[],'attrs':{'value':4},'out':[{'name':'v651','type':'u64'}]})
    block['ops'][index+1]['args'][-1]='v651'
    exact(assemble_program(read(root/'tests/hia_native/batch_apply_hex_transport.hepta')).as_dict(),original,'hex fixture changed beyond its fixed target')
    exact(sha(read(root/'tests/hia_native/batch_apply_hex_transport.hepta')),transport['source_sha256'],'hex fixture source changed')
    return {'source_sha256':proof['source_sha256'],'editable_source_sha256':child['source_sha256'],
        'composition_sha256':sha(read(root/'native/batch_apply_composition.json')),'fixtures_sha256':sha(read(root/'native/batch_apply_fixtures.json')),
        'bulk_composition_sha256':sha(read(root/'native/editable_bulk_composition.json')),
        'imported_functions':count,'unchanged_editable_functions':20,'debug_imported_functions':len(reverse),
        'debug_properties_sha256':PROPERTIES_SHA,'original_sources':proof['original_sources']}

def framed_stream(path,magic,rows,*,side):
    digest=hashlib.sha256();total=0;prefixes=[]
    with gzip.open(path,'rb') as stream:
        header=stream.read(8);exact(header,magic,'corpus stream tag differs');digest.update(header);total+=8
        for index,row in enumerate(rows):
            prefix=stream.read(8);require(len(prefix)==8,'corpus record prefix was truncated')
            size=struct.unpack('<Q',prefix)[0]
            exact(size,row[side+'_bytes'],'corpus record size differs')
            require(size<=1073741824,'corpus record exceeded declared buffer profile')
            digest.update(prefix);total+=8;item=hashlib.sha256();left=size;first=bytearray()
            while left:
                data=stream.read(min(1<<20,left));require(data,'corpus record was truncated')
                item.update(data);digest.update(data);total+=len(data);left-=len(data)
                if len(first)<112:first.extend(data[:112-len(first)])
            exact(item.hexdigest(),row[side+'_sha256'],'corpus record bytes differ')
            if side=='input':require(first[:8]==b'HBACT001' and size>=112,'apply input frame differs')
            else:
                require(first[:8]==b'HBAPLR01' and size>=80,'apply output frame differs')
                words=struct.unpack_from('<9Q',first,8)
                require(words[0] in (0,1) and words[2] in (1,2) and words[3] in (0,1),'apply result metadata differs')
                require(words[7]+words[8]==size-80,'apply output sections differ')
                require((words[0]==0 and words[8]==0) or (words[0]==1 and words[1]==words[7]==0 and words[8]>0),'apply semantic result domain differs')
            prefixes.append(bytes(first))
        require(stream.read(1)==b'','corpus has unaccounted trailing rows')
    return {'bytes':total,'sha256':digest.hexdigest(),'prefixes':prefixes}

def trace_counts(row,*,reference):
    trace=row['trace'];require(type(trace) is list and len(trace)<=3,'invalid apply continuation count')
    phases=[r['phase'] for r in trace]
    require(phases in ([],[1],[1,2],[1,3],[1,2,3]),'apply continuation order differs')
    for item in trace:
        require(item['target']==5 and type(item['code']) is int and 0<=item['code']<=0xffffffff,'wrong child owner or code')
        require(type(item['input_bytes']) is int and 48<=item['input_bytes']<=536870912,'child input size differs')
        for key in ('input_sha256','output_sha256'):
            value=item[key];require(type(value) is str and len(value)==64 and all(c in '0123456789abcdef' for c in value),'child byte digest differs')
        if reference:require(item['code']>=80 and item['code']<0xffff0000,'reference result had a child refusal')
    exact(row['controller_calls'],1+len(trace),'controller call accounting differs')
    exact(row['editable_calls'],len(trace),'Editable call accounting differs')
    for flag in ('input_unchanged','guards_unchanged','output_tail_unchanged'):
        exact(row[flag],True,'native immutability/guard check missing')
    require(type(row['cleared_prefix_bytes']) is int and 0<=row['cleared_prefix_bytes']<=row['workspace_capacity'],'private cleanup range differs')
    if row['workspace_capacity']>=24832:require(row['cleared_prefix_bytes']>=24576,'private metadata was not erased')
    return 1+len(trace),len(trace)

def corpus_evidence(directory,bundle,closure,pins):
    directory=Path(directory);value=json_file(directory/'native-corpus.json')
    for key,wanted in {'schema':'hepta.runtime.batch-apply-native.v1','status':'PASS','development_small':False,
        'original_replay_cases':CASES,'groups':GROUPS,'counts':NATIVE_COUNTS,
        'loaded_artifacts':bundle['loaded_artifacts'][3:],'bundle_sha256':bundle['manifest_sha256'],
        'source_contract':closure,'execution_source_pins':pins,'source_sha256':closure['source_sha256']}.items():
        exact(value.get(key),wanted,'native complete-corpus declaration differs: '+key)
    require(type(value['elapsed_seconds']) in (int,float) and 0<value['elapsed_seconds']<180,'native suite missed unchanged deadline')
    rows=value['rows'];controls=value['controls'];require(len(rows)==CASES and len(controls)==146,'native history has missing rows')
    domains=collections.Counter();controllers=leaves=0
    for index,row in enumerate(rows):
        exact(row['ordinal'],index,'native reference row order differs')
        domains[row['domain']]+=1;a,b=trace_counts(row,reference=True);controllers+=a;leaves+=b
    request=framed_stream(directory/'requests.bin.gz',b'HBAREQ01',rows,side='input')
    response=framed_stream(directory/'native-output.bin.gz',b'HBARES01',rows,side='output')
    for index,row in enumerate(rows):
        mode=struct.unpack_from('<Q',request['prefixes'][index],8)[0]
        status=struct.unpack_from('<Q',response['prefixes'][index],8)[0]
        wanted=[1] if status else [1,3] if mode==0 else [1,2] if mode==1 else [1,2,3]
        exact([item['phase'] for item in row['trace']],wanted,'native successful/semantic-refusal trace differs')
    for index,row in enumerate(controls):
        exact(row['ordinal'],index,'native refusal row order differs')
        require(row['domain'] in ('invalid_frames','capacity_refusals'),'unclassified native control')
        domains[row['domain']]+=1
        exact(row['code'],0xffffffff if row['domain']=='invalid_frames' else 0xfffffffe,'wrong native refusal code')
        exact(sha(bytes.fromhex(row['input_hex'])),row['input_sha256'],'refusal input digest differs')
        exact(row['output_hex'],'','native refusal leaked result bytes');exact(row['output_bytes'],0,'refusal output length differs')
        exact(row['output_sha256'],sha(b''),'native refusal digest differs')
        a,b=trace_counts(row,reference=False);controllers+=a;leaves+=b
    exact(dict(domains),GROUPS,'complete native history domain counts differ')
    exact({'requests':len(rows)+len(controls),'native_controller_calls':controllers,'native_editable_calls':leaves},NATIVE_COUNTS,'native actual-call history count differs')
    for name,wanted in [('requests.bin.gz',value['corpus_files']['requests.bin.gz']),('native-output.bin.gz',value['corpus_files']['native-output.bin.gz'])]:
        exact(file_record(directory/name),wanted,'complete gzip artifact changed')
    for found,prefix,digest,size in [(request,'requests',REQUEST_SHA,293448899),(response,'native_output',OUTPUT_SHA,301354944)]:
        exact(found['sha256'],digest,'complete raw corpus digest differs');exact(found['bytes'],size,'complete raw corpus byte count differs')
        exact(value[prefix+'_sha256'],digest,'declared raw corpus digest differs');exact(value[prefix+'_bytes'],size,'declared raw corpus byte count differs')
    return {'schema':'hepta.runtime.batch-apply-corpus-evidence.v1','status':'PASS','cases':CASES,
        'input_sha256':REQUEST_SHA,'input_bytes':request['bytes'],'native_output_sha256':OUTPUT_SHA,
        'native_output_bytes':response['bytes'],'counts':NATIVE_COUNTS,'groups':GROUPS,
        'metadata_sha256':sha(read(directory/'native-corpus.json')),'corpus_files':value['corpus_files'],
        'rows':rows}

def contract_evidence(path,bundle,closure,pins):
    value=json_file(path)
    for key,wanted in {'schema':'hepta.runtime.batch-apply-contract.v1','status':'PASS',
        'counts':CONTRACT_COUNTS,'requests':103,'fault_cases':102,'successful_exact_capacity_cases':1,
        'loaded_artifacts':bundle['loaded_artifacts'][3:],'bundle_sha256':bundle['manifest_sha256'],
        'execution_source_pins':pins,'source_sha256':closure['source_sha256']}.items():
        exact(value.get(key),wanted,'native contract evidence differs: '+key)
    require(0<value['elapsed_seconds']<180,'contract suite missed unchanged deadline')
    exact([r['phase'] for r in value['success_trace']],[1,2,3],'exact-capacity success lost a child call')
    wanted_names=set()
    for phase in (1,2,3):
        wanted_names.update(f'footer_{offset}_phase_{phase}' for offset in (0,8,16,24,32,40,48,56,64,72,80,88,96,104,120,128))
        wanted_names.update(f'result_{offset}_phase_{phase}' for offset in (0,8,16,24,32,40,48,56,64,72))
        wanted_names.update(f'{name}_phase_{phase}' for name in ('child_invalid','child_capacity','utf8','unknown',
            'input_capacity_changed','output_capacity_changed','known_private_bytes_cleared'))
    wanted_names.update(('sequence_exhausted','wrong_initial_event','wrong_initial_caller'))
    rows=value['rows'];exact(len(rows),102,'contract rows missing')
    exact({r['case'] for r in rows},wanted_names,'contract control domain changed')
    controllers=4;leaves=3
    for row in rows:
        phase=row['phase'];require(phase in (None,1,2,3),'contract control phase differs')
        exact(row['fault_applied'],[] if phase is None else [phase],'fault injection was not observed')
        exact(row['code'],0xfffffffe if row['case'].startswith('child_capacity_') else 0xfffffff8,'contract refusal code differs')
        exact(row['editable_calls'],0 if phase is None else phase,'contract actual child count differs')
        exact(row['controller_calls'],row['editable_calls']+1,'contract controller count differs')
        for flag in ('output_untouched','input_unchanged','guards_unchanged'):exact(row[flag],True,'contract integrity check missing')
        exact(row['output_bytes'],0,'contract refusal exposed output')
        require(row['cleared_prefix_bytes']>=24576 and row['cleared_prefix_bytes']+row['workspace_tail_bytes']==row['workspace_capacity']-256,'contract cleanup bound differs')
        controllers+=row['controller_calls'];leaves+=row['editable_calls']
    exact({'requests':103,'native_controller_calls':controllers,'native_editable_calls':leaves},CONTRACT_COUNTS,'contract complete actual-call counts differ')
    return {'status':'PASS','fault_cases':102,'counts':CONTRACT_COUNTS,'receipt_sha256':sha(read(path))}

def artifact_evidence(directory,bundle,closure,pins,corpus):
    directory=Path(directory);value=json_file(directory/'result.json')
    fixed={'schema':'hepta.runtime.batch-apply-artifacts.v1','status':'PASS',
        'bundle_sha256':bundle['manifest_sha256'],'source_contract':closure,'execution_source_pins':pins,
        'native_debug_probe_calls':1,'unicode_codepoints':1114112,'unicode_valid_scalars':1112064,'unicode_surrogates':2048,
        'native_debug_properties_sha256':PROPERTIES_SHA,'native_debug_probe_manifest_sha256':bundle['probe_manifest_sha256'],
        'native_plan_counts':{'requests':8,'native_controller_calls':30,'native_endpoint_calls':15,'native_verify_calls':7},
        'native_apply_counts':{'requests':8,'native_controller_calls':26,'native_editable_calls':18},
        'joined_loaded_artifacts':bundle['loaded_artifacts'],'original_cases_added_by_join':0,
        'real_elf_processes':1,'real_elf_requests':8,'real_elf_capacity_refusals':1,'real_elf_invalid_refusals':1,
        'elf_sha256':bundle['composition']['executable_sha256'],'elf_returncode':0,
        'runtime_python_required':False,'production_activated':False,'original_rust_executions_in_this_suite':0}
    for key,wanted in fixed.items():exact(value.get(key),wanted,'actual artifact evidence differs: '+key)
    require(0<value['elapsed_seconds']<180,'artifact suite missed unchanged deadline')
    exact(file_record(directory/'native-debug-properties.bin'),{'bytes':1114112,'sha256':PROPERTIES_SHA},'complete native Unicode flags changed')
    for name,key,digest in [('elf-input.txt','elf_input_sha256','eea71f3822e1d231149fd863083622d05af4cbbfe08b8dc538231618578d627f'),
        ('elf-output.txt','elf_output_sha256','9fc432dc80b4e2088d5539246346c29ce021355bc3a48874bff516038cf30c2a'),
        ('elf-stderr.txt','elf_stderr_sha256',sha(b''))]:
        exact(sha(read(directory/name)),digest,'actual ELF stream changed');exact(value[key],digest,'ELF stream declaration differs')
    require(read(directory/'elf-input.txt').count(b'\n')==read(directory/'elf-output.txt').count(b'\n')==8,'actual ELF request accounting differs')
    require(len(value['joined_cases'])==8,'native planner/apply join incomplete')
    for index,row in enumerate(value['joined_cases']):
        exact(row['original_corpus_ordinal'],index,'joined case original identity differs')
        original=corpus['rows'][index]
        exact(row['apply_input_sha256'],original['input_sha256'],'join did not use a complete original-replayed request')
        exact(row['apply_output_sha256'],original['output_sha256'],'join did not return the complete original-replayed result')
        exact(row['apply_output_bytes'],original['output_bytes'],'joined result length differs')
        plan=bytes.fromhex(row['planner_output_hex']);require(plan[:8]==b'HBPLR001' and struct.unpack_from('<Q',plan,8)[0]==0,'joined native plan was not successful')
    return {'status':'PASS','receipt_sha256':sha(read(directory/'result.json')),
        'unicode_codepoints':1114112,'joined_cases':8,'real_elf_requests':8,
        'elf_sha256':value['elf_sha256'],'native_plan_counts':value['native_plan_counts'],'native_apply_counts':value['native_apply_counts']}

def evidence(corpus_dir,contract_path,artifact_dir,bundle_path,*,source_root=ROOT,reference_root=None,hepta=None):
    root=Path(source_root);reference=Path(reference_root or root)
    closure=source_contract(root,reference,hepta);pins=execution_source_pins(root,reference)
    bundle=inspect_bundle(bundle_path,source_root=root,reference_root=reference)
    corpus=corpus_evidence(corpus_dir,bundle,closure,pins)
    contract=contract_evidence(contract_path,bundle,closure,pins)
    artifacts=artifact_evidence(artifact_dir,bundle,closure,pins,corpus)
    return {'schema':'hepta.runtime.batch-apply-qualification.v1','status':'PASS','source_contract':closure,
        'source_pins':pins,'bundle_sha256':bundle['manifest_sha256'],
        'native_image_sha256':bundle['loaded_artifacts'][3]['image_sha256'],
        'editable_image_sha256':bundle['loaded_artifacts'][4]['image_sha256'],
        'compiler_receipts_sha256':sha(canonical({'wide':bundle['wide_compilation_receipts'],
            'packed':bundle['composition']['compilation_receipts'],'probe':bundle['probe_compilation_receipts']})),
        'corpus':{k:v for k,v in corpus.items() if k!='rows'},'contract':contract,'artifacts':artifacts,
        'complete_original_tool_parity':False,'production_activated':False,'whole_runtime_replaced':False}

def original_blocks(reference):
    text=read(Path(reference)/'src/mcp/fs/text_editing.rs').decode()
    line=read(Path(reference)/'src/utils/line_hash.rs').decode()
    def section(raw,start,end):return raw[raw.index(start):raw.index(end)]
    return {
        'batch_operation':section(text,'#[derive(Debug, Clone)]\nstruct BatchOperation','// Unresolved batch operation'),
        'operation_type_and_range':section(text,'#[derive(Debug, Clone, PartialEq)]\nenum OperationType','#[derive(Debug, Clone)]\nenum UnresolvedLineRange'),
        'editable_and_incoming':section(text,'const LF_ENDING:','fn sanitize_incoming_content'),
        'guards_and_apply':section(text,'fn is_structural_noise',"// Parse an operation's `start`"),
        'batch_guards':section(text,'\t// Check for conflicts between operations','\n\tlet edited = apply_batch_operations'),
        'line_ids':section(line,'fn fnv1a_8','/// Verify a composite id'),
    }

def prepare_original_reference(destination,native_evidence,corpus_dir,artifact_dir,*,source_root=ROOT,reference_root=None):
    """Materialize exact reviewed inputs after the caller has checked evidence()."""
    root=Path(source_root);reference=Path(reference_root or root);destination=Path(destination)
    require(native_evidence['schema']=='hepta.runtime.batch-apply-qualification.v1' and native_evidence['status']=='PASS','native qualification is required')
    exact(native_evidence['source_pins'],execution_source_pins(root,reference),'native source closure changed before reference preparation')
    require(destination.is_absolute() and not destination.exists(),'reference project must be an absent absolute directory')
    blocks=original_blocks(reference);oracle=read(root/'tests/hia_native/oracle_batch_apply.rs').decode()
    require(all(oracle.count(body)==1 for body in blocks.values()),'original Rust owner body changed')
    files={'oracle.rs':root/'tests/hia_native/oracle_batch_apply.rs','driver.py':root/'tests/hia_native/compare_batch_apply_original.py',
        'text_editing.rs':reference/'src/mcp/fs/text_editing.rs','line_hash.rs':reference/'src/utils/line_hash.rs',
        'requests.gz':Path(corpus_dir)/'requests.bin.gz','expected.gz':Path(corpus_dir)/'native-output.bin.gz',
        'rust_debug_properties.rs':root/'tests/hia_native/rust_debug_properties.rs',
        'rust_debug_properties.json':root/'tests/hia_native/rust_debug_properties.json',
        'native-debug-properties.bin':Path(artifact_dir)/'native-debug-properties.bin'}
    destination.mkdir()
    for name,path in files.items():
        with (destination/name).open('xb') as stream:stream.write(read(path))
    block_records={name:{'bytes':len(body.encode()),'sha256':sha(body.encode())} for name,body in blocks.items()}
    (destination/'original-blocks.json').write_text(json.dumps(block_records,indent=2,sort_keys=True)+'\n')
    (destination/'native-evidence.json').write_text(json.dumps(native_evidence,indent=2,sort_keys=True)+'\n')
    manifest={'schema':'hepta.runtime.batch-apply-original-input.v1','kind':'batch_apply','oracle':'oracle.rs',
        'requests':'requests.gz','expected':'expected.gz','original_text_editing':'text_editing.rs','original_line_hash':'line_hash.rs',
        'original_blocks':'original-blocks.json','cases':CASES,'source_sha256':native_evidence['source_contract']['source_sha256'],
        'image_sha256':native_evidence['native_image_sha256'],'editable_source_sha256':native_evidence['source_contract']['editable_source_sha256'],
        'editable_image_sha256':native_evidence['editable_image_sha256'],'native_evidence_sha256':sha(canonical(native_evidence)),
        'requests_sha256':REQUEST_SHA,'requests_bytes':293448899,'native_output_sha256':OUTPUT_SHA,'native_output_bytes':301354944}
    manifest['files']={name:file_record(destination/name) for name in [*files,'original-blocks.json','native-evidence.json']}
    path=destination/'input.json';path.write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
    return path

def check_original_runtime_summary(path,result,expected):
    raw=read(path)
    exact(sha(raw),result.get('original_stderr_sha256'),'actual original runtime stderr bytes changed')
    exact(len(raw),result.get('original_stderr_bytes'),'actual original runtime stderr size changed')
    exact(canonical(json_file(path)),canonical(expected),'actual original runtime stderr summary changed')

def original_comparison_evidence(project,*,source_root=ROOT):
    project=Path(project);root=Path(source_root);manifest=json_file(project/'input.json')
    result=json_file(project/'replay/result.json')
    fixed={'schema':'hepta.runtime.batch-apply-original-comparison.v1','status':'PASS','kind':'batch_apply',
        'cases':CASES,'original_runtime_calls':CASES,'original_rust_executions':2,'native_calls_added':0,
        'input_files_unchanged':True,'timed_out':False,'timeout_seconds':180,
        'requests_sha256':REQUEST_SHA,'requests_bytes':293448899,'output_sha256':OUTPUT_SHA,'output_bytes':301354944,
        'original_summary':{'status':'PASS','rust_oracle_cases':CASES,'output_bytes':301354944},
        'native_source_sha256':manifest['source_sha256'],'native_image_sha256':manifest['image_sha256'],
        'editable_source_sha256':manifest['editable_source_sha256'],'editable_image_sha256':manifest['editable_image_sha256'],
        'native_evidence_sha256':manifest['native_evidence_sha256'],'manifest_sha256':sha(read(project/'input.json')),
        'oracle_sha256':sha(read(root/'tests/hia_native/oracle_batch_apply.rs')),
        'driver_sha256':sha(read(root/'tests/hia_native/compare_batch_apply_original.py'))}
    for key,wanted in fixed.items():exact(result.get(key),wanted,'actual original replay declaration differs: '+key)
    exact(result['input_files'],manifest['files'],'reference input identity set differs')
    for name,record in manifest['files'].items():exact(file_record(project/name),record,'reference input changed after actual replay')
    require(result['compiler_version'].startswith('rustc 1.95.0 '),'original Rust toolchain differs')
    exact(sha(read(project/'replay/original-oracle')),result['binary_sha256'],'original executable changed')
    exact(sha(read(project/'replay/original-debug-properties')),result['debug_reference']['binary_sha256'],'Debug executable changed')
    exact(sha(read(project/'replay/debug-original.stdout')),sha(read(root/'tests/hia_native/rust_debug_properties.json')),'actual complete Debug reference changed')
    exact(read(project/'replay/debug-original.stderr'),b'','Debug reference emitted stderr')
    check_original_runtime_summary(project/'replay/original.stderr',result,fixed['original_summary'])
    debug=result['debug_reference']
    for key,wanted in {'native_flags_sha256':PROPERTIES_SHA,'codepoints':1114112,'valid_scalars':1112064,
        'surrogates':2048,'target_format_comparisons':4448256,'prefix_format_comparisons':4448256,'unicode':[17,0,0],
        'source_sha256':sha(read(root/'tests/hia_native/rust_debug_properties.rs'))}.items():exact(debug.get(key),wanted,'Debug actual-domain proof differs')
    digest=hashlib.sha256();size=0
    with gzip.open(project/'replay/original-output.gz','rb') as handle:
        for part in iter(lambda:handle.read(1<<20),b''):digest.update(part);size+=len(part)
    exact(digest.hexdigest(),OUTPUT_SHA,'actual original complete output changed');exact(size,301354944,'actual original output was truncated')
    return {'schema':'hepta.runtime.batch-apply-original-evidence.v1','status':'PASS','cases':CASES,
        'original_runtime_calls':CASES,'original_rust_executions':2,'native_calls_added':0,
        'debug_reference':debug,'native_evidence_sha256':manifest['native_evidence_sha256'],
        'output_sha256':OUTPUT_SHA,'output_bytes':size,'receipt_sha256':sha(read(project/'replay/result.json')),
        'original_executable_sha256':result['binary_sha256'],'source_sha256':manifest['source_sha256'],
        'complete_original_tool_parity':False,'production_activated':False}
