"""Reproduce a typed CustomRequest dispatch after actual G1 and G2 admission."""
from pathlib import Path
import copy,hashlib,json,sys
ROOT=Path(__file__).resolve().parent
ENC=lambda v:(json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
CAN=lambda v:json.dumps(v,sort_keys=True,separators=(',',':')).encode()
SHA=lambda b:hashlib.sha256(b).hexdigest()
PIN=lambda b:{'bytes':len(b),'sha256':SHA(b)}
def apply(source,hepta):
    source,hepta=Path(source).resolve(strict=True),Path(hepta).resolve(strict=True)
    inputs=json.loads((ROOT/'INPUTS.json').read_bytes());binding_path=source/'native/runtime_mcp_sources.json'
    original_binding=binding_path.read_bytes();assert SHA(original_binding)==inputs['baseline_binding']
    original_rows={p.relative_to(source).as_posix():PIN(p.read_bytes()) for p in source.rglob('*') if p.is_file()}
    assert len(original_rows)==inputs['baseline_files']==432
    assert json.loads(original_binding)['sources']=={n:r for n,r in original_rows.items() if n!='native/runtime_mcp_sources.json'}
    sys.path.insert(0,str(source/'authoring/public_extract'))
    import source_support as support
    assert SHA(Path(support.__file__).read_bytes())==inputs['support_sha256']
    api=support.tools(hepta);assemble,render=api[-2:]
    name='native/sdk_public_protocol.hepta';before=(source/name).read_bytes()
    assert PIN(before)==inputs['protocol_before']
    previous=assemble(before).as_dict();assert len(previous['functions'])==22
    composition_raw=(source/'native/sdk_public_protocol_composition.json').read_bytes();composition=json.loads(composition_raw)
    assert PIN(composition_raw)==inputs['composition_before']
    pseudo=(ROOT/'custom_request.pseudo').read_text()
    generated,names,delta=support.compile_delta(api,before,composition['aliases'],pseudo,composition['constants'],previous['module'])
    document=assemble(generated).as_dict();functions={f['name']:f for f in document['functions']}
    assert names['noncall_request']=='f22' and len(document['functions'])==28
    old=copy.deepcopy(functions['f11']);block=next(b for b in functions['f11']['blocks'] if b['id']=='b34')
    assert block['params']==[{'name':'v356','type':'mutbuf'},{'name':'v357','type':'mutbuf'}]
    original_block=copy.deepcopy(block)
    assert [op['op'] for op in original_block['ops']]==['const','const','const','const','call','const','call']
    assert original_block['ops'][-1]['attrs']=={'function':'f5'}
    assert original_block['term']=={'op':'ret','values':['v370']}
    block['ops']=[{'out':[{'name':'v373','type':'u32'}],'op':'call','args':['v356','v357'],'attrs':{'function':names['noncall_request']}}]
    block['term']={'op':'ret','values':['v373']}
    after,stats=support.checked_program(api,document)
    assert all(previous['functions'][i]==document['functions'][i] for i in range(22) if i!=11)
    inverse=copy.deepcopy(functions['f11']);next(b for b in inverse['blocks'] if b['id']=='b34').update(original_block)
    assert inverse==old==previous['functions'][11]
    changes={}
    def save(n,b):
        path=source/n;oldraw=path.read_bytes() if path.exists() else None
        path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b)
        changes[n]={'before':PIN(oldraw) if oldraw is not None else None,'after':PIN(b)}
    save(name,after)
    for n in ('author.py','INPUTS.json','custom_request.pseudo'):save('authoring/public_custom_request/'+n,(ROOT/n).read_bytes())
    proof={'schema':'hepta.runtime.typed-custom-request-overlay.v1','inputs':inputs,'source':PIN(after),
        'retained_original_functions':{f['name']:SHA(CAN(f)) for f in previous['functions'] if f['name']!='f11'},
        'changed_function':'f11','changed_block':'b34','original_block':original_block,'new_block':block,
        'inverse_original_function_ast_exact':True,'other_original_blocks_exact':True,'aliases':names,
        'generated_functions':delta['generated_functions'],'statistics':stats,'native_or_rust_executions':0,
        'typed_method_and_canonical_id_only':True,'metadata_and_protocol_admission_precede_dispatch':True,
        'raw_method_text_never_reclassified':True,'non_custom_fallback_action_exact':True,
        'error_code':-32601,'error_message_is_complete_typed_method':True,'full_sdk_qualified':False}
    save('native/sdk_public_custom_request_composition.json',ENC(proof))
    old_composition=copy.deepcopy(composition);composition['source_bytes']=len(after);composition['source_sha256']=SHA(after)
    composition['functions']=len(document['functions']);composition['aliases']=names
    composition['current_typed_custom_request_extension']={'source':PIN(after),'before':PIN(before),
        'proof':PIN(ENC(proof)),'g1_kind':1,'g1_variant':19,'g2_admitted_kind':2,
        'g1_method_pair':64,'g1_canonical_id_pair':80,'raw_method_reparse':False,
        'full_sdk_qualified':False,'whole_runtime_replaced':False}
    restored=copy.deepcopy(composition);del restored['current_typed_custom_request_extension']
    for k in ('source_bytes','source_sha256','functions','aliases'):restored[k]=old_composition[k]
    assert restored==old_composition and ENC(restored)==composition_raw
    save('native/sdk_public_protocol_composition.json',ENC(composition))
    text=original_binding.decode();needle='\n  "sources": ';assert text.count(needle)==1
    start=text.index(needle)+len(needle);oldrows,end=json.JSONDecoder().raw_decode(text[start:])
    assert oldrows=={n:r for n,r in original_rows.items() if n!='native/runtime_mcp_sources.json'}
    newrows={p.relative_to(source).as_posix():PIN(p.read_bytes()) for p in source.rglob('*') if p.is_file() and p!=binding_path}
    replacement=json.dumps(newrows,sort_keys=True,indent=2).replace('\n','\n  ')
    text=text[:start]+replacement+text[start+end:]
    extension={'g1_kind':1,'g1_variant':19,'g2_admitted_kind':2,'before':PIN(before),'source':PIN(after),
        'composition':PIN(ENC(proof)),'whole_public_domain_qualified':False}
    payload=json.dumps(extension,sort_keys=True,indent=2).replace('\n','\n  ')
    text=text.replace(needle,'\n  "typed_custom_request_extension": '+payload+','+needle)
    save('native/runtime_mcp_sources.json',text.encode())
    rows={p.relative_to(source).as_posix():PIN(p.read_bytes()) for p in source.rglob('*') if p.is_file()}
    assert len(rows)==436
    assert all(rows[n]==r for n,r in original_rows.items() if n not in changes)
    return {'schema':'hepta.runtime.public-custom-request-source-author.v1','source_files':rows,'changed_files':changes,
        'source_binding_sha256':SHA(binding_path.read_bytes()),'baseline_source':inputs['baseline_source'],
        'source_proof':proof,'runtime_hia_images':118,'descriptor_slots':64,'installed_handlers':10,
        'native_or_rust_executed':False,'full_sdk_qualified':False,'public_wait_qualified':False,'whole_runtime_replaced':False}
