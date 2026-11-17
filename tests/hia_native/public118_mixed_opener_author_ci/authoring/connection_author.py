"""Narrow G2 pre-serve continuation and explicit observed EOF source successor."""
from pathlib import Path
import copy,hashlib,json,re
SHA=lambda b:hashlib.sha256(b).hexdigest()
CAN=lambda v:json.dumps(v,sort_keys=True,separators=(',',':')).encode()
PIN=lambda b:{'bytes':len(b),'sha256':SHA(b)}
ENC=lambda v:(json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
ROOT=Path(__file__).resolve().parent
ERROR=b'Error: connection closed: initialize request\n'
def generate(source,api,support,inputs,save):
    assemble,render=api[-2:]
    name='native/sdk_connection_target.hepta';before=(source/name).read_bytes()
    assert PIN(before)==inputs['g2_before']
    doc=assemble(before).as_dict();assert len(doc['functions'])==26
    original=copy.deepcopy(doc)
    f5=doc['functions'][5]
    missing=next(b for b in f5['blocks'] if b['id']=='b19');old_missing=copy.deepcopy(missing)
    mode=next(o for o in missing['ops'] if o['out']==[{'name':'v208','type':'u64'}])
    assert mode['op']=='const' and mode['attrs']=={'value':3};mode['attrs']['value']=0
    close=next(o for o in missing['ops'] if o['out']==[{'name':'v212','type':'u64'}])
    assert close['op']=='call' and close['attrs']=={'function':'f25'} and close['args']==['v188','v211','v200']
    close['args']=['v188','v211','v208']
    unsupported=next(b for b in f5['blocks'] if b['id']=='b24');old_unsupported=copy.deepcopy(unsupported)
    assert unsupported['params']==[{'name':'v254','type':'readbuf'},{'name':'v255','type':'mutbuf'}]
    additions=[
      {'out':[{'name':'v496','type':'u64'}],'op':'const','args':[],'attrs':{'value':8}},
      {'out':[{'name':'v497','type':'u64'}],'op':'call','args':['v255','v496'],'attrs':{'function':'f24'}},
      {'out':[{'name':'v498','type':'u64'}],'op':'const','args':[],'attrs':{'value':520}},
      {'out':[{'name':'v499','type':'u64'}],'op':'call','args':['v255','v498','v497'],'attrs':{'function':'f25'}},
    ]
    unsupported['ops']=additions+unsupported['ops']
    restored=copy.deepcopy(f5)
    next(b for b in restored['blocks'] if b['id']=='b19').update(old_missing)
    next(b for b in restored['blocks'] if b['id']=='b24').update(old_unsupported)
    assert restored==original['functions'][5]
    saved=copy.deepcopy(doc['functions'][0]);saved['name']='f26';doc['functions'].append(saved)
    base=render(doc).encode()
    aliases={'entry':'f0','retained_entry':'f26','read':'f23','get':'f24','put':'f25','valid_state':'f1'}
    pseudo=(ROOT/'connection_eof.pseudo').read_text()
    rows=['def eof_literal(o:mutbuf,at:u64) -> u64:']
    for at in range(0,len(ERROR)//8*8,8):
        rows.append('    put(o, at + '+str(at)+', '+str(int.from_bytes(ERROR[at:at+8],'little'))+')')
    for at in range(len(ERROR)//8*8,len(ERROR)):
        rows.append('    store(o, at + '+str(at)+', '+str(ERROR[at])+')')
    rows.append('    return 0')
    pseudo+='\n'+'\n'.join(rows)+'\n'
    constants={'QUERY':int.from_bytes(b'HRCNQ001','little'),'EOF_RESULT':int.from_bytes(b'HRCEOF01','little'),
        'STATE_MAGIC':3544425623512633928,'EOF_SIZE':len(ERROR),'INVALID':0xffffffff,'RESOURCE':0xfffffffe}
    after,names,delta=support.compile_delta(api,base,aliases,pseudo,constants,doc['module'])
    final=assemble(after).as_dict()
    assert len(final['functions'])==29
    assert all(final['functions'][i]==original['functions'][i] for i in range(26) if i not in (0,5))
    retained=copy.deepcopy(final['functions'][26]);retained['name']='f0'
    assert retained==original['functions'][0]
    save(name,after)
    boundary=(ROOT/'connection_eof_boundary.S').read_text()
    transport=(source/'scripts/runtime_mcp_transport.S').read_text()
    anchor='public_span_finish:\n    call pump_finish\n'
    assert transport.count(anchor)==1
    transport=transport.replace(anchor,anchor+'    call public_span_connection_eof\n    test eax,eax\n    jnz public_span_fail\n',1)
    transport+='\n'+boundary
    save('scripts/runtime_mcp_transport.S',transport.encode())
    engine=(source/'scripts/runtime_mcp_extra_engine.S').read_text()
    anchor_engine='runtime_grow_connection_result:\n'
    assert engine.count(anchor_engine)==1
    engine=engine.replace(anchor_engine,(ROOT/'connection_eof_engine.S').read_text(),1)
    save('scripts/runtime_mcp_extra_engine.S',engine.encode())
    adapter=(source/'scripts/hia_native_runtime_mcp_adapter.py').read_text()
    anchor="    return adapter+'\\n'+CALLABLE+'\\n'+transport+'\\n'+HELPERS\n"
    assert adapter.count(anchor)==1
    patch=("    eof_boundaries=transport.count('\\npublic_span_connection_eof:\\n')\n"
           "    if eof_boundaries not in (0,1):raise ValueError('duplicate actual G2 EOF boundary')\n"
           "    if eof_boundaries==1:\n"
           "        adapter=replace(adapter,'finish_ok:\\n    xor ebp, ebp\\n','finish_ok:\\n    mov ebp, dword ptr [r15 + CG_PUBLIC_EOF_EXIT]\\n')\n")
    adapter=adapter.replace(anchor,patch+anchor,1)
    save('scripts/hia_native_runtime_mcp_adapter.py',adapter.encode())
    proof={'schema':'hepta.runtime.g2-observed-eof-source.v1','baseline':PIN(before),'source':PIN(after),
        'locked_sdk_source':inputs['locked_sdk_source'],'old_functions_retained_exactly':[f'f{i}' for i in range(26) if i not in (0,5)],
        'retained_f0':'f26','f5_inverse_exact':True,'missing_metadata_before':old_missing,
        'missing_metadata_after':next(b for b in final['functions'][5]['blocks'] if b['id']=='b19'),
        'unsupported_version_before':old_unsupported,'unsupported_version_after':next(b for b in final['functions'][5]['blocks'] if b['id']=='b24'),
        'new_private_operation':3,'input_magic':'HRCNQ001','output_magic':'HRCEOF01',
        'output_header_bytes':32,'output_fields':{'exit_status':8,'stderr_offset':16,'stderr_length':24},
        'private_op2_retained':True,'eof_uses_actual_persistent_g2_mode':True,
        'pre_serve_metadata_and_unsupported_version_keep_receive_loop':True,
        'stderr_source_literal':ERROR.decode(),'stderr_literal':PIN(ERROR),'exit_field_config_context':920,
        'host_json_policy':False,'host_calls_fixed_g2_slot':55,'host_retains_config_teardown':True,
        'old_stdout_write_helper_unchanged':True,'private_filesystem_fixture_finish_unchanged':True,
        'eof_exit_load_only_with_actual_g2_boundary':True,'compiler':delta,'aliases':names,
        'native_or_rust_executions':0,'full_sdk_qualified':False,'public_wait_qualified':False}
    save('native/sdk_connection_eof_composition.json',ENC(proof))
    return proof
