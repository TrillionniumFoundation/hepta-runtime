"""Reproducible source repair of the public118 extract graph; no semantic execution."""
from pathlib import Path
import argparse,copy,hashlib,json,shutil,sys
sys.dont_write_bytecode=True
SHA=lambda b:hashlib.sha256(b).hexdigest()
ENC=lambda v:(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
CAN=lambda v:json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
BASE='a521066dfa07db38e6a22bd2f03d1dae3c203cc2'
BIND='2c423747b2827c3a6d0993b89583c47691640ea44fcf5f77e6c0ed2aaaf0dc70'
SDK='fa2aed97cf22b720d85bd8d08b720aeadba3c4d6'
def pin(b):return {'bytes':len(b),'sha256':SHA(b)}
def patch(raw,old,new):
    assert raw.count(old)==1,old
    return raw.replace(old,new,1)
def generate(base,configured,hepta,output):
    assert not output.exists();source=output/'source'
    before_binding=(base/'native/runtime_mcp_sources.json').read_bytes();assert SHA(before_binding)==BIND
    before_rows=json.loads(before_binding)['sources']
    actual={p.relative_to(base).as_posix():pin(p.read_bytes()) for p in base.rglob('*') if p.is_file()}
    assert set(actual)==set(before_rows)|{'native/runtime_mcp_sources.json'} and len(actual)==425
    for n,row in before_rows.items():assert actual[n]==row,n
    ck=json.loads((configured/'CHECKPOINT.json').read_bytes());assert ck['schema']=='hepta.runtime.configured111-author-checkpoint.v1'
    selected=('runtime_mcp.hepta','sdk_public_protocol.hepta','sdk_public_protocol_composition.json','list_frontend.pseudo')
    for n in selected:
        row=next(x for x in ck['files'] if x['path']=='authored-v1/'+n);b=(configured/n).read_bytes()
        assert pin(b)=={k:row[k] for k in ('bytes','sha256')} and hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()==row['git_blob'],n
    sys.path.insert(0,str(hepta))
    from hepta.hia_agent_assembly import assemble_program,render_assembly
    original=(base/'native/runtime_mcp.hepta').read_bytes();doc=assemble_program(original).as_dict();old={f['name']:f for f in doc['functions']}
    assert len(old)==87 and set(old)=={f'f{i}' for i in range(87)}
    metadata=json.loads((base/'native/runtime_mcp_composition.json').read_bytes())
    assert metadata['source_sha256']==SHA(original) and metadata['function_sha256']=={n:SHA(CAN(f)) for n,f in old.items()}
    reference=assemble_program((configured/'runtime_mcp.hepta').read_bytes()).as_dict();ref={f['name']:f for f in reference['functions']}
    assert len(ref)==90
    restored=copy.deepcopy(ref['f88']);restored['name']='f1';assert restored==old['f1']
    restored_catalog=copy.deepcopy(ref['f84']);restored_catalog['name']='f7';assert restored_catalog==old['f7']
    relocations={'f88':'f87','f89':'f88'}
    def relocated(function,name):
        f=copy.deepcopy(function);f['name']=name
        for b in f['blocks']:
            for op in b['ops']:
                if op['op']=='call':
                    target=op['attrs']['function']
                    if target in relocations:op['attrs']['function']=relocations[target]
                    elif target=='f7':assert restored_catalog==old[target]
                    else:assert target in old and ref[target]==old[target],('unchanged typed list helper',target)
        return f
    front=copy.deepcopy(doc);front['module']='runtime_mcp'
    front['functions'][1]=relocated(ref['f1'],'f1')
    saved=copy.deepcopy(old['f1']);saved['name']='f87';front['functions'].append(saved)
    front['functions'].append(relocated(ref['f89'],'f88'))
    raw=render_assembly(front).encode();assert assemble_program(raw).as_dict()==front
    after={f['name']:f for f in front['functions']}
    assert len(after)==89 and all(after[n]==f for n,f in old.items() if n!='f1')
    stats={'functions':len(after),'blocks':sum(len(f['blocks']) for f in after.values()),'operations':sum(len(b['ops']) for f in after.values() for b in f['blocks'])}
    assert stats['functions']<=128 and stats['blocks']<=1536 and stats['operations']<=8192
    assert all(len(f['blocks'])<=256 and all(len(b['params'])<=16 for b in f['blocks']) for f in after.values())
    protocol_before=(base/'native/sdk_public_protocol.hepta').read_bytes()
    assert SHA(protocol_before)=='27f486900a1486e3a79fa32d41af45f01847f0d01e79ac3a23ea5baf0f274f5a'
    projection=(configured/'sdk_public_protocol.hepta').read_bytes()
    assert SHA(projection)=='b79868ad5363eaeea18cbc388c23635709374a4436aebe7f0b0bbb02c65a07c5'
    proof={'schema':'hepta.runtime.extract-public-callback-and-list-repair.v1','base_source':BASE,'base_binding':BIND,'sdk_base':SDK,
        'author_sha256':SHA(Path(__file__).read_bytes()),'source_sha256':SHA(raw),'source_bytes':len(raw),**stats,
        'unchanged_old_functions':{n:SHA(CAN(f)) for n,f in old.items() if n!='f1'},'retained_after_protocol':'f87',
        'configured111_checkpoint_blob':'67eccd5deece2b74f2e7c62ecc0b1739740d087e','typed_list_function_relocations':relocations,
        'configured102_qualified_source':'b82386d285b8397e21e67dac42318dd6c15b4da6','protocol_before':pin(protocol_before),'protocol_after':pin(projection),
        'catalog_semantic_owner_unchanged':True,'catalog_installed_set_unchanged':True,'full_configured_catalog_presence_extension_installed':False,
        'new_slots':[],'extract_slots':[59,60,61,62,63],'extract_context_offsets':[456,464],
        'native_executed':False,'rust_executed':False,'public_handler_qualified':False,'full_async_cancellation_qualified':False,'whole_runtime_replaced':False}
    metadata.update(source_sha256=SHA(raw),source_bytes=len(raw),function_sha256={n:SHA(CAN(f)) for n,f in after.items()},extract_public_repair=proof)
    assert 'retained_list_protocol' not in metadata['functions'] and 'accept_current_list' not in metadata['functions']
    metadata['functions'].update(retained_list_protocol='f87',accept_current_list='f88')
    shutil.copytree(base,source)
    changes={}
    def save(n,b):
        old_raw=(base/n).read_bytes() if (base/n).exists() else None
        p=source/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b)
        changes[n]={'before':pin(old_raw) if old_raw is not None else None,'after':pin(b)}
    save('native/runtime_mcp.hepta',raw);save('native/runtime_mcp_composition.json',ENC(metadata))
    save('native/sdk_public_protocol.hepta',projection);save('native/sdk_public_protocol_composition.json',(configured/'sdk_public_protocol_composition.json').read_bytes())
    n='scripts/runtime_extract_cache_bridge.S';cache=(base/n).read_text()
    cache=patch(cache,'    cmp qword ptr [rsi + 8], 3\n    jne rec_cache_invalid\n','    cmp qword ptr [rsi + 8], 3\n    je rec_cache_operation\n    cmp qword ptr [rsi + 8], 7\n    jne rec_cache_invalid\n')
    cache=cache.replace('extract_lines cache Get/Set/Forget boundary.','extract_lines cache Get/Set/Forget/InvalidateVariants boundary.')
    save(n,cache.encode())
    n='scripts/runtime_mcp_filesystem_fixture.S';fixture=(base/n).read_text()
    anchor='    add rbx, 128\n    mov rdi, [r12 + 24]\n'
    reset="""    add rbx, 128
    /* A public process constructs this shared HIA owner before either Session.
     * Fixture operation0 requests a fresh history. First use the same owner's
     * finalize operation4, then forward the original initialize frame. Both
     * replies and every state change are produced by the actual HIA owner. */
    mov rdi, [r12 + 24]
    mov rax, 0x3130515453494848
    cmp [rdi], rax
    jne fs_fixture_extract_history_direct
    cmp qword ptr [rdi + 8], 0
    jne fs_fixture_extract_history_direct
    cmp qword ptr [r12 + 88], 64
    jne fs_fixture_extract_history_direct
    mov ecx, 16
fs_fixture_extract_history_zero_fields:
    cmp qword ptr [rdi + rcx], 0
    jne fs_fixture_extract_history_direct
    add rcx, 8
    cmp rcx, 64
    jb fs_fixture_extract_history_zero_fields
    sub rsp, 64
    mov rsi, rdi
    mov rdi, rsp
    mov ecx, 8
    rep movsq
    mov qword ptr [rsp + 8], 4
    mov rdi, rsp
    mov esi, 64
    mov rdx, [rbx + 24]
    mov rcx, [rbx + 32]
    mov r8, [rbx + 8]
    mov r9, [rbx + 16]
    call qword ptr [rbx]
    add rsp, 64
    cmp rax, 64
    jne fs_fixture_failure
    mov rdx, [rbx + 24]
    mov rax, 0x3130525453494848
    cmp [rdx], rax
    jne fs_fixture_failure
    cmp qword ptr [rdx + 8], 0
    jne fs_fixture_failure
fs_fixture_extract_history_direct:
    mov rdi, [r12 + 24]
"""
    fixture=patch(fixture,anchor,reset);save(n,fixture.encode())
    inputs={'schema':'hepta.runtime.extract-public-repair-inputs.v1','base_source':BASE,'base_binding':BIND,'configured111_checkpoint_blob':'67eccd5deece2b74f2e7c62ecc0b1739740d087e',
        'selected_configured_inputs':[x for x in ck['files'] if x['path'] in {'authored-v1/'+n for n in selected}],
        'original_semantic_run':43996474802,'native_failure_diagnostic':{'source':'c36be5b3248d093585eba465a5ce0917b7cc3a15','run':43998941322,'artifact':14290539287},
        'cache_repair_trial':{'source':'4d773184f658848ddb082178ea350b097eacdf98','run':43999484230,'artifact':14292330094,'scope':'one first public request on a diagnostic prefix; no full qualification'},
        'semantic_qualification_claimed':False}
    save('authoring/public_extract_repair/author.py',Path(__file__).read_bytes())
    save('authoring/public_extract_repair/INPUTS.json',ENC(inputs))
    proof['changed_source_files']=copy.deepcopy(changes)
    save('native/runtime_mcp_extract_repair_composition.json',ENC(proof))
    binding=json.loads(before_binding)
    rows={p.relative_to(source).as_posix():pin(p.read_bytes()) for p in source.rglob('*') if p.is_file() and p.relative_to(source).as_posix()!='native/runtime_mcp_sources.json'}
    binding['sources']=rows;save('native/runtime_mcp_sources.json',ENC(binding))
    all_rows={p.relative_to(source).as_posix():pin(p.read_bytes()) for p in source.rglob('*') if p.is_file()}
    assert len(all_rows)==428
    report={'schema':'hepta.runtime.extract-public-repaired-source.v1','baseline_commit':BASE,'baseline_binding_sha256':BIND,'sdk_baseline_commit':SDK,
        'source_files':all_rows,'source_binding_sha256':SHA((source/'native/runtime_mcp_sources.json').read_bytes()),'changed_files':changes,
        'runtime_hia_images':118,'direct_hia_members':110,'physical_images':111,'installed_catalog_tools':10,'extract_slots':[59,60,61,62,63],
        'unchanged_hia_source_files':sum(1 for n in before_rows if n.endswith('.hepta') and all_rows[n]==actual[n]),
        'native_semantics_executed':False,'rust_executed':False,'public_handler_qualified':False,'full_async_cancellation_qualified':False,'whole_runtime_replaced':False}
    (output/'AUTHOR.json').write_bytes(ENC(report));return report
if __name__=='__main__':
    p=argparse.ArgumentParser()
    for name in ('baseline','configured','hepta','output'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();r=generate(a.baseline.resolve(strict=True),a.configured.resolve(strict=True),a.hepta.resolve(strict=True),a.output.absolute())
    print(json.dumps({'source_files':len(r['source_files']),'binding':r['source_binding_sha256'],'changed_files':len(r['changed_files']),'native_semantics_executed':False},sort_keys=True))
