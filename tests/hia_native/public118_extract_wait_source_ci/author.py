"""Pure exact source author. No HIA loader/emitter/runtime or Rust execution."""
from pathlib import Path
import ast,copy,hashlib,importlib.util,json,re,stat,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
PIN=lambda raw:{'bytes':len(raw),'sha256':SHA(raw)}
CAN=lambda value:json.dumps(value,sort_keys=True,separators=(',',':')).encode()
ENC=lambda value:(json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
ASSETS=('author.py','BASELINE_SOURCE_ROWS.json','CHANGES.json','INPUTS.json',
        'frontend_cancel_wrapper.hia','runtime_extract_wait.S',
        'runtime_mcp_task_extract.S','ABI.md')
def field(raw,name,value,*,new=False):
    text=raw.decode();needle='\n  "'+name+'": '
    rendered=json.dumps(value,sort_keys=True,indent=2).replace('\n','\n  ')
    if new:
        assert needle not in text and text.startswith('{\n')
        return ('{'+needle+rendered+','+text[1:]).encode()
    assert text.count(needle)==1,name
    start=text.index(needle)+len(needle)
    _,count=json.JSONDecoder().raw_decode(text[start:])
    return (text[:start]+rendered+text[start+count:]).encode()
def fn(raw,number):
    values=re.findall(rb'^fn f'+str(number).encode()+rb'\(.*?^end\n',raw,re.M|re.S)
    assert len(values)==1
    return values[0]
def rows(root):
    result={}
    for path in sorted(root.rglob('*')):
        assert not path.is_symlink(),path
        if path.is_file():
            assert stat.S_ISREG(path.stat().st_mode),path
            result[path.relative_to(root).as_posix()]=PIN(path.read_bytes())
    return result
def apply(installed,hepta,destination):
    installed=Path(installed).resolve(strict=True)
    hepta=Path(hepta).resolve(strict=True)
    destination=Path(destination).resolve()
    assert not destination.exists()
    destination.mkdir(parents=True)
    inputs=json.loads((ROOT/'INPUTS.json').read_bytes())
    baseline=json.loads((ROOT/'BASELINE_SOURCE_ROWS.json').read_bytes())
    assert len(baseline)==inputs['baseline_files']==452
    assert len({r['path'] for r in baseline})==len(baseline)
    for row in baseline:
        name=row['path'];path=installed/name
        assert name and not name.startswith('/') and '..' not in Path(name).parts
        assert path.is_file() and not path.is_symlink(),name
        raw=path.read_bytes()
        assert PIN(raw)=={k:row[k] for k in ('bytes','sha256')},name
        assert format(stat.S_IFREG|stat.S_IMODE(path.stat().st_mode),'o')==row['mode']
        assert hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==row['git_blob']
        target=destination/name;target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(raw);target.chmod(int(row['mode'],8)&0o777)
    oldrows=rows(destination)
    binding_path=destination/'native/runtime_mcp_sources.json'
    binding_before=binding_path.read_bytes()
    assert SHA(binding_before)==inputs['baseline_binding']
    assert json.loads(binding_before)['sources']=={n:r for n,r in oldrows.items() if n!='native/runtime_mcp_sources.json'}
    sys.path.insert(0,str(destination/'authoring/public_extract'))
    import source_support as support
    assert SHA(Path(support.__file__).read_bytes())==inputs['support_sha256']
    api=support.tools(hepta);assemble,render=api[-2:]
    changed={}
    def save(name,raw):
        path=destination/name;before=path.read_bytes() if path.exists() else None
        path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw);path.chmod(0o644)
        changed[name]={'before':PIN(before) if before is not None else None,'after':PIN(raw)}
    plan=json.loads((ROOT/'CHANGES.json').read_bytes())
    assert plan['baseline_source']==inputs['baseline_source']
    assert plan['baseline_binding']==inputs['baseline_binding']
    for name,row in plan['files'].items():
        raw=(destination/name).read_bytes();assert PIN(raw)==row['before'],name
        text=raw.decode()
        for patch in row['splices']:
            before=patch['from']
            if before is None:text+=patch['to']
            else:
                assert text.count(before)==1,(name,'splice multiplicity')
                text=text.replace(before,patch['to'],1)
        result=text.encode();assert PIN(result)==row['after'],name
        save(name,result)
    for name,row in inputs['new_boundaries'].items():
        assert not (destination/name).exists(),name
        raw=(ROOT/row['file']).read_bytes()
        assert PIN(raw)=={k:row[k] for k in ('bytes','sha256')}
        save(name,raw)
    name='native/runtime_mcp.hepta';original=(destination/name).read_bytes()
    assert PIN(original)==inputs['frontend_before']
    old=assemble(original).as_dict();assert len(old['functions'])==93
    oldfn=fn(original,6);wrapper=(ROOT/'frontend_cancel_wrapper.hia').read_bytes()
    result=original.replace(oldfn,wrapper,1)+oldfn.replace(b'fn f6(',b'fn f93(',1)
    assert PIN(result)==inputs['frontend_after']
    new=assemble(result).as_dict();assert len(new['functions'])==94
    assert old['schema']==new['schema'] and old['module']==new['module']
    assert all(old['functions'][i]==new['functions'][i] for i in range(93) if i!=6)
    restored=copy.deepcopy(new['functions'][93]);restored['name']='f6'
    assert restored==old['functions'][6]
    assert all(fn(original,i)==fn(result,i) for i in range(93) if i!=6)
    assert assemble(render(new).encode()).as_dict()==new
    stats={'functions':len(new['functions']),'blocks':sum(len(x['blocks']) for x in new['functions']),
           'operations':sum(len(b['ops']) for x in new['functions'] for b in x['blocks'])}
    assert stats['functions']<=128 and stats['blocks']<=1536 and stats['operations']<=8192
    assert all(len(x['blocks'])<=256 for x in new['functions'])
    assert all(len(b['params'])<=16 for x in new['functions'] for b in x['blocks'])
    save(name,result)
    proof={'schema':'hepta.runtime.public118-extract-lock-wait-source.v1',
      'baseline_source':inputs['baseline_source'],'baseline_binding':inputs['baseline_binding'],
      'source_patch_plan':PIN((ROOT/'CHANGES.json').read_bytes()),
      'frontend':{'before':PIN(original),'after':PIN(result),'original_functions':93,**stats,
                  'changed_original':['f6'],'retained_after_tool':'f93',
                  'inverse_original_f6_exact':True,'other92_functions_byte_and_ast_exact':True,
                  'original_function_sha256':{x['name']:SHA(CAN(x)) for x in old['functions']},
                  'new_function_sha256':{x['name']:SHA(CAN(x)) for x in new['functions']}},
      'changed_runtime_files':copy.deepcopy(changed),'descriptor_slots':64,
      'engine_bytes':16384,'descriptor_base':8192,'retained_chain':[18,59,61,62,63],
      'idle_params_slot':60,'engine_context_offset':456,'engine_installed_offset':464,
      'continuation_pending_wait':2,'actual_hia_reserved_lease_wake':True,
      'notification_cancels_handler_future':False,'actual_drop_only_after_transport_close':True,
      'unchanged_hia_caller_scope_drain':True,'unchanged_hia_gateway_effect_release':True,
      'pure_source_author_executions':1,'native_or_rust_semantic_executions':0,
      'public_wait_qualified':False,'full_async_qualified':False,'full_sdk_qualified':False,
      'remote_qualified':False,'whole_runtime_replaced':False}
    proofraw=ENC(proof);save('native/runtime_mcp_extract_wait_composition.json',proofraw)
    comp_path='native/runtime_mcp_composition.json';comp_raw=(destination/comp_path).read_bytes()
    comp=json.loads(comp_raw)
    assert comp['source_sha256']==SHA(original) and comp['source_bytes']==len(original)
    assert comp['function_sha256']=={x['name']:SHA(CAN(x)) for x in old['functions']}
    names=dict(comp['functions']);assert 'retained_wait_after_tool' not in names
    names['retained_wait_after_tool']='f93'
    for key,value in {'source_sha256':SHA(result),'source_bytes':len(result),'functions':names,
                      'function_sha256':{x['name']:SHA(CAN(x)) for x in new['functions']}}.items():
        comp_raw=field(comp_raw,key,value)
    comp_raw=field(comp_raw,'extract_wait_extension',{'proof':PIN(proofraw),'public_wait_qualified':False,
        'fixed_chain':[18,59,61,62,63],'drop_child':15,'drop_phase':6,'retained_after_tool':'f93'},new=True)
    parsed=json.loads(comp_raw)
    for key in comp:
        if key not in ('source_sha256','source_bytes','functions','function_sha256'):
            assert parsed[key]==comp[key],key
    save(comp_path,comp_raw)
    for name in ASSETS:save('authoring/public_extract_wait_v1/'+name,(ROOT/name).read_bytes())
    save('native/extract_wait_abi.md',(ROOT/'ABI.md').read_bytes())
    current=rows(destination)
    binding=field(binding_before,'sources',{n:r for n,r in current.items() if n!='native/runtime_mcp_sources.json'})
    binding=field(binding,'extract_wait_extension',{'source_proof':PIN(proofraw),
        'baseline_source':inputs['baseline_source'],'actual_lock_wait_registered':True,
        'public_wait_qualified':False,'full_async_qualified':False},new=True)
    save('native/runtime_mcp_sources.json',binding)
    final=rows(destination)
    assert json.loads(binding)['sources']=={n:r for n,r in final.items() if n!='native/runtime_mcp_sources.json'}
    assert all(final[n]==r for n,r in oldrows.items() if n not in changed)
    for name,row in oldrows.items():
        if name.endswith('.hepta') and name!='native/runtime_mcp.hepta':assert final[name]==row,name
    for path in destination.rglob('*.py'):ast.parse(path.read_bytes(),filename=str(path))
    finalrows=[]
    for name in sorted(final):
        path=destination/name;raw=path.read_bytes()
        finalrows.append({'path':name,**final[name],'mode':'100644',
            'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()})
    return {'schema':'hepta.runtime.public118-extract-wait-source-result.v1',
      'status':'PURE_SOURCE_AUTHOR_PASS','baseline_source':inputs['baseline_source'],
      'source_binding_sha256':SHA(binding),'source_files':len(final),'runtime_hia_images':118,
      'physical_images':111,'descriptor_slots':64,'installed_handlers':10,
      'changed_files':changed,'source_rows':finalrows,'semantic_executions':0,
      'public_wait_qualified':False,'full_async_qualified':False,'whole_runtime_replaced':False}
