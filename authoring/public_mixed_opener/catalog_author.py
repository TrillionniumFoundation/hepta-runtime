"""Compose actual configuration presence with the installed native catalog bytes."""
from pathlib import Path
import copy,hashlib,json
ROOT=Path(__file__).resolve().parent
SHA=lambda b:hashlib.sha256(b).hexdigest()
PIN=lambda b:{'bytes':len(b),'sha256':SHA(b)}
ENC=lambda v:(json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
CAN=lambda v:json.dumps(v,sort_keys=True,separators=(',',':')).encode()
def spans(raw):
    text=raw.decode();assert text[0]=='[' and text[-1]==']'
    dec=json.JSONDecoder();at=1;rows=[]
    while at<len(text)-1:
        item,end=dec.raw_decode(text,at)
        rows.append((item['name'],len(text[:at].encode()),len(text[:end].encode()),text[at:end].encode()))
        if text[end]==']':at=end
        else:assert text[end]==',';at=end+1
    return rows
def generate(source,api,support,inputs,save):
    assemble,render=api[-2:]
    asset_root=ROOT/'catalog_assets';asset_raw=(asset_root/'ASSETS.json').read_bytes()
    assert PIN(asset_raw)==inputs['catalog_absent_assets']
    asset=json.loads(asset_raw);assert asset['status']=='ACTUAL_NATIVE_FLAGS_ZERO_ASSETS_READ' and asset['artifact']==14201568537
    assert asset['native_or_rust_executions']==0 and asset['expected_wires_used_as_implementation'] is False
    present=(source/'authoring/public_extract/catalog_assets/selected/ordinary.tools.json').read_bytes()
    absent=(asset_root/'selected/ordinary.tools.json').read_bytes()
    assert (asset_root/'selected/modern.tools.json').read_bytes()==absent
    for n,row in asset['files'].items():assert PIN((asset_root/n).read_bytes())==row
    parts=spans(present);gone={'effective_config','execution_shadow_admit','host_list'}
    assert len(parts)==10 and [n for n,_,_,_ in parts]==inputs['installed_sorted']
    expected=b'['+b','.join(raw for n,_,_,raw in parts if n not in gone)+b']'
    assert expected==absent
    full=b'"tools":'+present+b'}}';filtered=b'"tools":'+absent+b'}}'
    index={n:(a+8,b+8) for n,a,b,_ in parts}
    # Seven installed non-runtime Tool records are byte-identical in the two
    # actual policy outputs. Copy their three contiguous, exact original spans.
    cuts=[(0,index['effective_config'][0]),(index['extract_lines'][0],index['host_list'][0]),
          (index['text_editor'][0],len(full))]
    assert b''.join(full[a:b] for a,b in cuts)==filtered
    name='native/runtime_mcp_catalog_ninth.hepta';before=(source/name).read_bytes()
    original=assemble(before).as_dict();assert len(original['functions'])==64
    old=copy.deepcopy(original);retained=copy.deepcopy(old['functions'][0]);retained['name']='f64';old['functions'].append(retained)
    aliases=json.loads((source/'native/runtime_mcp_catalog_ninth_composition.json').read_bytes())['aliases']
    aliases={**aliases,'retained_catalog_entry':'f64'}
    lines=[
      'def entry(s:readbuf,o:mutbuf,w:mutbuf) -> u32:',
      '    if length(s) >= 16:',
      '        if load(s, 0) == QUERY and load(s, 8) == 7:',
      '            return configured_list(s, o, w)',
      '    return retained_catalog_entry(s, o, w)',
      '',
      'def configured_list(s:readbuf,o:mutbuf,w:mutbuf) -> u32:',
      '    if length(o) < 32:',
      '        return RESOURCE',
      '    if length(s) != 40:',
      '        return INVALID',
      '    modern = load(s, 16)',
      '    present = load(s, 24)',
      '    if modern > 1 or present > 1 or load(s, 32) != 10:',
      '        return INVALID',
      '    if length(w) < 16384:',
      '        return grow(o, 1, 16384)',
      '    prefix = choose(modern == 0, 11, 67)',
      '    size = prefix + choose(present == 1, '+str(len(full))+', '+str(len(filtered))+')',
      '    if length(o) - 32 < size:',
      '        return grow(o, 2, 32 + size)',
      '    if modern == 0:',
      '        prefix_0(o, 32)',
      '    else:',
      '        prefix_1(o, 32)',
      '    at = 32 + prefix',
      '    if present == 1:',
      '        common_literal(o, at)',
      '    else:',
      '        common_literal(w, 4096)',
    ]
    consumed=0
    for a,b in cuts:
        lines.append('        copy_range(o, w, at + '+str(consumed)+', '+str(4096+a)+', '+str(b-a)+')')
        consumed+=b-a
    lines.extend(['    return finish(o, size)',''])
    pseudo='\n'.join(lines)
    raw,names,delta=support.compile_delta(api,render(old).encode(),aliases,pseudo,
        {'QUERY':int.from_bytes(b'HRMCD002','little'),'RESOURCE':0xfffffffe,'INVALID':0xffffffff},old['module'])
    after=assemble(raw).as_dict();assert len(after['functions'])==66
    assert all(after['functions'][i]==original['functions'][i] for i in range(1,64))
    inverse=copy.deepcopy(after['functions'][64]);inverse['name']='f0';assert inverse==original['functions'][0]
    save(name,raw)
    comp_path='native/runtime_mcp_catalog_ninth_composition.json';comp=json.loads((source/comp_path).read_bytes())
    comp.update(source_sha256=SHA(raw),source_bytes=len(raw),aliases=names,functions=66,
        blocks=sum(len(f['blocks']) for f in after['functions']),
        operations=sum(len(b['ops']) for f in after['functions'] for b in f['blocks']))
    proof={'schema':'hepta.runtime.public118.configured-catalog-literal.v1','baseline':PIN(before),'source':PIN(raw),
      'full_actual_assets':PIN(asset_raw),'actual_pipeline_artifact':14201568537,'actual_pipeline_run':43813791993,
      'selected_present':PIN(present),'selected_absent':PIN(absent),'selected_absent_native_output_exact':True,
      'original_functions_1_through_63_exact':True,'old_entry_retained':'f64','new_operation':7,
      'request_fields':{'modern':16,'runtime_config_present':24,'installed_profile_10':32},
      'copied_common_spans':cuts,'whole_selected_common':PIN(full),'absent_selected_common':PIN(filtered),
      'old_public_protocol_prefixes_exact':True,'catalog_owner':delta,'native_or_rust_executions':0,
      'expected_original_wire_used_as_implementation':False,'installed_handlers':10,'visible_with_config':10,'visible_without_config':7}
    comp['configured_presence_extension']=proof
    save(comp_path,ENC(comp))
    front_name='native/runtime_mcp.hepta';front_before=(source/front_name).read_bytes()
    front=assemble(front_before).as_dict();original_front=copy.deepcopy(front);assert len(front['functions'])==89
    front_comp_name='native/runtime_mcp_composition.json'
    front_comp=json.loads((source/front_comp_name).read_bytes())
    relocation={7:89,8:90,62:91}
    for previous,destination in relocation.items():
        f=copy.deepcopy(front['functions'][previous]);f['name']='f'+str(destination);front['functions'].append(f)
    edits=[]
    for bid,value,oldvalue,newvalue in (('b19','v161',117,118),('b21','v177',17,18)):
        block=next(b for b in front['functions'][73]['blocks'] if b['id']==bid)
        op=next(o for o in block['ops'] if o['out']==[{'name':value,'type':'u64'}])
        assert op['op']=='const' and op['attrs']=={'value':oldvalue};op['attrs']['value']=newvalue
        edits.append({'block':bid,'value':value,'before':oldvalue,'after':newvalue})
    # The current real entry routes phases >=15 to the Bellman owner. The
    # source-only configured111 prototype never qualified phase18 here.
    # Keep Bellman exactly 15..17; phase18 reaches the existing authority arm.
    routing=next(b for b in front['functions'][73]['blocks'] if b['id']=='b57')
    routing_before=copy.deepcopy(routing)
    assert routing['term']['op']=='branch' and routing['term']['cond']=='v900001'
    assert not any(o['out'] and o['out'][0]['name'] in ('v900002','v900003','v900004') for b in front['functions'][73]['blocks'] for o in b['ops'])
    routing['ops'] += [
      {'out':[{'name':'v900002','type':'u64'}],'op':'const','args':[],'attrs':{'value':17}},
      {'out':[{'name':'v900003','type':'bool'}],'op':'compare.le','args':['v467','v900002'],'attrs':{}},
      {'out':[{'name':'v900004','type':'bool'}],'op':'bool.and','args':['v900001','v900003'],'attrs':{}},
    ]
    routing['term']['cond']='v900004'
    front_aliases={**front_comp['functions'],'retained_presence_catalog':'f89',
        'retained_presence_prepare':'f90','retained_presence_authority':'f91'}
    front_pseudo=(ROOT/'catalog_frontend.pseudo').read_text()
    const={'CONFIG_QUERY':int.from_bytes(b'HRCFGQ01','little'),'CONFIG_RESULT':int.from_bytes(b'HRCFGM01','little'),
        'CATALOG_QUERY':int.from_bytes(b'HRMCD002','little'),'CONFIG_ABSENT_SIZE':len(b'runtime tools are disabled; start with --runtime-config <file>'),
        'INVALID':0xffffffff}
    front_raw,front_names,front_delta=support.compile_delta(api,render(front).encode(),front_aliases,front_pseudo,const,front['module'])
    front_after=assemble(front_raw).as_dict();assert len(front_after['functions'])==93
    changed={7,8,62,73}
    assert all(original_front['functions'][i]==front_after['functions'][i] for i in range(89) if i not in changed)
    for previous,destination in relocation.items():
        f=copy.deepcopy(front_after['functions'][destination]);f['name']='f'+str(previous)
        assert f==original_front['functions'][previous]
    f=copy.deepcopy(front_after['functions'][73])
    for edit in edits:
        b=next(b for b in f['blocks'] if b['id']==edit['block'])
        o=next(o for o in b['ops'] if o['out']==[{'name':edit['value'],'type':'u64'}]);assert o['attrs']=={'value':edit['after']};o['attrs']['value']=edit['before']
    next(b for b in f['blocks'] if b['id']=='b57').update(routing_before)
    assert f==original_front['functions'][73]
    front_comp.update(source_sha256=SHA(front_raw),source_bytes=len(front_raw),functions=front_names,
        function_sha256={f['name']:SHA(CAN(f)) for f in front_after['functions']})
    front_proof={'schema':'hepta.runtime.public118.configured-catalog-frontend.v1','baseline':PIN(front_before),
      'source':PIN(front_raw),'configured111_author_blob':'17d39e424ffeea635cf3a298e43259ad59303d38',
      'configured111_pseudo_blob':'81b8e0016a61f473cd0211390e5baec94036a11e',
      'exact_relocations':{'f'+str(a):'f'+str(b) for a,b in relocation.items()},'entry_inverse_exact':True,
      'entry_bounds':edits,'phase18_routing_before':routing_before,
      'phase18_routing_after':next(b for b in front_after['functions'][73]['blocks'] if b['id']=='b57'),
      'old_functions_unchanged':[f'f{i}' for i in range(89) if i not in changed],
      'current_list_g1_id_meta_resolved_protocol_unchanged':True,'custom_request_projection_unchanged':True,
      'phase':18,'growth_phase':118,'config_child':6,'config_operation':3,'catalog_child':2,
      'catalog_operation':7,'installed_profile':10,'extract_slots':[59,60,61,62,63],
      'new_descriptors':0,'bellman_phase_97_exact':True,'compiler':front_delta,
      'native_or_rust_executions':0,'public_wait_qualified':False,'whole_runtime_replaced':False}
    front_comp['configured_presence_extension']=front_proof
    save(front_name,front_raw);save(front_comp_name,ENC(front_comp))
    combined={'catalog':proof,'frontend':front_proof}
    save('native/runtime_mcp_catalog_presence_composition.json',ENC(combined))
    for n in sorted(asset['files']):save('authoring/public_mixed_opener/catalog_assets/'+n,(asset_root/n).read_bytes())
    save('authoring/public_mixed_opener/catalog_assets/ASSETS.json',asset_raw)
    return combined
