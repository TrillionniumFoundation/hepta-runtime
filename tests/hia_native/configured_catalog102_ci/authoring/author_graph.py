"""Derive an isolated configuration-aware 102 graph; preserve every boundary."""
from pathlib import Path
import argparse,copy,hashlib,json,sys
sys.dont_write_bytecode=True
BASE='41a42a6247d8b4bf0ccee11e743bad28285273637b9f824fcbf2f0bf9bad0726'
sha=lambda b:hashlib.sha256(b).hexdigest()
pin=lambda b:{'bytes':len(b),'sha256':sha(b)}
encode=lambda v:(json.dumps(v,sort_keys=True,indent=2)+'\n').encode()

def generate(base,component,hepta,output):
    raw=(base/'native/runtime_mcp_sources.json').read_bytes();assert sha(raw)==BASE
    binding=json.loads(raw);assert len(binding['sources'])==217
    names=set(binding['sources'])|{'native/runtime_mcp_sources.json'}
    assert {p.relative_to(base).as_posix() for p in base.rglob('*') if p.is_file()}==names
    for name,wanted in binding['sources'].items():assert pin((base/name).read_bytes())==wanted,name
    sys.path.insert(0,str(component));import configured_common as c
    c.source_check(component)
    sys.path.insert(0,str(hepta));from hepta.hia_agent_assembly import assemble_program
    changes={
        'native/runtime_mcp_catalog_ninth.hepta':(component/'native/runtime_mcp_catalog_configured.hepta').read_bytes(),
        'native/runtime_mcp.hepta':(component/'native/runtime_mcp.hepta').read_bytes()}
    catalog=json.loads((component/'native/catalog_configured_composition.json').read_bytes())
    front=json.loads((component/'native/catalog_frontend_composition.json').read_bytes())
    md=json.loads((base/'native/runtime_mcp_composition.json').read_bytes())
    graph_pin=lambda f:sha(json.dumps(f,sort_keys=True,separators=(',',':')).encode())
    old=assemble_program((base/'native/runtime_mcp.hepta').read_bytes()).as_dict()
    assert md['function_sha256']=={f['name']:graph_pin(f) for f in old['functions']}
    new=assemble_program(changes['native/runtime_mcp.hepta']).as_dict()
    md.update(source_bytes=len(changes['native/runtime_mcp.hepta']),source_sha256=sha(changes['native/runtime_mcp.hepta']),function_sha256={f['name']:graph_pin(f) for f in new['functions']})
    md['functions'].update(retained_configured_catalog='f73',retained_configured_prepare='f74',retained_configured_after_authority='f75',after_catalog_presence='f76')
    md['configured_catalog_extension']={**front,'catalog_source_sha256':catalog['source_sha256'],'actual_config_presence_qualified':False}
    changes['native/runtime_mcp_composition.json']=encode(md)
    catalog.update(schema='hepta.runtime.configured-installed-catalog-composition.v1',source='native/runtime_mcp_catalog_ninth.hepta',compatible_catalog_slot=0,request_magic='HRMCD002',response_magic='HRCATR02',entry_return_bytes=32,configured_operation=7,retained_fixed_eleven_operation=1,installed_tool_mask=1,advertised_tool_counts={'absent':7,'present':10},old_ninth_composition_sha256=sha((base/'native/runtime_mcp_catalog_ninth_composition.json').read_bytes()),current_sdk_original_configuration_comparison=False,public_packed_configuration_qualified=False)
    changes['native/runtime_mcp_catalog_ninth_composition.json']=encode(catalog)
    name='scripts/public_nine_build.py';text=(base/name).read_text()
    replacements={
        "'advertised_catalog_tools': 9":"'advertised_catalog_tools': None, 'advertised_catalog_tools_by_runtime_presence': {'absent': 7, 'present': 10}, 'catalog_installed_capability_mask': 1, 'catalog_config_presence_child': 6, 'catalog_config_presence_operation': 3, 'catalog_config_presence_phase': 18, 'catalog_all_configuration_public_qualified': False",
        "'directory_create', 'file_move', 'directory_move', 'text_editor']":"'directory_create', 'file_move', 'directory_move', 'text_editor', 'batch_edit']",
        "'catalog_source_qualified_separately': True":"'catalog_source_qualified_separately': False, 'catalog_retained_fixed_eleven_qualified_separately': True"}
    for old,new in replacements.items():assert text.count(old)==1;text=text.replace(old,new)
    changes[name]=text.encode()
    name='scripts/hia_native_runtime_mcp_build.py';text=(base/name).read_text()
    old='Build the current 102-image, nine-tool HIA stdio executable.';assert text.count(old)==1
    changes[name]=text.replace(old,'Build the 102-image HIA stdio executable with an installed-capability catalog.').encode()
    for name,raw in changes.items():binding['sources'][name]=pin(raw)
    binding['configured_catalog_extension']={'baseline_binding_sha256':BASE,'component_source_profile':pin((component/'source-profile.json').read_bytes()),'source_checkpoint':'1845aec93168e3f0270d429625cefb143331573a','catalog_source_sha256':catalog['source_sha256'],'frontend_source_sha256':front['source_sha256'],'installed_mask':1,'runtime_presence_source':'actual config owner child 6 operation 3','absent_tools':7,'present_tools':10,'bellman_route_installed':False,'all_public_configuration_qualified':False,'whole_runtime_replaced':False}
    changes['native/runtime_mcp_sources.json']=encode(binding)
    output.mkdir(parents=True,exist_ok=False);rows=[]
    for name in sorted(names):
        before=(base/name).read_bytes();after=changes.get(name,before)
        p=output/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(after)
        if before!=after:rows.append({'path':name,'before':pin(before),'after':pin(after)})
    assert len(rows)==7
    return {'schema':'hepta.runtime.catalog-configured102-graph-author.v1','base_binding_sha256':BASE,'new_binding_sha256':sha(changes['native/runtime_mcp_sources.json']),'files':len(names),'changed':rows,'unchanged_files':len(names)-7,'all_assembly_boundaries_byte_identical':True,'physical_hia_images':102,'new_runtime_sources':2,'bellman_route_installed':False,'native_or_rust_execution':False}

if __name__=='__main__':
    p=argparse.ArgumentParser()
    for name in ('base','component','hepta','output','receipt'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();result=generate(a.base.resolve(strict=True),a.component.resolve(strict=True),a.hepta.resolve(strict=True),a.output.absolute())
    with a.receipt.open('xb') as out:out.write(encode(result))
    print(json.dumps(result,sort_keys=True))
