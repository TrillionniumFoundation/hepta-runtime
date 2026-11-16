"""Install the owned current ListTools projection into the isolated 102 graph."""
from pathlib import Path
import argparse,hashlib,json,shutil
sha=lambda b:hashlib.sha256(b).hexdigest()
pin=lambda b:{'bytes':len(b),'sha256':sha(b)}
enc=lambda v:(json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
BASE='2333590e3fab06f254508e7800441346eea281030a89e3a4675dc7d8a6f65ab4'
def install(base,authored,author,output):
    raw=(base/'native/runtime_mcp_sources.json').read_bytes();assert sha(raw)==BASE
    binding=json.loads(raw);names=set(binding['sources'])|{'native/runtime_mcp_sources.json'}
    for name,wanted in binding['sources'].items():assert pin((base/name).read_bytes())==wanted,name
    output.mkdir(parents=True,exist_ok=False)
    for name in sorted(names):
        dst=output/name;dst.parent.mkdir(parents=True,exist_ok=True);dst.write_bytes((base/name).read_bytes())
    selected=['sdk_public_protocol.hepta','runtime_mcp.hepta','runtime_mcp_composition.json','list_projection.pseudo','list_projection_composition.json','list_frontend.pseudo','list_frontend_composition.json']
    for name in selected:(output/'native'/name).write_bytes((authored/name).read_bytes())
    current=json.loads((authored/'list_projection_composition.json').read_bytes())
    comp=json.loads((base/'native/sdk_public_protocol_composition.json').read_bytes())
    comp['retained_pre_list_source_metadata']={'source_sha256':comp['source_sha256'],'source_bytes':comp['source_bytes'],'functions':comp['functions']}
    comp.update(source_sha256=current['source_sha256'],source_bytes=current['source_bytes'],functions=current['functions'],current_typed_list_extension=current)
    comp['aliases'].update(list_projection='f19',resolved_cache_hints='f20',context_threshold='f21')
    (output/'native/sdk_public_protocol_composition.json').write_bytes(enc(comp))
    for src in sorted(author.iterdir()):
        assert src.is_file(),src
        dst=output/'authoring/configured_catalog'/src.name;dst.parent.mkdir(parents=True,exist_ok=True);dst.write_bytes(src.read_bytes())
    dst=output/'authoring/configured_catalog/baseline_graph_sources.json';dst.write_bytes(raw)
    binding['configured_catalog_extension']['frontend_source_sha256']=sha((output/'native/runtime_mcp.hepta').read_bytes())
    binding['configured_catalog_extension']['current_typed_list_projection']={
       'base_graph_binding_sha256':BASE,'protocol_source_sha256':current['source_sha256'],
       'frontend_source_sha256':sha((output/'native/runtime_mcp.hepta').read_bytes()),
       'projection_magic':'HRCLST01','actual_typed_id_metadata_and_resolved_protocol':True,
       'legacy_raw_metadata_offsets_reused':False,'all_public_configuration_qualified':False}
    binding['sources']={p.relative_to(output).as_posix():pin(p.read_bytes()) for p in sorted(output.rglob('*')) if p.is_file() and p.relative_to(output).as_posix()!='native/runtime_mcp_sources.json'}
    (output/'native/runtime_mcp_sources.json').write_bytes(enc(binding))
    rows=[]
    for p in sorted(output.rglob('*')):
        if not p.is_file():continue
        name=p.relative_to(output).as_posix();before=base/name
        if not before.exists() or p.read_bytes()!=before.read_bytes():rows.append({'path':name,'before':pin(before.read_bytes()) if before.exists() else None,'after':pin(p.read_bytes())})
    return {'schema':'hepta.configured-catalog-list-projection-install.v2','base_binding_sha256':BASE,'binding_sha256':sha((output/'native/runtime_mcp_sources.json').read_bytes()),'source_files':len(binding['sources'])+1,'changed_or_new':rows,'runtime_images':102,'assembly_unchanged':True,'native_execution':False,'rust_execution':False}
if __name__=='__main__':
    p=argparse.ArgumentParser()
    for name in ('base','authored','author','output','receipt'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();result=install(a.base,a.authored,a.author,a.output);a.receipt.write_bytes(enc(result));print(json.dumps({k:v for k,v in result.items() if k!='changed_or_new'},sort_keys=True))
