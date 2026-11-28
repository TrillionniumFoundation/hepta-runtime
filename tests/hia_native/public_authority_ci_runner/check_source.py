"""Admit the complete immutable public91 source package without execution."""
from pathlib import Path
import ast
import hashlib
import json
import stat

SHA=lambda raw:hashlib.sha256(raw).hexdigest()
SOURCE_MANIFEST='a3b30470a5b7dbe61ffb452d1bd7b7401cac3826ce58167a85d896cff0464c4e'
def row(raw):return dict(bytes=len(raw),sha256=SHA(raw),git_blob=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest())
def tree(root,excluded):
    result={}
    for path in sorted(root.rglob('*')):
        assert not path.is_symlink()
        if path.is_dir():continue
        assert stat.S_ISREG(path.stat().st_mode)
        name=path.relative_to(root).as_posix()
        if name in excluded:continue
        raw=path.read_bytes();result[name]=row(raw)
        if path.suffix=='.py':ast.parse(raw,filename=name)
    return result
def check(source):
    source=Path(source).resolve(strict=True);raw=(source/'source-manifest.json').read_bytes()
    assert SHA(raw)==SOURCE_MANIFEST
    manifest=json.loads(raw);actual=tree(source,{'source-manifest.json'});assert actual==manifest['files']
    assert manifest['schema']=='hepta.public-authority.source.v1'
    graph=source/'source';binding=json.loads((graph/'native/runtime_mcp_sources.json').read_bytes())
    assert binding['schema']=='hepta.runtime.public-source-closure.v2'
    for name,pin in binding['sources'].items():
        data=(graph/name).read_bytes();assert pin==dict(bytes=len(data),sha256=SHA(data)),name
    previous=source/'baseline-source';old=json.loads((previous/'native/runtime_mcp_sources.json').read_bytes())
    for name,pin in old['sources'].items():
        path=previous/name if (previous/name).is_file() else graph/name
        data=path.read_bytes();assert pin==dict(bytes=len(data),sha256=SHA(data)),name
    module=ast.parse((graph/'scripts/public_nine_build.py').read_bytes())
    values={node.targets[0].id:ast.literal_eval(node.value) for node in module.body
        if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name)
        and node.targets[0].id in ('MEMBERS','EXTRA')}
    assert len(values['MEMBERS'])==91 and len(values['EXTRA'])==57
    assert values['EXTRA'][47:53]==[None]*6 and values['EXTRA'][53:]==['target_shutdown','current_get_info','target_connection',None]
    owner_pins=check_authority(source,graph)
    return dict(files=len(actual)+1,source_manifest_sha256=SHA(raw),graph_source_binding_sha256=SHA((graph/'native/runtime_mcp_sources.json').read_bytes()),
        owner_v4_source_pins_sha256=SHA(owner_pins),physical_images=91,global_slots=57,
        authority_profile_changed_files=7,historical_test_files_unchanged=5,
        native_or_rust_executed=False,full_sdk_qualified=False,production_activated=False,old_path_removed=False)
def check_runner(root):
    raw=(root/'runner-manifest.json').read_bytes();manifest=json.loads(raw)
    assert manifest['schema']=='hepta.public-authority.runner-source.v1'
    actual=tree(root,{'runner-manifest.json'});assert actual==manifest['files']
    return dict(files=len(actual)+1,manifest_sha256=SHA(raw))

def check_authority(source,graph):
    owner=source/'owner-reference';profile=json.loads((graph/'native/caller_owner_export_profile.json').read_bytes())
    assert len(profile['members'])==9
    for member in profile['members']:assert (graph/member['source']).read_bytes()==(owner/member['source']).read_bytes()
    for name in ('caller_owner_export_profile.json','caller_owner_export_source_proof.json','caller_owner_export_abi.md'):
        assert (graph/'native'/name).read_bytes()==(owner/'native'/name).read_bytes()
    current=source/'authority-retained';historical=source/'authority-historical'
    current_files=tree(current,set());old_files=tree(historical,set());assert set(current_files)==set(old_files)
    changed={name for name in current_files if current_files[name]!=old_files[name]}
    assert changed=={'native/caller_authority.hepta','native/authority_profile.json','native/authority_packer.hepta',
        'native/authority_packer_provenance.json','scripts/hia_native_authority_build.py',
        'scripts/hia_native_authority_qualification.py','tests/hia_native/authority_native_harness.py'}
    assert (current/'native/caller_authority.hepta').read_bytes()==(graph/'native/caller_authority.hepta').read_bytes()
    assert current_files['native/caller_authority.hepta']['sha256']=='c8762a6c08a7270e473b6868798de059cbee2443ad47c1cd49962fe5d27b4775'
    assert old_files['native/caller_authority.hepta']['sha256']=='4bf4a50d560db251b5d6e1eaad59c53b67796c1da2c749e4a9d3985587f22af6'
    for name in ('test_caller_authority.py','test_authority_loader_kernel.py','test_authority_transport.py','test_authority_packer.py','test_authority_evidence.py'):
        assert (current/'tests/hia_native'/name).read_bytes()==(historical/'tests/hia_native'/name).read_bytes()
    owner_pins=(owner/'tests/hia_native/caller_owner_export/source-pins.json').read_bytes()
    for name,pin in json.loads(owner_pins)['files'].items():
        data=(owner/name).read_bytes();assert pin==dict(bytes=len(data),sha256=SHA(data))
    return owner_pins
