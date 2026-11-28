#!/usr/bin/env python3
"""Freshly rebuild the exact retained target-request62 baseline without Rust."""
from pathlib import Path
import argparse, ast, hashlib, importlib.util, json, shutil, sys
sys.dont_write_bytecode=True
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
MANIFEST='d234cd39fdf8d2e7f3a1fa394f57c69b0d851742c5321d9d6094021a4c748366'

def put(path,value):
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('sdk-source','hepta','output'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();source=args.sdk_source.resolve(strict=True)
    raw=(source/'source-manifest.json').read_bytes();assert SHA(raw)==MANIFEST
    manifest=json.loads(raw);assert len(manifest['files'])==247
    for relative,pin in manifest['files'].items():
        name=Path(relative);assert not name.is_absolute() and '..' not in name.parts
        data=(source/name).read_bytes();assert pin['bytes']==len(data) and pin['sha256']==SHA(data),relative
    output=args.output.resolve();assert not output.exists() and not output.is_relative_to(source);output.mkdir(parents=True)
    (output/'evidence').mkdir()
    graph=output/'source';shutil.copytree(source/'base-source',graph)
    shutil.copytree(source/'baseline',output/'baseline');shutil.copytree(source/'native',output/'native')
    binding=graph/'native/runtime_mcp_sources.json';doc=json.loads(binding.read_bytes())
    for name in ('hia_native_build.py','hia_native_loader.py'):
        rel='scripts/'+name;data=(source/'g5'/rel).read_bytes();(graph/rel).write_bytes(data)
        doc['sources'][rel]={'bytes':len(data),'sha256':SHA(data)}
    put(binding,doc)
    prepare=load('_public_nine_retained_mechanical_prepare',source/'scripts/prepare_public_graph.py')
    prepare.ROOT=output;prepare.SOURCE=graph;prepare.main()
    original=(graph/'scripts/hia_native_runtime_mcp_build.py').read_text()
    marker='or len(MEMBERS) != 58';assert original.count(marker)==1
    helper=graph/'scripts/hia_native_runtime_mcp_build62.py'
    helper.write_text(original.replace(marker,'or len(MEMBERS) != 62',1))
    assert SHA(helper.read_bytes())=='32f3118dc39b00aa3ee07aace3ec6c7a1fc563db123b5fb46c9730dc4421371d'
    doc=json.loads(binding.read_bytes());doc['sources'][str(helper.relative_to(graph))]={
        'bytes':helper.stat().st_size,'sha256':SHA(helper.read_bytes())};put(binding,doc)
    sys.path.insert(0,str(graph/'scripts'))
    build=load('_public_nine_retained_62_build',helper)
    assert len(build.MEMBERS)==58 and len(build.EXTRA)==33
    members=[]
    for name,owner,profile in build.MEMBERS[:-5]:
        if name=='catalog':owner='runtime_mcp_catalog_target'
        elif name=='protocol':owner='sdk_public_protocol';profile='sdk-message-target.v1'
        members.append((name,owner,profile))
    members.extend([('target_message','sdk_message_target','sdk-message-target.v1'),
        ('target_request','sdk_request_target','serde-json.v1'),
        ('target_bridge','sdk_frontend_bridge_target','sdk-message-target.v1'),
        ('historical_protocol','runtime_mcp_protocol','history.v1')])
    members.extend(build.MEMBERS[-5:]);build.MEMBERS=members
    build.EXTRA=list(build.EXTRA)+[None]*9+['target_message','target_request','target_bridge','historical_protocol']
    assert len(build.MEMBERS)==62 and len(build.EXTRA)==46
    path=build.build_runtime_mcp(args.hepta.resolve(strict=True),output/'build',
        name='retained-eight',source_root=graph,private_fixture=False)
    data=json.loads(path.read_bytes());assert data['physical_images']==62
    assert all(row['fresh_compile'] is True for row in data['members'])
    assert data['elf_sha256']=='0bbb39cbfd04cdb16539c64c7305c4e5d10e6e1594cfcf66acc7bad9f28668cc'
    result={'schema':'hepta.runtime.public-nine-retained-baseline-build.v1','status':'FRESH_RETAINED_62_PASS',
        'input_manifest_sha256':MANIFEST,'manifest':str(path),'manifest_sha256':SHA(path.read_bytes()),
        'elf':str(path.parent/data['elf']),'elf_sha256':data['elf_sha256'],'fresh_members':62,
        'rust_executed':False,'existing_binary_inputs':False,'fresh_cold_qualified':False}
    put(output/'BUILD.json',result);print(json.dumps(result,sort_keys=True),flush=True)

if __name__=='__main__':main()
