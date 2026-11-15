"""Build the actual fixed local-file HIA composition, with no host runtime."""
from __future__ import annotations
import argparse,hashlib,json,re,struct,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from hia_native_build import NativeBuild,json_bytes,write_new
from hia_native_loader import NativeModule
sha=lambda raw:hashlib.sha256(raw).hexdigest()
SOURCES=['scripts/view_call_adapter.S','scripts/view_call_fixture_controls.S','scripts/view_call_engine.S','scripts/view_call_read_bridge.S',
         'scripts/view_call_key_bridge.S','scripts/view_call_scope_bridge.S']
MEMBERS=[('view-call','view_call','history.v1'),('view-read','view_read','history.v1'),
 ('view-endpoint','line_endpoint','standard'),('view-key','file_lock_key','history.v1'),
 ('view-scope','request_scope_lifecycle','standard'),('view-lease','request_cache_lease','standard'),
 ('view-cache','view_cache','history.v1'),('view-render','view_render','history.v1'),
 ('view-context','request_context','standard'),('view-error','view_error','standard')]
SLOT_IMAGES=[0,1,1,1,2,3,4,5,6,7,8,9]

def assemble_prefix(root:Path,folder:Path):
    raw='\n'.join((root/p).read_text() for p in SOURCES)
    for name in re.findall(r'^\.global ([A-Za-z_][A-Za-z_0-9]*)$',raw,re.M):
        if name=='_start':continue
        alias=name+'_flat'
        if '\n'+alias+':' not in raw:raw=raw.replace('\n'+name+':','\n'+name+':\n'+alias+':')
        raw=re.sub(r'\b(call|jmp) '+re.escape(name)+r'\b',lambda m:m[1]+' '+alias,raw)
        raw=raw.replace('[rip + '+name+']','[rip + '+alias+']')
    write_new(folder/'combined.S',raw.encode())
    subprocess.run(['as','--64','-o',str(folder/'adapter.o'),str(folder/'combined.S')],check=True)
    relocations=subprocess.check_output(['readelf','-r',str(folder/'adapter.o')])
    if b'There are no relocations' not in relocations:raise ValueError('unresolved native boundary relocation')
    subprocess.run(['objcopy','-O','binary','-j','.text',str(folder/'adapter.o'),str(folder/'adapter.bin')],check=True)
    symbols=subprocess.check_output(['nm','-n',str(folder/'adapter.o')],text=True)
    table=176+int(re.search(r'^([0-9a-f]+) T view_image_table$',symbols,re.M)[1],16)
    header=(b'\x7fELF\x02\x01\x01'+bytes(9)+struct.pack('<HHIQQQIHHHHHH',2,62,1,0x4000b0,64,0,0,64,56,2,0,0,0)
       +struct.pack('<IIQQQQQQ',1,5,0,0x400000,0x400000,0,0,4096)+struct.pack('<IIQQQQQQ',0x6474e551,6,0,0,0,0,0,16))
    prefix=header+(folder/'adapter.bin').read_bytes()
    proof=json.loads((root/'native/view_call_adapter.json').read_bytes())
    if proof['sources']!={p:sha((root/p).read_bytes()) for p in SOURCES}:raise ValueError('boundary source closure changed')
    if proof['prefix_sha256']!=sha(prefix) or proof['prefix_bytes']!=len(prefix) or proof['table_offset']!=table:raise ValueError('frozen native prefix changed')
    if prefix[table:table+96]!=bytes(96):raise ValueError('image slots are not reserved zeros')
    return prefix,table

def build_view_call(hepta:Path,build_root:Path,*,source_root:Path=ROOT):
    build=NativeBuild(hepta,build_root);build.bootstrap()
    folder=build_root/'view-call';folder.mkdir(parents=True,exist_ok=False)
    prefix,table=assemble_prefix(source_root,folder)
    members=[];images=[]
    for name,source,profile in MEMBERS:
        manifest=build.compile(name,source_root/'native'/f'{source}.hepta',standalone=None,buffer_profile=profile)
        data=json.loads(manifest.read_bytes());image=(manifest.parent/data['image']).read_bytes();images.append(image)
        members.append({'name':name,'source':f'native/{source}.hepta','manifest':str(manifest.relative_to(build_root)),
          'manifest_sha256':sha(manifest.read_bytes()),'source_sha256':data['source_sha256'],'image_sha256':sha(image)})
    packer=build.compile('view-call-packer',source_root/'native/view_call_packer.hepta',standalone=None)
    frame=b'HVCLELF1'+struct.pack('<11Q',10,*map(len,images))+b''.join(images)
    with NativeModule(packer,manifest_sha256=sha(packer.read_bytes())) as module:
        elf=module.invoke(frame,output_capacity=2<<20,workspace_capacity=4096)
    expected=bytearray(prefix);positions=[]
    for image in images:
        expected+=bytes((-len(expected))%16);positions.append(len(expected));expected+=image
    struct.pack_into('<QQ',expected,96,len(expected),len(expected))
    for slot,index in enumerate(SLOT_IMAGES):struct.pack_into('<Q',expected,table+slot*8,0x400000+positions[index])
    if elf!=expected:raise ValueError('actual HIA packed ELF or fixed slot table differs')
    write_new(folder/'view-call.elf',elf,0o500)
    data={'schema':'hepta.runtime.view-call-build.v1','elf':'view-call.elf','elf_sha256':sha(elf),'members':members,
      'packer_manifest':str(packer.relative_to(build_root)),'packer_manifest_sha256':sha(packer.read_bytes()),
      'prefix_sha256':sha(prefix),'prefix_bytes':len(prefix),'table_offset':table,'slot_image_indices':SLOT_IMAGES,
      'image_offsets':positions,'sources':{p:sha((source_root/p).read_bytes()) for p in SOURCES},
      'fixed_total_read_limit':None,'public_mcp_route_replaced':False,'whole_view_replaced':False,'whole_runtime_replaced':False}
    path=folder/'manifest.json';write_new(path,json_bytes(data));return path

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--hepta',type=Path,required=True);p.add_argument('--build',type=Path,required=True)
    a=p.parse_args();print(build_view_call(a.hepta.resolve(),a.build.resolve()))
