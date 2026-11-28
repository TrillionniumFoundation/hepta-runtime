"""Build the ordinary local-file HIA read owner and its closed Linux fixture.

Compilation orchestration only. The static ELF runs the exact HIA owner and
fixed syscall boundary without a host interpreter or dynamic loader.
"""
from __future__ import annotations
import argparse,hashlib,json,re,struct,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from hia_native_build import NativeBuild,json_bytes,write_new
from hia_native_loader import NativeModule
sha=lambda raw:hashlib.sha256(raw).hexdigest()

def prefix_for(source:Path,folder:Path):
    subprocess.run(['as','--64','-o',str(folder/'adapter.o'),str(source)],check=True)
    relocations=subprocess.check_output(['readelf','-r',str(folder/'adapter.o')])
    if b'There are no relocations' not in relocations:raise ValueError('unresolved adapter relocations')
    subprocess.run(['objcopy','-O','binary','-j','.text',str(folder/'adapter.o'),str(folder/'adapter.bin')],check=True)
    symbols=subprocess.check_output(['nm','-n',str(folder/'adapter.o')],text=True)
    found=re.search(r'^([0-9a-f]+) T owner_call_displacement$',symbols,re.M)
    if found is None:raise ValueError('missing owner call hole')
    hole=176+int(found[1],16)
    header=(b'\x7fELF\x02\x01\x01'+bytes(9)+struct.pack('<HHIQQQIHHHHHH',2,62,1,0x4000b0,64,0,0,64,56,2,0,0,0)
            +struct.pack('<IIQQQQQQ',1,5,0,0x400000,0x400000,0,0,4096)+struct.pack('<IIQQQQQQ',0x6474e551,6,0,0,0,0,0,16))
    prefix=header+(folder/'adapter.bin').read_bytes()
    if prefix[hole-1:hole+4]!=b'\xe8\0\0\0\0':raise ValueError('owner call instruction differs')
    return prefix,hole

def build_view_read(hepta:Path,build_root:Path,*,source_root:Path=ROOT):
    build=NativeBuild(hepta,build_root);build.bootstrap()
    from generate_hia_transport import document,packer_source
    from hepta.hia_agent_assembly import render_assembly
    folder=build_root/'view-read';folder.mkdir(parents=True,exist_ok=False)
    prefix,hole=prefix_for(source_root/'scripts/view_read_adapter.S',folder)
    expected=render_assembly(document(packer_source(prefix,hole),'runtime_view_read_packer')).encode()
    source=source_root/'native/view_read_packer.hepta'
    if source.read_bytes()!=expected:raise ValueError('frozen HIA packer differs from the fixed boundary')
    owner=build.compile('view-read',source_root/'native/view_read.hepta',standalone=None,buffer_profile='history.v1')
    packer=build.compile('view-read-packer',source,standalone=None)
    om=json.loads(owner.read_bytes());image=(owner.parent/om['image']).read_bytes()
    frame=b'HIAFLT01'+struct.pack('<Q',len(image))+image
    with NativeModule(packer,manifest_sha256=sha(packer.read_bytes())) as module:
        elf=module.invoke(frame,output_capacity=1<<20,workspace_capacity=4096)
    patched=bytearray(prefix);struct.pack_into('<QQ',patched,96,len(elf),len(elf));struct.pack_into('<i',patched,hole,len(prefix)-hole-4)
    if elf!=bytes(patched)+image:raise ValueError('actual HIA packed image or prefix differs')
    write_new(folder/'view-read.elf',elf,0o500)
    data={'schema':'hepta.runtime.view-read-build.v1','elf':'view-read.elf','elf_sha256':sha(elf),
          'owner_manifest':str(owner.relative_to(build_root)),'owner_manifest_sha256':sha(owner.read_bytes()),
          'owner_source_sha256':om['source_sha256'],'owner_image_sha256':sha(image),'image_offset':len(prefix),'call_displacement_offset':hole,
          'packer_manifest':str(packer.relative_to(build_root)),'packer_manifest_sha256':sha(packer.read_bytes()),
          'adapter_source_sha256':sha((source_root/'scripts/view_read_adapter.S').read_bytes()),
          'compiler_commit':om['compiler_commit'],'compiler_sha256':om['compiler_sha256'],
          'initial_arena_bytes':131072,'read_window_bytes':65536,'fixed_total_read_limit':None,
          'public_mcp_route_replaced':False,'whole_view_replaced':False,'whole_runtime_replaced':False}
    path=folder/'manifest.json';write_new(path,json_bytes(data));return path

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--hepta',type=Path,required=True);p.add_argument('--build',type=Path,required=True)
    a=p.parse_args();print(build_view_read(a.hepta.resolve(),a.build.resolve()))
