"""Compile the HIA result owner and its fixed, source-owned native boundary."""
from __future__ import annotations
import argparse, hashlib, json, struct, subprocess, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from hia_native_build import NativeBuild, json_bytes, write_new
from hia_native_loader import NativeModule

def sha(raw): return hashlib.sha256(raw).hexdigest()

def build_result_publication(hepta: Path, build_root: Path, *, source_root: Path=ROOT):
    build=NativeBuild(hepta,build_root)
    def component(name, source):
        path=build_root/'modules'/name/'manifest.json'
        if not path.exists():return build.compile(name,source_root/source,standalone=None)
        meta=json.loads(path.read_bytes())
        if meta['source_sha256']!=sha((source_root/source).read_bytes()) or meta['compiler_sha256']!=sha(build.bootstrap().read_bytes()):
            raise ValueError('existing component source/compiler differs; select a fresh build directory')
        with NativeModule(path,manifest_sha256=sha(path.read_bytes())):pass
        return path
    owner=component('result-publication','native/result_publication.hepta')
    packer=component('result-publication-packer','native/result_publication_packer.hepta')
    om=json.loads(owner.read_bytes()); image=(owner.parent/om['image']).read_bytes()
    frame=b'HRPPCK01'+struct.pack('<Q',len(image))+image
    with NativeModule(packer,manifest_sha256=sha(packer.read_bytes())) as module:
        elf=module.invoke(frame,output_capacity=1<<20,workspace_capacity=4096)
    layout=json.loads((source_root/'native/result_publication_layout.json').read_bytes())
    offset=layout['image_offset']
    if (elf[offset:]!=image or struct.unpack_from('<Q',elf,96)[0]!=len(elf)
            or struct.unpack_from('<Q',elf,104)[0]!=len(elf)):
        raise ValueError('actual embedded owner or native ELF extent differs')
    folder=build_root/'result-publication';folder.mkdir(parents=True,exist_ok=False)
    subprocess.run(['as','--64','-o',str(folder/'adapter.o'),str(source_root/'scripts/result_publication_adapter.S')],check=True)
    subprocess.run(['objcopy','-O','binary','-j','.text',str(folder/'adapter.o'),str(folder/'adapter.bin')],check=True)
    code=(folder/'adapter.bin').read_bytes()
    if code[-1:]!=b'\0' or elf[176:offset]!=code[:-1]:
        raise ValueError('source-owned adapter bytes differ from the HIA-packed executable')
    write_new(folder/'result-publication.elf',elf,0o500)
    data={'schema':'hepta.runtime.result-publication.v1','elf':'result-publication.elf','elf_sha256':sha(elf),
          'owner_manifest':str(owner.relative_to(build_root)),'owner_manifest_sha256':sha(owner.read_bytes()),
          'owner_source_sha256':om['source_sha256'],'owner_image_sha256':sha(image),'image_offset':offset,
          'packer_manifest':str(packer.relative_to(build_root)),'packer_manifest_sha256':sha(packer.read_bytes()),
          'adapter_source_sha256':sha((source_root/'scripts/result_publication_adapter.S').read_bytes()),
          'compiler_commit':om['compiler_commit'],'compiler_sha256':om['compiler_sha256'],
          'initial_arena_bytes':131072,'output_window_bytes':65536,'fixed_total_result_limit':None,
          'fixture_argv':['--owner-fixture','--publish-fixture'],
          'production_config_route_replaced':False,'filesystem_callers_replaced':False,'whole_runtime_replaced':False}
    path=folder/'manifest.json';write_new(path,json_bytes(data));return path

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--hepta',type=Path,required=True);p.add_argument('--build',type=Path,required=True)
    a=p.parse_args();print(build_result_publication(a.hepta.resolve(),a.build.resolve()))
