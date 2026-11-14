"""Build an actual static five-image administrator configuration executable."""
from pathlib import Path
import argparse,hashlib,json,re,struct,subprocess,sys
ROOT=Path(__file__).resolve().parents[1]
sha=lambda b:hashlib.sha256(b).hexdigest()

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--hepta',type=Path,required=True);p.add_argument('--build-root',type=Path,default=ROOT/'build')
    p.add_argument('--runtime',type=Path,default=ROOT)
    p.add_argument('--name',required=True);p.add_argument('--fixture-admin',action='store_true')
    for name in ['owner','fs','json','validation','identity']:p.add_argument('--'+name+'-manifest',type=Path,required=True)
    a=p.parse_args();sys.path.insert(0,str(ROOT/'scripts'))
    sys.path.insert(1,str(a.runtime.resolve(strict=True)/'scripts'))
    sys.path.insert(2,str(a.hepta.resolve(strict=True)))
    from hia_native_build import NativeBuild
    from hia_native_loader import NativeModule
    from generate_hia_transport import document
    from hepta.hia_agent_assembly import render_assembly
    from tools.generate_hia_elf_linker import SOURCE as HELPERS
    build=NativeBuild(a.hepta,a.build_root);build.bootstrap()
    names=['owner','fs','json','validation','identity'];profiles=['history.v1','standard','serde-json.v1','history.v1','history.v1']
    members=[];images=[]
    for index,(name,profile) in enumerate(zip(names,profiles)):
        path=getattr(a,name+'_manifest').resolve(strict=True);m=json.loads(path.read_bytes())
        source=(path.parent/m['source']).read_bytes();image=(path.parent/m['image']).read_bytes()
        if (sha(source)!=m['source_sha256'] or sha(image)!=m['image_sha256']
            or source!=(ROOT/('native/config_'+name+'.hepta')).read_bytes()
            or m['compiler_commit']!=build.identity['commit'] or m['compiler_sha256']!=build.compiler_sha256
            or m.get('buffer_profile','standard')!=profile):raise ValueError('configuration member/source/profile changed: '+name)
        members.append({'id':index,'name':name,'manifest':str(path),'manifest_sha256':sha(path.read_bytes()),
                        'source_sha256':sha(source),'image_sha256':sha(image),'image_bytes':len(image),
                        'buffer_profile':profile,'input_capacity':m['input_capacity'],'output_capacity':m['output_capacity'],'workspace_capacity':m['workspace_capacity']})
        images.append(image)
    work=a.build_root/(a.name+'-elf');work.mkdir(mode=0o700)
    assembly=(ROOT/'scripts/config_owner_adapter.S').read_text()
    if a.fixture_admin:
        needle='    mov qword ptr [rax + 120], 1\n    jmp owner_resume'
        assert assembly.count(needle)==1
        assembly=assembly.replace(needle,'''    mov qword ptr [rax + 120], 1
    cmp qword ptr [r15 + 24], 64
    jb fixture_kind_done
    mov rdx, 0x3130434746435248 /* Test-only trusted startup frame. */
    cmp [r15 + INPUT], rdx
    jne fixture_kind_done
    mov qword ptr [rax + 120], 3
fixture_kind_done:
    jmp owner_resume''')
    (work/'adapter.S').write_text(assembly)
    subprocess.run(['as','--64',str(work/'adapter.S'),'-o',str(work/'adapter.o')],check=True)
    relocations=subprocess.check_output(['readelf','-r',str(work/'adapter.o')])
    if b'There are no relocations' not in relocations:raise ValueError('unresolved native relocations')
    subprocess.run(['objcopy','-O','binary','--only-section=.text',str(work/'adapter.o'),str(work/'adapter.bin')],check=True)
    symbols=subprocess.check_output(['nm','-n',str(work/'adapter.o')],text=True)
    holes=[]
    for name in names:
        match=re.search(r'^([0-9a-f]+) T '+name+r'_call_displacement$',symbols,re.M)
        if match is None:raise ValueError('missing native image call hole: '+name)
        holes.append(176+int(match[1],16))
    header=(b'\x7fELF\x02\x01\x01'+bytes(9)+struct.pack('<HHIQQQIHHHHHH',2,62,1,0x4000b0,64,0,0,64,56,2,0,0,0)
            +struct.pack('<IIQQQQQQ',1,5,0,0x400000,0x400000,0,0,4096)+struct.pack('<IIQQQQQQ',0x6474e551,6,0,0,0,0,0,16))
    prefix=header+(work/'adapter.bin').read_bytes()
    for hole in holes:
        if prefix[hole-1:hole+4]!=b'\xe8\0\0\0\0':raise ValueError('native call hole differs')
    source='def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:\n'
    source+='    if length(s) < 61 or length(s) > 8388608:\n        return 4294967295\n'
    source+=f"    if uint(s, 0, 8) != {int.from_bytes(b'HCFGPCK1','little')} or uint(s, 48, 8) != 0:\n        return 4294967295\n"
    for i in range(5):
        source+=f'    n{i} = uint(s, {8+i*8}, 8)\n    if n{i} == 0 or n{i} > 1048576:\n        return 4294967295\n'
    source+='    total = n0 + n1 + n2 + n3 + n4\n    if length(s) != 56 + total:\n        return 4294967295\n'
    source+=f'    size = {len(prefix)} + total\n    if size > 8388608 or length(o) < size:\n        return 4294967294\n'
    for at in range(0,len(prefix),8):
        raw=prefix[at:at+8];source+=f'    write(o, {at}, {int.from_bytes(raw,"little")}, {len(raw)})\n'
    source+='    write(o, 96, size, 8)\n    write(o, 104, size, 8)\n'
    source+=f'    at = {len(prefix)}\n    pos = 56\n'
    for i,hole in enumerate(holes):
        source+=f'    write(o, {hole}, at - {hole+4}, 4)\n    copy_bytes(s, o, pos, at, n{i})\n    at = at + n{i}\n    pos = pos + n{i}\n'
    source+='    return size\n'+HELPERS[HELPERS.index('\ndef uint('):]
    raw=render_assembly(document(source,'runtime_config_owner_packer')).encode()
    packer=ROOT/('native/config_owner_'+('fixture_' if a.fixture_admin else '')+'packer.hepta')
    if packer.read_bytes()!=raw:raise ValueError('frozen HIA installed-owner packer differs')
    manifest=build.compile(a.name+'-packer',packer,standalone=None)
    frame=b'HCFGPCK1'+b''.join(struct.pack('<Q',len(image)) for image in images)+bytes(8)+b''.join(images)
    with NativeModule(manifest,manifest_sha256=sha(manifest.read_bytes())) as module:
        elf=module.invoke(frame,output_capacity=len(prefix)+sum(map(len,images)),workspace_capacity=4096)
    expected=bytearray(prefix);struct.pack_into('<QQ',expected,96,len(elf),len(elf));at=len(prefix)
    for image,hole,member in zip(images,holes,members):
        if elf[at:at+len(image)]!=image:raise ValueError('packed native image differs')
        struct.pack_into('<i',expected,hole,at-hole-4);member.update(offset=at,call_displacement_offset=hole);at+=len(image)
    if at!=len(elf) or elf[:len(prefix)]!=expected:raise ValueError('packed fixed adapter differs')
    binary=work/'config-owner.elf';binary.write_bytes(elf);binary.chmod(0o700);(work/'pack.input.bin').write_bytes(frame)
    build._recheck()
    for member in members:
        path=Path(member['manifest']);m=json.loads(path.read_bytes())
        if sha(path.read_bytes())!=member['manifest_sha256'] or sha((path.parent/m['image']).read_bytes())!=member['image_sha256']:raise ValueError('member changed during build')
    result=dict(schema='hepta.runtime.config-owner-native.v1',compiler_commit=build.identity['commit'],compiler_sha256=build.compiler_sha256,
                members=members,executable=binary.name,elf_sha256=sha(elf),elf_bytes=len(elf),
                adapter_source_sha256=sha(assembly.encode()),adapter_base_sha256=sha((ROOT/'scripts/config_owner_adapter.S').read_bytes()),
                prefix_bytes=len(prefix),prefix_sha256=sha(prefix),pack_input_sha256=sha(frame),
                packer_source_sha256=sha(raw),packer_manifest=str(manifest.resolve()),packer_manifest_sha256=sha(manifest.read_bytes()),
                fixture_admin_reinstallation=a.fixture_admin,complete_config_owner=False,regex_compilation_closed=False,
                caller_configuration_installation=False,fresh_cold_qualified=False)
    (work/'manifest.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'manifest':str((work/'manifest.json').resolve()),'elf_sha256':sha(elf),'elf_bytes':len(elf),'fixture_admin_reinstallation':a.fixture_admin}))

if __name__=='__main__':main()
