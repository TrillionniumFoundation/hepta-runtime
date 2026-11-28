"""Pack a fixed regex test transport from source-pinned HIA images.

The five allowed layouts are source-owned. No supplied layout, syscall, module
entry point or replacement implementation can enter the resulting executable.
"""
from pathlib import Path
import argparse,hashlib,json,re,struct,subprocess,sys,time
ROOT=Path(__file__).resolve().parents[1]
sha=lambda raw:hashlib.sha256(raw).hexdigest()
PROFILES={
 'unicode':{'ids':[10,11],'names':['regex_unicode','regex_unicode_data'],'adapter':'regex_unicode_adapter.S','packer':'regex_unicode_packer.hepta','magic':b'HRGELF01','symbols':['query','data'],'edges':{'10':[11]}},
 'syntax':{'ids':[10,11],'names':['regex_syntax','regex_unicode_data'],'adapter':'regex_syntax_adapter.S','packer':'regex_syntax_packer.hepta','magic':b'HRGELF01','symbols':['query','data'],'edges':{'10':[11]}},
 'hir':{'ids':[12,11],'names':['regex_hir','regex_unicode_data'],'adapter':'regex_hir_adapter.S','packer':'regex_hir_packer.hepta','magic':b'HRGELF01','symbols':['query','data'],'edges':{'12':[11]}},
 'regex':{'ids':[15,10,12,13,14,11],'names':['regex_controller','regex_syntax','regex_hir','regex_nfa','regex_match','regex_unicode_data'],'adapter':'regex_pipeline_adapter.S','packer':'regex_pipeline_packer.hepta','magic':b'HRGPK601','edges':{'15':[10,12,13,14],'10':[11],'12':[11],'14':[11]}},
 'validation':{'ids':[3,15,10,12,13,14,11],'names':['config_validation','regex_controller','regex_syntax','regex_hir','regex_nfa','regex_match','regex_unicode_data'],'adapter':'config_regex_adapter.S','packer':'config_regex_packer.hepta','magic':b'HRCVPK71','edges':{'3':[15],'15':[10,12,13,14],'10':[11],'12':[11],'14':[11]}}}


def build_probe(hepta,build_root,profile,name,module_paths):
    from hia_native_build import NativeBuild
    from hia_native_loader import NativeModule
    spec=PROFILES[profile];builder=NativeBuild(hepta,build_root);builder.bootstrap()
    work=build_root/(name+'-elf');work.mkdir(mode=0o700)
    tracked={};members=[];images=[]
    def read(path):
        path=path.resolve(strict=True);raw=path.read_bytes();tracked[str(path)]=sha(raw);return raw
    for ident,source in zip(spec['ids'],spec['names'],strict=True):
        path=module_paths[source].resolve(strict=True);metadata=json.loads(read(path));image=read(path.parent/metadata['image']);raw=read(ROOT/'native'/(source+'.hepta'))
        expected_profile='standard'if source in ['regex_unicode','regex_unicode_data']else'history.v1'
        if metadata['source_sha256']!=sha(raw) or read(path.parent/metadata['source'])!=raw or metadata['image_sha256']!=sha(image):raise ValueError('regex member/source/image changed')
        if metadata['compiler_commit']!=builder.identity['commit']or metadata['compiler_sha256']!=builder.compiler_sha256 or metadata.get('buffer_profile','standard')!=expected_profile:raise ValueError('regex compiler/profile changed')
        with NativeModule(path,manifest_sha256=sha(path.read_bytes())):pass
        images.append(image);members.append({'id':ident,'source':'native/'+source+'.hepta','manifest':str(path),'manifest_sha256':sha(path.read_bytes()),'source_sha256':sha(raw),'image_sha256':sha(image),'image_bytes':len(image),'buffer_profile':expected_profile})
    assembly=ROOT/'scripts'/spec['adapter'];assembly_raw=read(assembly);packer=ROOT/'native'/spec['packer'];packer_raw=read(packer);read(Path(__file__))
    records=[]
    def command(label,argv):
        start=time.monotonic();result=subprocess.run(argv,cwd=ROOT,capture_output=True,timeout=30)
        (work/(label+'.stdout')).write_bytes(result.stdout);(work/(label+'.stderr')).write_bytes(result.stderr)
        records.append({'name':label,'command':argv,'cwd':str(ROOT),'elapsed':time.monotonic()-start,'exit':result.returncode,'stdout_sha256':sha(result.stdout),'stderr_sha256':sha(result.stderr),'timeout_seconds':30})
        if result.returncode:raise RuntimeError((label,result.returncode,result.stderr[-4096:]))
        return result.stdout
    command('assemble',['as','--64',str(assembly),'-o',str(work/'adapter.o')])
    relocations=command('relocations',['readelf','-r',str(work/'adapter.o')])
    if b'There are no relocations'not in relocations:raise ValueError('unresolved regex relocation')
    command('text',['objcopy','-O','binary','--only-section=.text',str(work/'adapter.o'),str(work/'adapter.bin')])
    symbols=command('symbols',['nm','-n',str(work/'adapter.o')]).decode();holes=[]
    for symbol in spec.get('symbols',['image'+str(ident)for ident in spec['ids']]):
        matches=re.findall(r'^([0-9a-f]+) T '+symbol+'_call_displacement$',symbols,re.M)
        if len(matches)!=1:raise ValueError('fixed native call displacement changed')
        holes.append(176+int(matches[0],16))
    header=(b'\x7fELF\x02\x01\x01'+bytes(9)+struct.pack('<HHIQQQIHHHHHH',2,62,1,0x4000b0,64,0,0,64,56,2,0,0,0)
        +struct.pack('<IIQQQQQQ',1,5,0,0x400000,0x400000,0,0,4096)+struct.pack('<IIQQQQQQ',0x6474e551,6,0,0,0,0,0,16))
    prefix=header+(work/'adapter.bin').read_bytes()
    if any(prefix[hole-1:hole+4]!=b'\xe8\0\0\0\0'for hole in holes):raise ValueError('fixed call opcode changed')
    packer_manifest=builder.compile(name+'-packer',packer,standalone=None)
    frame=spec['magic']+struct.pack('<'+'Q'*len(images),*map(len,images))+b''.join(images)
    with NativeModule(packer_manifest,manifest_sha256=sha(packer_manifest.read_bytes()))as module:
        elf=module.invoke(frame,output_capacity=len(prefix)+sum(map(len,images)),workspace_capacity=4096)
    expected=bytearray(prefix);struct.pack_into('<QQ',expected,96,len(elf),len(elf));offset=len(prefix)
    for member,image,hole in zip(members,images,holes,strict=True):
        if elf[offset:offset+len(image)]!=image:raise ValueError('actual packed HIA image changed')
        struct.pack_into('<i',expected,hole,offset-hole-4);member.update(offset=offset,call_displacement_offset=hole);offset+=len(image)
    if offset!=len(elf)or elf[:len(prefix)]!=expected:raise ValueError('actual packed native boundary changed')
    if any(sha(Path(path).read_bytes())!=digest for path,digest in tracked.items()):raise ValueError('regex input changed during build')
    builder._recheck();executable=work/(profile+'.elf');executable.write_bytes(elf);executable.chmod(0o500);(work/'pack.input.bin').write_bytes(frame)
    report={'schema':'hepta.runtime.regex-native-composition.v1','profile':profile,'members':members,'compiler_commit':builder.identity['commit'],'compiler_sha256':builder.compiler_sha256,'executable':executable.name,'executable_sha256':sha(elf),'executable_bytes':len(elf),
        'packer_manifest':str(packer_manifest),'packer_manifest_sha256':sha(packer_manifest.read_bytes()),'packer_source_sha256':sha(packer_raw),'adapter_source_sha256':sha(assembly_raw),'builder_source_sha256':sha(Path(__file__).read_bytes()),'pack_input_sha256':sha(frame),'prefix_bytes':len(prefix),'prefix_sha256':sha(prefix),'records':records,'inputs':tracked,'call_edges':spec['edges'],'transport':'internal-length-prefixed-bytes','runtime_python_required':False,'runtime_libc_required':False,'unconstrained_regex_resources_closed':False,'fresh_cold_qualified':False}
    result=work/'manifest.json';result.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n');return result


def main():
    p=argparse.ArgumentParser();p.add_argument('--hepta',required=True,type=Path);p.add_argument('--build-root',required=True,type=Path);p.add_argument('--profile',required=True,choices=PROFILES);p.add_argument('--name',required=True);p.add_argument('--modules',required=True,type=Path);a=p.parse_args()
    paths=json.loads(a.modules.read_bytes());result=build_probe(a.hepta.resolve(strict=True),a.build_root.resolve(strict=True),a.profile,a.name,{name:Path(path)for name,path in paths.items()});print(json.dumps({'manifest':str(result.resolve()),'sha256':sha(result.read_bytes())},sort_keys=True))


if __name__=='__main__':main()
