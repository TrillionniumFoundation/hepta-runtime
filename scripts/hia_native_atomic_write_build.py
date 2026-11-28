"""Compile and strictly inspect the HIA local atomic writer and fixed Linux boundary.

This driver validates build artifacts. The emitted static ELF executes HIA
policy and fixed syscalls without a Python or libc runtime.
"""
from __future__ import annotations
import argparse, hashlib, json, os, struct, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
if str(ROOT/'scripts') not in sys.path:sys.path.insert(0,str(ROOT/'scripts'))
from hia_native_build import NativeBuild, json_bytes, write_new

COMMIT='d3e2c90173cf733e42b299d0c4274df4b593a12f'
TREE='8d8b0fb8d015fb7edab302498bb9ed4c74ab6f49'
COMPILER='bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'
DEPENDENCY='c3a2f7776feead1232bb31ef6dd319d69cf91663492634ece3c8a2c46dd5c2bd'
POLICY_SOURCE='bedb27429d970833db4800436511788eaae2bfaa5487b4c751a94f8e7cbe410b'
POLICY_IMAGE='0939cf8e05ec20c79316ab412e69aef3602547a42a747da98a399ba7c595e952'
PACKER_SOURCE='3e5f23dfaf73053ada568ec5d56d1b3d3fa18c37864d265300f4f7f7d09d3bf3'
PACKER_IMAGE='2d222d9d2b6576b0a3317c460ac8d6f0516969713c604f58fd04460376740a96'
PREFIX_BYTES=2896
PREFIX_SHA='5a06ece5c87b0548adce2281678a91e82752db14fd4bc9af225f51503268eb21'
CAPACITIES=(512<<20,1024<<20,1152<<20)
COMPILE_FILES=('manifest.json','build.json','module.input.bin','module.output.bin','module.image.bin',
 'module.receipt.json','module.request.json','module.stdout.log','module.stderr.log')
PACK_FILES=('pack.input.bin','pack.output.bin','pack.receipt.json','pack.request.json','pack.stdout.log','pack.stderr.log')
def require(ok,message):
    if not ok:raise ValueError(message)
def exact(value,wanted,message):require(type(value)is type(wanted) and value==wanted,message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def read(path):
    path=Path(path);require(path.is_file() and not path.is_symlink(),'atomic artifact must be a regular non-symlink file')
    return path.read_bytes()
def pairs(items):
    result={}
    for key,value in items:
        require(key not in result,'duplicate atomic artifact field');result[key]=value
    return result
def obj(path):
    value=json.loads(read(path),object_pairs_hook=pairs);require(type(value)is dict,'atomic artifact must contain an object');return value
def file_record(path):
    raw=read(path);return {'bytes':len(raw),'sha256':sha(raw)}
def source_pins(root):
    root=Path(root)
    return {name:file_record(root/name) for name in ('native/atomic_write.hepta','native/atomic_write_packer.hepta',
      'native/atomic_write_layout.json','native/atomic_write_composition.json',
      'scripts/hia_native_atomic_write_build.py','scripts/hia_native_build.py')}

def native_receipt(directory,stem,*,source,produced,producer):
    """Check the full retained native invocation, including its actual stdout."""
    directory=Path(directory);receipt=obj(directory/(stem+'.receipt.json'));stdout=obj(directory/(stem+'.stdout.log'))
    output=read(directory/(stem+'.output.bin'))
    expected={'status':'returned','abi_status':0,'core_u32':len(produced),'result_u64':len(produced),'source_unchanged':True,
      'input_bytes':len(source),'input_sha256':sha(source),'source_sha256':sha(source),'artifact_sha256':producer,
      'image_sha256':producer,'output_sha256':sha(output),'forbidden_compiler_modules_loaded':[],'format':'flat-x86-64',
      'case':stem,'return_encoding':'zero-extended-u32'}
    for key,wanted in expected.items():exact(receipt.get(key),wanted,'atomic native receipt differs: '+key)
    require(0<len(produced)<=len(output)==1<<20,'atomic native output capacity differs')
    exact(output[:len(produced)],produced,'atomic produced image differs from actual native output')
    exact(output[len(produced):],b'\xa5'*(len(output)-len(produced)),'atomic native output tail changed')
    exact(read(directory/(stem+'.input.bin')),source,'atomic actual compiler/packer input differs')
    exact(read(directory/(stem+'.stderr.log')),b'','atomic native invocation emitted stderr')
    for key,value in stdout.items():exact(receipt.get(key),value,'atomic retained actual stdout differs: '+key)
    require(set(stdout)=={'abi_status','core_u32','forbidden_compiler_modules_loaded','image_sha256','limits',
      'loader_operations','native_elapsed_ns','output_sha256','output_unchanged','result_u64','return_encoding',
      'source_sha256','source_unchanged','status','workspace_header'},'atomic actual stdout field set differs')
    request=obj(directory/(stem+'.request.json'))
    for key,wanted in {'capacity':1<<20,'format':'flat-x86-64','image_sha256':producer,
      'source_sha256':sha(source),'workspace_fill':0,'workspace_size':1<<20}.items():
        exact(request.get(key),wanted,'atomic invocation request differs: '+key)
    for key,filename in (('source',stem+'.input.bin'),('output',stem+'.output.bin')):
        require(type(request.get(key))is str and Path(request[key]).name==filename,'atomic invocation path identity differs')
    require(type(request.get('image'))is str and Path(request['image']).name.endswith('.image.bin'),'atomic producer path differs')
    return receipt

def inspect_elf(raw,image):
    require(len(raw)==PREFIX_BYTES+len(image),'atomic ELF extent differs')
    require(raw[:16]==b'\x7fELF\x02\x01\x01'+bytes(9),'atomic ELF identity differs')
    require(struct.unpack_from('<HHIQQQIHHHHHH',raw,16)==(2,62,1,0x4000b0,64,0,0,64,56,2,0,0,0),'atomic ELF header differs')
    require(struct.unpack_from('<IIQQQQQQ',raw,64)==(1,5,0,0x400000,0x400000,len(raw),len(raw),4096),'atomic RX segment differs')
    require(struct.unpack_from('<IIQQQQQQ',raw,120)==(0x6474e551,6,0,0,0,0,0,16),'atomic nonexecutable stack differs')
    prefix=bytearray(raw[:PREFIX_BYTES]);prefix[96:112]=bytes(16)
    exact(sha(prefix),PREFIX_SHA,'atomic fixed syscall boundary differs')
    exact(raw[PREFIX_BYTES:],image,'atomic embedded HIA image differs')
    return {'bytes':len(raw),'dynamic_loader':False,'elf_type':'ET_EXEC','entry':0x4000b0,'interpreter':None,'libc':False,
      'machine':'EM_X86_64','program_headers':['PT_LOAD_RX','PT_GNU_STACK_RW'],'sha256':sha(raw)}

def inspect_module(directory,kind,source,*,dependency=None):
    directory=Path(directory);metadata=obj(directory/(kind+'.json'));image=read(directory/(kind+'.image.bin'))
    caps=CAPACITIES if kind=='policy' else (8<<20,8<<20,32<<20)
    expected={'schema':'hepta.runtime.native-module.v1','abi':'hepta.runtime.borrowed-bytes.linux-x86_64.v1','target':'linux-x86_64',
      'compiler_commit':COMMIT,'compiler_sha256':COMPILER,'source':kind+'.hepta','image':kind+'.image.bin',
      'source_sha256':sha(source),'image_sha256':POLICY_IMAGE if kind=='policy' else PACKER_IMAGE,
      'input_capacity':caps[0],'output_capacity':caps[1],'workspace_capacity':caps[2],'standalone':None,'qualification':'development_fixed_point'}
    for key,wanted in expected.items():exact(metadata.get(key),wanted,'atomic module contract differs: '+kind+'/'+key)
    if kind=='policy':exact(metadata.get('buffer_profile'),'batch-plan.v1','atomic wide buffer profile differs')
    else:require('buffer_profile' not in metadata,'atomic packer must use the standard profile')
    exact(read(directory/(kind+'.hepta')),source,'atomic module source bytes differ')
    exact(sha(image),expected['image_sha256'],'atomic actual flat image differs')
    compiled=directory/(kind+'-build')
    receipt=native_receipt(compiled,'module',source=source,produced=image,producer=COMPILER)
    exact(receipt.get('produced_bytes'),len(image),'atomic compiler produced length differs')
    exact(receipt.get('produced_sha256'),sha(image),'atomic compiler produced identity differs')
    exact(read(compiled/'module.image.bin'),image,'atomic compiled image differs')
    built=obj(compiled/'build.json')
    exact(built.get('compile_receipt'),receipt,'atomic build receipt differs from actual invocation')
    exact(built.get('whole_runtime_replaced'),False,'atomic compilation cannot qualify the whole runtime')
    observed=built.get('compiler_dependency');exact(sha(canonical(observed)),DEPENDENCY,'atomic complete compiler dependency differs')
    if dependency is not None:exact(observed,dependency,'atomic fresh compiler checkout differs')
    origin=obj(compiled/'manifest.json');renamed=dict(origin,source=kind+'.hepta',image=kind+'.image.bin')
    exact(renamed,metadata,'atomic packaged module differs from the compiled manifest')
    return {'source_sha256':sha(source),'image_sha256':sha(image),'manifest':file_record(directory/(kind+'.json')),
      'compilation':{name:file_record(compiled/name) for name in COMPILE_FILES}},image

def inspect_bundle(manifest_path,*,source_root=ROOT,dependency=None):
    manifest_path=Path(manifest_path).resolve(strict=True);root=Path(source_root);directory=manifest_path.parent;pins=source_pins(root)
    exact(pins['native/atomic_write.hepta']['sha256'],POLICY_SOURCE,'atomic policy source is not qualified')
    exact(pins['native/atomic_write_packer.hepta']['sha256'],PACKER_SOURCE,'atomic packer source is not qualified')
    metadata=obj(manifest_path)
    expected={'schema':'hepta.runtime.native-atomic-write.v2','target':'linux-x86_64',
      'transport':'u64-length-binary-requests-u32-results','compiler_sha256':COMPILER,'compiler_commit':COMMIT,'compiler_tree':TREE,
      'executable':'native-atomic-write.elf','policy_manifest':'policy.json','packer_manifest':'packer.json',
      'input_capacity':CAPACITIES[0],'output_capacity':CAPACITIES[1],'workspace_bytes':CAPACITIES[2],
      'runtime_python_required':False,'runtime_libc_required':False,'registered_mcp_tool':False,
      'production_activated':False,'whole_runtime_replaced':False,'source_files':pins}
    for key,wanted in expected.items():exact(metadata.get(key),wanted,'atomic bundle contract differs: '+key)
    layout=obj(root/'native/atomic_write_layout.json')
    exact(read(directory/'layout.json'),read(root/'native/atomic_write_layout.json'),'atomic boundary layout changed')
    for key,wanted in {'schema':'hepta.runtime.atomic-write-layout.v1','packer_sha256':PACKER_SOURCE,
      'prefix_bytes':PREFIX_BYTES,'prefix_sha256':PREFIX_SHA,'image_offset':PREFIX_BYTES,'input_bytes':CAPACITIES[0],
      'output_bytes':CAPACITIES[1],'workspace_bytes':CAPACITIES[2],'buffer_profile':'batch-plan.v1',
      'runtime_python_required':False,'runtime_libc_required':False,'production_activated':False}.items():
        exact(layout.get(key),wanted,'atomic layout contract differs: '+key)
    images={};module_evidence={}
    for kind in ('policy','packer'):
        name='atomic_write.hepta' if kind=='policy' else 'atomic_write_packer.hepta'
        evidence,image=inspect_module(directory,kind,read(root/'native'/name),dependency=dependency)
        images[kind]=image;module_evidence[kind]=evidence
        for key in ('source_sha256','image_sha256'):
            exact(metadata.get(kind+'_'+key),evidence[key],'atomic bundle module identity differs')
        exact(metadata.get(kind+'_manifest_sha256'),evidence['manifest']['sha256'],'atomic module manifest hash differs')
        exact(metadata.get(kind+'_compilation'),evidence['compilation'],'atomic retained compilation files differ')
    elf=read(directory/'native-atomic-write.elf');inspection=inspect_elf(elf,images['policy'])
    exact(metadata.get('inspection'),inspection,'atomic executable inspection differs')
    exact(metadata.get('executable_sha256'),sha(elf),'atomic executable hash differs')
    frame=b'HIAATPK1'+struct.pack('<Q',len(images['policy']))+images['policy']
    receipt=native_receipt(directory,'pack',source=frame,produced=elf,producer=PACKER_IMAGE)
    exact(metadata.get('pack_receipt'),receipt,'atomic actual packer receipt differs')
    pack_files={name:file_record(directory/name) for name in PACK_FILES}
    exact(metadata.get('pack_files'),pack_files,'atomic complete packer files differ')
    exact(source_pins(root),pins,'atomic sources changed while inspecting artifacts')
    return {'schema':'hepta.runtime.atomic-write-artifact-evidence.v1','status':'PASS','manifest':file_record(manifest_path),
      'executable':file_record(directory/'native-atomic-write.elf'),'compiler_commit':COMMIT,'compiler_sha256':COMPILER,
      'compiler_dependency_sha256':DEPENDENCY,'source_files':pins,'modules':module_evidence,'pack_files':pack_files,
      'layout':file_record(directory/'layout.json'),'inspection':inspection}

def build_atomic_write(hepta,build_root,*,source_root=ROOT):
    root=Path(source_root).resolve(strict=True);build_root=Path(build_root).resolve();pins=source_pins(root)
    exact(read(root/'scripts/hia_native_atomic_write_build.py'),read(__file__),'loaded atomic build driver differs')
    build=NativeBuild(hepta,build_root);exact(sha(build.bootstrap().read_bytes()),COMPILER,'atomic compiler image differs')
    exact(sha(canonical(build.identity)),DEPENDENCY,'atomic compiler source closure differs')
    destination=build_root/'atomic-write'/sha(canonical(pins));manifest=destination/'manifest.json'
    if manifest.exists():
        inspect_bundle(manifest,source_root=root,dependency=build.identity);build._recheck();return manifest
    modules={}
    for kind in ('policy','packer'):
        filename='atomic_write.hepta' if kind=='policy' else 'atomic_write_packer.hepta';source=read(root/'native'/filename)
        exact(sha(source),POLICY_SOURCE if kind=='policy' else PACKER_SOURCE,'atomic unqualified source differs')
        name='atomic-write-'+kind+'-'+sha(source)[:16];path=build_root/'modules'/name/'manifest.json'
        if not path.exists():path=build.compile(name,root/'native'/filename,standalone=None,buffer_profile='batch-plan.v1' if kind=='policy' else 'standard')
        modules[kind]=(path,source,obj(path))
    destination.mkdir(parents=True,mode=0o700)
    for kind,(path,source,origin) in modules.items():
        image=read(path.parent/origin['image']);renamed=dict(origin,source=kind+'.hepta',image=kind+'.image.bin')
        write_new(destination/(kind+'.hepta'),source);write_new(destination/(kind+'.image.bin'),image)
        write_new(destination/(kind+'.json'),json_bytes(renamed));folder=destination/(kind+'-build');folder.mkdir(mode=0o700)
        for name in COMPILE_FILES:write_new(folder/name,read(path.parent/name))
        inspect_module(destination,kind,source,dependency=build.identity)
    write_new(destination/'layout.json',read(root/'native/atomic_write_layout.json'))
    frame=b'HIAATPK1'+struct.pack('<Q',len(read(destination/'policy.image.bin')))+read(destination/'policy.image.bin')
    from tools.qualify_hia_selfhost import invoke
    receipt,packed=invoke(destination,'pack',destination/'packer.image.bin',frame)
    count=receipt.get('core_u32');require(type(count)is int and 0<count<=1<<20,'atomic native packer rejected the image')
    elf=packed[:count];inspection=inspect_elf(elf,read(destination/'policy.image.bin'))
    native_receipt(destination,'pack',source=frame,produced=elf,producer=PACKER_IMAGE)
    metadata={'schema':'hepta.runtime.native-atomic-write.v2','target':'linux-x86_64',
      'transport':'u64-length-binary-requests-u32-results','compiler_commit':COMMIT,'compiler_tree':TREE,'compiler_sha256':COMPILER,
      'executable':'native-atomic-write.elf','executable_sha256':sha(elf),'input_capacity':CAPACITIES[0],
      'output_capacity':CAPACITIES[1],'workspace_bytes':CAPACITIES[2],'runtime_python_required':False,'runtime_libc_required':False,
      'registered_mcp_tool':False,'production_activated':False,'whole_runtime_replaced':False,'source_files':pins,
      'inspection':inspection,'pack_receipt':receipt,'pack_files':{name:file_record(destination/name) for name in PACK_FILES}}
    for kind in ('policy','packer'):
        module=obj(destination/(kind+'.json'))
        metadata.update({kind+'_manifest':kind+'.json',kind+'_manifest_sha256':sha(read(destination/(kind+'.json'))),
          kind+'_source_sha256':module['source_sha256'],kind+'_image_sha256':module['image_sha256'],
          kind+'_compilation':{name:file_record(destination/(kind+'-build')/name) for name in COMPILE_FILES}})
    write_new(destination/'native-atomic-write.elf',elf,0o500)
    exact(source_pins(root),pins,'atomic sources changed during build')
    write_new(manifest,json_bytes(metadata));inspect_bundle(manifest,source_root=root,dependency=build.identity);build._recheck();return manifest

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--hepta',type=Path,default=os.environ.get('HIA_HEPTA_DIR'))
    p.add_argument('--build-root',type=Path,default=os.environ.get('HIA_BUILD_ROOT'));a=p.parse_args()
    if not a.hepta or not a.build_root:p.error('--hepta and --build-root or their HIA environment variables are required')
    print(json.dumps({'manifest':str(build_atomic_write(a.hepta,a.build_root))}))
