"""Build the pure batch planner's wide images and fixed four-image test ELF.

The Python layer holds artifacts. Every planning and endpoint decision executes
in the admitted HIA images. The ELF has no Python runtime or filesystem owner.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from hia_native_build import NativeBuild,HEPTA_COMMIT,HEPTA_TREE,json_bytes,write_new
from hia_native_loader import NativeModule,BUFFER_PROFILES

COMPILER='bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'
PACKER='4367179d1c4776853d5c9542db6582b24be2c59c76ac8d1c347d6373cb297d5a'
IMAGES=('86a51a65697f937c790ca1acd9578e642ca5fbb293572e7785188f9dc40b9432',
 'b5b189a7a108135c11fbbe6b34cbd104fc096d74e9ce8cacdffdf40f6672e036',
 '0015c437dfdda0e3538e97c3296b3ce6f073a0bc78ed78456b5fb2780b140079',
 '01e6c20286db43b4c995b676eaf93e2b7a23ab6c17588e43ef05d2fe91ac1233')
SPECS=(('batch-hex-fixture','tests/hia_native/record_hex_transport.hepta',1,2,8<<20,8<<20,16<<20),
 ('batch-plan','native/batch_plan.hepta',1,12,8<<20,2<<20,16<<20),
 ('line-endpoint','native/line_endpoint.hepta',0,0,8<<20,8<<20,8),
 ('line-verify','native/line_verify.hepta',0,0,8<<20,8<<20,192))
REFERENCE_FILES=('native/composition_packer.hepta','native/io_policy.hepta','native/text_budget.hepta',
 'native/line_endpoint.hepta','native/line_verify.hepta','tests/hia_native/record_hex_transport.hepta',
 'scripts/hia_native_composition_build.py','scripts/hia_native_entropy_qualification.py',
 'scripts/hia_native_scope_qualification.py','scripts/check_hia_native_inventory.py')
OWN_FILES=('native/batch_plan.hepta','native/batch_plan_composition.json',
 'scripts/hia_native_build.py','scripts/hia_native_loader.py','scripts/hia_native_batch_plan_build.py')

def require(condition,message):
    if not condition:raise ValueError(message)
def read(path):
    path=Path(path)
    require(path.is_file() and not path.is_symlink() and path.absolute()==path.resolve(),'artifact must be a regular unsymlinked file: '+str(path))
    return path.read_bytes()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def at(root,relative):
    name=Path(relative)
    require(not name.is_absolute() and '..' not in name.parts and name.parts,'artifact path escaped its build root')
    result=Path(root)/name;read(result);return result
def source_path(root,reference,index):return (root if index==1 else reference)/SPECS[index][1]
def source_pins(root,reference):
    return {'owner':{name:sha(read(root/name)) for name in OWN_FILES},
            'reference':{name:sha(read(reference/name)) for name in REFERENCE_FILES}}
def support(reference):
    # Explicit admission also works when the checkout is named runtime and under -I.
    sys.path.insert(0,str(reference/'scripts'))
    def load(name,file):
        spec=importlib.util.spec_from_file_location(name,reference/'scripts'/file)
        module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module);return module
    return (load('_batch_composition','hia_native_composition_build.py'),
            load('_batch_compile_receipts','hia_native_entropy_qualification.py'),
            load('_batch_embedded_images','hia_native_scope_qualification.py'))

def module_identity(path,source,*,wide,image_sha):
    raw=read(path);m=json.loads(raw)
    capacities=BUFFER_PROFILES['batch-plan.v1' if wide else 'standard']
    expected={'schema':'hepta.runtime.native-module.v1','target':'linux-x86_64',
      'abi':'hepta.runtime.borrowed-bytes.linux-x86_64.v1','compiler_commit':HEPTA_COMMIT,
      'compiler_sha256':COMPILER,'source_sha256':sha(source),'image_sha256':image_sha,
      'input_capacity':capacities[0],'output_capacity':capacities[1],'workspace_capacity':capacities[2],
      'standalone':None}
    require(all(type(m.get(k)) is type(v) and m[k]==v for k,v in expected.items()),'batch native module identity or capacity differs')
    require(m.get('buffer_profile','standard')==('batch-plan.v1' if wide else 'standard'),'batch buffer profile differs')
    for field in ('source','image'):require(len(Path(m[field]).parts)==1 and not Path(m[field]).is_absolute(),'module artifact path differs')
    require(read(path.parent/m['source'])==source,'compiled batch source bytes differ')
    image=read(path.parent/m['image']);require(sha(image)==image_sha,'compiled batch image bytes differ')
    with NativeModule(path,manifest_sha256=sha(raw)):pass
    return m,image

def compilation(path,source,image,build_root,receipt_support):
    receipt=json.loads(read(path.parent/'module.receipt.json'))
    compiler=read(build_root/'bootstrap/B3.image.bin')
    require(sha(compiler)==COMPILER,'batch compiler fixed point differs')
    receipt_support.native_receipt(receipt,image=compiler,source=source,output=read(path.parent/'module.output.bin'),produced=image)
    built=json.loads(read(path.parent/'build.json'));boot=json.loads(read(build_root/'bootstrap/bootstrap.json'))
    require(read(path.parent/'module.input.bin')==source and read(path.parent/'module.image.bin')==image,'batch actual compiler input/output differs')
    require(built.get('compile_receipt')==receipt and built.get('compiler_dependency')==boot.get('dependency'),'batch compiler provenance differs')
    require(boot['dependency']['commit']==HEPTA_COMMIT and boot['dependency']['tree']==HEPTA_TREE,'batch compiler source pin differs')
    return {name:sha(read(path.parent/name)) for name in ('module.receipt.json','module.input.bin','module.output.bin','module.image.bin','build.json')}

def inspect_composition(root,reference,manifest,build_root):
    _,receipt_support,embedding=support(reference)
    raw=read(manifest);meta=json.loads(raw)
    profile=[{'id':i,'name':s[0],'source_sha256':sha(read(source_path(root,reference,i))),
      'flags':s[2],'call_mask':s[3],'input_capacity':s[4],'output_capacity':s[5],'workspace_capacity':s[6]} for i,s in enumerate(SPECS)]
    require(meta.get('profile')==profile and len(meta.get('members',[]))==4,'batch fixed four-image profile differs')
    required={'schema':'hepta.runtime.native-composition.v1','compiler_commit':HEPTA_COMMIT,
      'compiler_sha256':COMPILER,'target':'linux-x86_64','executable':'native-local-read.elf',
      'runtime_python_required':False,'runtime_libc_required':False,'whole_runtime_replaced':False}
    require(all(type(meta.get(k)) is type(v) and meta[k]==v for k,v in required.items()),'batch static composition contract differs')
    packer=read(reference/'native/composition_packer.hepta');require(sha(packer)==PACKER,'batch packer identity differs')
    rows=[('packer',packer,meta['packer'],None)]+[(f'module_{i:02d}',read(source_path(root,reference,i)),meta['members'][i],i) for i in range(4)]
    frame=bytearray(b'HIABND01'+struct.pack('<3Q',4,0,0));images=[];receipts={}
    for stem,source,row,index in rows:
        require(row.get('manifest')==stem+'.json','batch packed child path differs')
        path=manifest.parent/(stem+'.json');require(sha(read(path))==row.get('manifest_sha256'),'batch packed child manifest changed')
        wanted='5cefb7cefc27ae1d1bddbdeefca2721f00ff6235fa85132744e2fe3e1048889e' if index is None else IMAGES[index]
        module,image=module_identity(path,source,wide=False,image_sha=wanted)
        require(row.get('source_sha256')==sha(source) and row.get('image_sha256')==wanted,'batch packed child source/image differs')
        compiled=build_root/'modules'/('composition-'+sha(source)[:24])/'manifest.json'
        original,original_image=module_identity(compiled,source,wide=False,image_sha=wanted)
        require(original_image==image,'packed batch child differs from compiled owner')
        receipts[stem]=compilation(compiled,source,image,build_root,receipt_support)
        if index is not None:
            p=profile[index];images.append(image)
            frame.extend(struct.pack('<8Q',len(image),p['input_capacity'],p['output_capacity'],p['workspace_capacity'],p['flags'],p['call_mask'],0,0))
            frame.extend(bytes.fromhex(sha(source))+bytes.fromhex(sha(image))+image)
    elf=read(manifest.parent/'native-local-read.elf');layout=embedding.embedded_images(elf,profile,images)
    require(meta.get('key')==sha(json_bytes({'compiler':COMPILER,'members':profile,'packer':PACKER})),'batch composition key differs')
    require(meta.get('frame_bytes')==len(frame) and meta.get('frame_sha256')==sha(frame),'batch actual HIA packer input differs')
    require(meta.get('executable_sha256')==sha(elf) and meta.get('inspection')==receipt_support.inspect_elf(elf),'batch actual ELF bytes/header differ')
    require(meta.get('packing')=={'owner':'HIA','input_unchanged':True,'buffer_canaries_unchanged':True,'packer_image_sha256':meta['packer']['image_sha256']},'batch packer receipt contract differs')
    return {'manifest_sha256':sha(raw),'executable_sha256':sha(elf),'frame_sha256':sha(frame),'profile':profile,'layout':layout,'compilation_receipts':receipts}

def inspect_bundle(path,*,source_root=ROOT,reference_root=None):
    root=Path(source_root).resolve();reference=Path(reference_root or root).resolve();path=Path(path).absolute()
    raw=read(path);m=json.loads(raw);build_root=path.parents[2]
    expected={'schema':'hepta.runtime.batch-plan-bundle.v1','compiler_commit':HEPTA_COMMIT,'compiler_sha256':COMPILER,
      'buffer_profile':'batch-plan.v1','complete_original_tool_parity':False,'production_activated':False}
    require(all(type(m.get(k)) is type(v) and m[k]==v for k,v in expected.items()),'batch bundle contract differs')
    require(path.name=='bundle.json' and path.parent.parent.name=='batch-plan','batch bundle layout differs')
    pins=source_pins(root,reference);require(m.get('source_pins')==pins,'batch build source closure changed')
    require(m.get('source_composition_sha256')==sha(read(root/'native/batch_plan_composition.json')),'batch composition provenance changed')
    key=sha(json_bytes({'compiler':COMPILER,'pins':pins,'buffer_profile':'batch-plan.v1'}))
    require(path.parent.name==key and m.get('key')==key,'batch bundle key differs')
    _,receipt_support,_=support(reference);loaded=[];manifests={};receipts={}
    require(len(m.get('wide_modules',[]))==3,'batch wide module count differs')
    for i,row in enumerate(m['wide_modules'],1):
        require(type(row.get('id')) is int and row['id']==i,'batch wide leaf order differs')
        child=at(build_root,row['manifest']);require(sha(read(child))==row.get('manifest_sha256'),'batch wide manifest changed')
        source=read(source_path(root,reference,i));module,image=module_identity(child,source,wide=True,image_sha=IMAGES[i])
        require(child.parent.name=='batch-plan-wide-'+sha(source)[:20] and child.parent.parent==build_root/'modules','batch wide cache path differs')
        receipts[str(i)]=compilation(child,source,image,build_root,receipt_support);manifests[i]=child
        loaded.append({'id':i,'manifest_sha256':sha(read(child)),'source_sha256':sha(source),'image_sha256':sha(image),'compiler_commit':HEPTA_COMMIT,'compiler_sha256':COMPILER,'buffer_profile':'batch-plan.v1'})
    composition=at(build_root,m['composition']['manifest'])
    require(sha(read(composition))==m['composition'].get('manifest_sha256'),'batch ELF manifest changed')
    packed=inspect_composition(root,reference,composition,build_root)
    return {'manifest_sha256':sha(raw),'loaded_artifacts':loaded,'wide_compilation_receipts':receipts,'composition':packed,
      'manifests':manifests,'elf_manifest':composition,'build_root':build_root,'source_pins':pins}

def build_batch_plan(hepta,build_root,*,source_root=ROOT,reference_root=None):
    root=Path(source_root).resolve();reference=Path(reference_root or root).resolve();build_root=Path(build_root).resolve()
    build=NativeBuild(hepta,build_root);require(sha(read(build.bootstrap()))==COMPILER,'batch compiler differs')
    pins=source_pins(root,reference);key=sha(json_bytes({'compiler':COMPILER,'pins':pins,'buffer_profile':'batch-plan.v1'}))
    destination=build_root/'batch-plan'/key;path=destination/'bundle.json'
    if path.exists():inspect_bundle(path,source_root=root,reference_root=reference);return path
    rows=[]
    for i in range(1,4):
        source=source_path(root,reference,i);raw=read(source);name='batch-plan-wide-'+sha(raw)[:20]
        child=build_root/'modules'/name/'manifest.json'
        if not child.exists():child=build.compile(name,source,standalone=None,buffer_profile='batch-plan.v1')
        module_identity(child,raw,wide=True,image_sha=IMAGES[i]);rows.append({'id':i,'manifest':child.relative_to(build_root).as_posix(),'manifest_sha256':sha(read(child))})
    generic,_,_=support(reference)
    specs=[generic.ModuleSpec(s[0],source_path(root,reference,i),flags=s[2],call_mask=s[3],input_capacity=s[4],output_capacity=s[5],workspace_capacity=s[6]) for i,s in enumerate(SPECS)]
    composition=generic.build_composition(Path(hepta),build_root,specs,source_root=reference)
    inspect_composition(root,reference,composition,build_root)
    require(source_pins(root,reference)==pins,'batch source closure changed during build');build._recheck()
    result={'schema':'hepta.runtime.batch-plan-bundle.v1','key':key,'compiler_commit':HEPTA_COMMIT,'compiler_sha256':COMPILER,
      'buffer_profile':'batch-plan.v1','source_pins':pins,'source_composition_sha256':sha(read(root/'native/batch_plan_composition.json')),
      'wide_modules':rows,'composition':{'manifest':composition.relative_to(build_root).as_posix(),'manifest_sha256':sha(read(composition))},
      'complete_original_tool_parity':False,'production_activated':False}
    destination.mkdir(parents=True,exist_ok=False);write_new(path,json_bytes(result));inspect_bundle(path,source_root=root,reference_root=reference);return path

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hepta',type=Path,default=os.environ.get('HIA_HEPTA_DIR'))
    parser.add_argument('--build-root',type=Path,default=os.environ.get('HIA_BUILD_ROOT'))
    parser.add_argument('--source-root',type=Path,default=ROOT)
    parser.add_argument('--reference-root',type=Path)
    args=parser.parse_args()
    if not args.hepta or not args.build_root:parser.error('pinned Hepta checkout and build root are required')
    print(json.dumps({'manifest':str(build_batch_plan(args.hepta,args.build_root,source_root=args.source_root,reference_root=args.reference_root))}))
