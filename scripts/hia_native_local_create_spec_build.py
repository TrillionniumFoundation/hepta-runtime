"""Compile and verify the fixed HIA Local Create composition and native bridge."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import stat
import struct
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from hia_native_build import ABI,HEPTA_COMMIT,NativeBuild,json_bytes,write_new
from hia_native_loader import NativeModule
COMPONENT='native/local_create_spec_component.json'
MEMBERS={'caller':'native/local_create_spec.hepta','local_read':'native/local_read.hepta',
         'path':'native/shell_capture_path.hepta','mkdir':'native/shell_capture_mkdir.hepta',
         'write':'native/local_create_file.hepta','key':'native/file_lock_key.hepta',
         'cache':'native/view_cache.hepta','packer':'native/local_create_spec_packer.hepta'}
ORDER=tuple(MEMBERS)[:-1]
SOURCE_FILES=(COMPONENT,*MEMBERS.values(),'scripts/local_create_spec_adapter.S','native/local_create_spec_sources.json')
SCOPE={'local_serial_profile_only':True,'public_handler_qualified':False,'runtime_shutdown_qualified':False,
       'whole_runtime_replaced':False,'old_stack_removal_qualified':False,'production_activated':False}
TAIL=1048576

def digest(raw:bytes)->str:return hashlib.sha256(raw).hexdigest()

def read(path:Path)->bytes:
    mode=path.lstat()
    if not stat.S_ISREG(mode.st_mode) or mode.st_nlink!=1 or path.resolve()!=path.absolute():
        raise ValueError('Local Create artifact must be an ordinary unaliased file: '+str(path))
    return path.read_bytes()

def source_evidence(root:Path=ROOT)->dict:
    metadata=json.loads(read(root/COMPONENT))
    if (metadata.get('schema')!='hepta.runtime.local-create-spec-component.v1'
            or metadata.get('compiler_commit')!=HEPTA_COMMIT or metadata.get('members')!=MEMBERS
            or metadata.get('member_order')!=list(ORDER)
            or metadata.get('target_commit')!='737acf6f901e46c57b0b4374e323e0d1132e0d49'
            or metadata.get('tokio_profile')!='1.53.3'
            or any(metadata.get(k)is not v for k,v in SCOPE.items())):
        raise ValueError('Local Create source scope or fixed members differ')
    pins=metadata.get('source_sha256')
    if not isinstance(pins,dict) or set(pins)!=set(SOURCE_FILES)-{COMPONENT}:
        raise ValueError('Local Create source closure differs')
    for name,want in pins.items():
        if digest(read(root/name))!=want:raise ValueError('Local Create source bytes differ: '+name)
    images=metadata.get('image_sha256')
    if not isinstance(images,dict) or set(images)!=set(MEMBERS):
        raise ValueError('Local Create image closure differs')
    prefix=bytes.fromhex(metadata['prefix_hex']);table=metadata.get('table_offset')
    if (type(table)is not int or len(prefix)!=13680 or len(prefix)!=metadata.get('prefix_bytes')
            or table!=len(prefix)-64 or prefix[96:112]!=bytes(16)
            or prefix[table:table+56]!=bytes(56) or prefix[table+56:]!=b'HLCPSIM1'
            or digest(prefix)!=metadata.get('prefix_sha256')):
        raise ValueError('Local Create native prefix differs')
    proof=json.loads(read(root/'native/local_create_spec_sources.json'))
    if proof.get('source_sha256')!=pins[MEMBERS['caller']] or proof.get('target_commit')!=metadata['target_commit']:
        raise ValueError('Local Create caller derivation differs')
    return {'component_sha256':digest(read(root/COMPONENT)),**metadata}

def expected_executable(component:dict,images:dict[str,bytes])->bytes:
    if set(images)!=set(MEMBERS):raise ValueError('Local Create executable members differ')
    for role,image in images.items():
        if not 0<len(image)<=1048576 or digest(image)!=component['image_sha256'][role]:
            raise ValueError('Local Create member image differs: '+role)
    result=bytearray(bytes.fromhex(component['prefix_hex'])+b''.join(images[role]for role in ORDER))
    struct.pack_into('<QQ',result,96,len(result),len(result))
    for index,role in enumerate(ORDER):struct.pack_into('<Q',result,component['table_offset']+8*index,len(images[role]))
    if (type(component.get('executable_bytes'))is not int or len(result)!=component['executable_bytes']
            or digest(result)!=component.get('executable_sha256')
            or result[:16]!=b'\x7fELF\x02\x01\x01'+bytes(9)
            or struct.unpack_from('<HHIQQQIHHHHHH',result,16)!=(2,62,1,0x4000b0,64,0,0,64,56,2,0,0,0)
            or struct.unpack_from('<IIQQQQQQ',result,64)!=(1,5,0,0x400000,0x400000,len(result),len(result),4096)
            or struct.unpack_from('<IIQQQQQQ',result,120)!=(0x6474e551,6,0,0,0,0,0,16)):
        raise ValueError('Local Create complete static executable differs')
    return bytes(result)

def pack_input(images):
    return b'HLCSPPK1'+b''.join(struct.pack('<Q',len(images[k]))for k in ORDER)+b''.join(images[k]for k in ORDER)

def pack_receipt(c,wire,out,work,code):
    return dict(schema='hepta.runtime.local-create-spec-pack.v1',abi=ABI,compiler_sha256=c['compiler_sha256'],
                packer_image_sha256=c['image_sha256']['packer'],result_u32=code,
                input_bytes=len(wire),input_sha256=digest(wire),output_capacity=len(out),output_sha256=digest(out),
                workspace_capacity=len(work),workspace_sha256=digest(work),source_unchanged=True,borrowed_boundary_guards_unchanged=True)

def check_pack(c,images,wire,out,work,receipt):
    expected=expected_executable(c,images)
    if (wire!=pack_input(images) or out!=expected+b'\xa5'*TAIL or work!=b'\x5a'*4096
            or receipt!=pack_receipt(c,wire,out,work,len(expected)) or type(receipt.get('result_u32'))is not int
            or receipt.get('source_unchanged')is not True or receipt.get('borrowed_boundary_guards_unchanged')is not True):
        raise ValueError('Local Create actual HIA packer receipt or complete buffers differ')
    return expected

def fixed_manifest(component):
    return {'schema':'hepta.runtime.local-create-spec-native.v1','target':'linux-x86_64',
            'compiler_commit':HEPTA_COMMIT,'compiler_sha256':component['compiler_sha256'],
            'source_evidence':component,'executable':'local-create-spec.elf',
            'transport':'u64-framed-cache-setup-one-local-create-cache-inspection',
            'runtime_python_required':False,'runtime_libc_required':False,'dynamic_loader':False,**SCOPE}

def verify_build(manifest_path:Path,*,source_root:Path=ROOT)->dict:
    component=source_evidence(source_root);folder=manifest_path.parent
    metadata=json.loads(read(manifest_path));expected=fixed_manifest(component)
    if (any(metadata.get(k)!=v for k,v in expected.items()) or any(metadata.get(k)is not v for k,v in SCOPE.items())
            or any(metadata.get(k)is not False for k in ('runtime_python_required','runtime_libc_required','dynamic_loader'))):
        raise ValueError('Local Create build manifest scope differs')
    pins=metadata.get('member_manifest_sha256')
    if not isinstance(pins,dict) or set(pins)!=set(MEMBERS):raise ValueError('Local Create member manifests differ')
    images={}
    for role,relative in MEMBERS.items():
        child=json.loads(read(folder/(role+'.json')));source=read(folder/(role+'.hepta'));image=read(folder/(role+'.image.bin'))
        want={'schema':'hepta.runtime.native-module.v1','abi':ABI,'target':'linux-x86_64',
              'compiler_commit':HEPTA_COMMIT,'compiler_sha256':component['compiler_sha256'],
              'source':role+'.hepta','source_sha256':component['source_sha256'][relative],
              'image':role+'.image.bin','image_sha256':component['image_sha256'][role],
              'standalone':None,'buffer_profile':'history.v1','input_capacity':134217728,
              'output_capacity':134217728,'workspace_capacity':268435456}
        if (any(child.get(k)!=v for k,v in want.items()) or pins[role]!=digest(read(folder/(role+'.json')))
                or source!=read(source_root/relative) or digest(image)!=want['image_sha256']):
            raise ValueError('Local Create compiled member differs: '+role)
        images[role]=image
    receipt=json.loads(read(folder/'pack.receipt.json'))
    executable=check_pack(component,images,read(folder/'pack.input.bin'),read(folder/'pack.output.bin'),read(folder/'pack.workspace.bin'),receipt)
    if metadata.get('pack_receipt')!=receipt or read(folder/'local-create-spec.elf')!=executable:
        raise ValueError('Local Create executable or receipt binding differs')
    return metadata

def build_local_create_spec(hepta:Path,build_root:Path,*,source_root:Path=ROOT)->Path:
    hepta,build_root,source_root=hepta.resolve(),build_root.resolve(),source_root.resolve()
    component=source_evidence(source_root);builder=NativeBuild(hepta,build_root)
    if digest(builder.bootstrap().read_bytes())!=component['compiler_sha256']:
        raise ValueError('Local Create compiler fixed point differs')
    folder=build_root/'local-create-spec'/component['component_sha256'];manifest_path=folder/'manifest.json'
    if manifest_path.exists():
        verify_build(manifest_path,source_root=source_root);builder._recheck();return manifest_path
    members={};images={}
    for role,relative in MEMBERS.items():
        name='local-create-spec-'+role+'-'+component['source_sha256'][relative][:16]
        manifest=builder.compile(name,source_root/relative,standalone=None,buffer_profile='history.v1')
        child=json.loads(read(manifest));image=read(manifest.parent/child['image'])
        if (read(manifest.parent/child['source'])!=read(source_root/relative)
                or child.get('source_sha256')!=component['source_sha256'][relative]
                or child.get('compiler_sha256')!=component['compiler_sha256']
                or digest(image)!=component['image_sha256'][role]):
            raise ValueError('Local Create newly compiled member differs: '+role)
        members[role]=(manifest,child);images[role]=image
    executable=expected_executable(component,images);wire=pack_input(images);manifest=members['packer'][0]
    with NativeModule(manifest,manifest_sha256=digest(read(manifest)))as packer:
        code,out,work=packer.invoke_raw(wire,output_capacity=len(executable)+TAIL,
            workspace_capacity=4096,output_fill=165,workspace_fill=90)
    receipt=pack_receipt(component,wire,out,work,code);check_pack(component,images,wire,out,work,receipt)
    folder.mkdir(parents=True,exist_ok=False)
    metadata={**fixed_manifest(component),'member_manifest_sha256':{},'pack_receipt':receipt}
    for role,relative in MEMBERS.items():
        child=dict(members[role][1],source=role+'.hepta',image=role+'.image.bin');encoded=json_bytes(child)
        write_new(folder/(role+'.json'),encoded);write_new(folder/(role+'.hepta'),read(source_root/relative))
        write_new(folder/(role+'.image.bin'),images[role]);metadata['member_manifest_sha256'][role]=digest(encoded)
    for name,raw in {'pack.input.bin':wire,'pack.output.bin':out,'pack.workspace.bin':work,
                     'pack.receipt.json':json_bytes(receipt)}.items():write_new(folder/name,raw)
    write_new(folder/'local-create-spec.elf',executable,0o500);write_new(manifest_path,json_bytes(metadata))
    verify_build(manifest_path,source_root=source_root)
    if source_evidence(source_root)!=component:raise ValueError('Local Create source changed during build')
    builder._recheck();return manifest_path

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hepta',type=Path,required=True);parser.add_argument('--build-root',type=Path,required=True)
    parser.add_argument('--source-root',type=Path,default=ROOT);args=parser.parse_args()
    print(build_local_create_spec(args.hepta,args.build_root,source_root=args.source_root))
