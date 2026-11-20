#!/usr/bin/env python3
"""Independent DATA-only proof of unchanged child builds and the new exact link."""
import hashlib,importlib.util,json,re,struct,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from evidence_common import decode,pin,require,owned,source_evidence

def module(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
parent=module('composition_original_parent_build',ROOT/'parent/scripts/read_parent_build.py')
sys.path.insert(0,str(ROOT/'adapter/scripts'))
adapter=module('composition_original_adapter_data',ROOT/'adapter/scripts/read_capture.py')
from common import source_evidence as adapter_source
ORDER=("parent","body","metadata","codec","stat","error","publish","read","base64","entropy","adapter","planner")
PATCHES=parent.PATCHES+(("binary_write_composition_adapter_call_displacement","adapter"),("binary_write_composition_planner_call_displacement","planner"))
ASM=tuple('parent/'+name for name in parent.ASM[:-1])+('asm/binary_write_composition_callable.S','asm/binary_write_composition_fixture.S')
sha=lambda raw:hashlib.sha256(raw).hexdigest()
object_parts=parent.object_parts

def read_build(source,images_root,linked):
    source,images_root,linked=map(lambda p:Path(p).resolve(strict=True),(source,images_root,linked))
    require(source==ROOT,'fixed source root')
    identity=source_evidence(source);capture=[]
    def raw(root,name):
        path=owned(root,name);value=path.read_bytes();capture.append((path,value));return value
    original_parent=parent.read_build(source/'parent',images_root/'parent',images_root/'original-parent-linked')
    require(original_parent['executable']==dict(bytes=1794048,sha256='6e5fefef8a116d25c07e476b92b96f5b5e39a87f74d1dc10bf1f7ba8dbf7d076'),'fresh entire original parent machine graph changed')
    old_adapter=adapter.read_images(images_root/'adapter',adapter_source(source/'adapter'))
    manifest_raw=raw(images_root,'IMAGES.json');images=decode(manifest_raw)
    require(images['schema']=='hepta.runtime.binary-write-composition-images.v1' and images['status']=='FRESH_ACTUAL_B3_COMPILE_PASS'
            and images['source']==identity and images['actual_hia_compilations']==16
            and images['new_seed_executions']==images['new_bootstrap_generations']==images['application_executions']==0
            and images['public_binary_write_registered']is False and images['whole_runtime_replaced']is False,'actual new build scope')
    require(images['children']=={kind:pin(images_root/kind/'IMAGES.json')for kind in('parent','adapter')}
            and images['original_parent_executable']==original_parent['executable'],'exact retained child provenance')
    derived={};bodies={}
    for kind in('parent','adapter'):
        child=decode(raw(images_root/kind,'IMAGES.json'))
        names=child['members']if kind=='parent'else('adapter','planner')
        for name in names:
            row=dict(child['members'][name]);row['source_path']=kind+'/'+row['source_path'];row['manifest']=kind+'/'+row['manifest'];derived[name]=row
            mp=images_root/row['manifest'];meta=decode(raw(mp.parent,mp.name));bodies[name]=raw(mp.parent,meta['image'])
    require(derived==images['members'] and set(derived)==set(ORDER)|{'linker','packer'},'entire exact fourteen-member source map')
    labels=('parent','adapter','original-parent-link','composition-fixture-author')
    require(len(images['processes'])==len(labels),'all actual build subprocesses')
    first=images['processes'][0]['argv']
    require(len(first)==11 and Path(first[6]).is_absolute() and Path(first[8]).is_absolute(),'absolute exact retained compiler and bootstrap inputs')
    expected_argv={kind:[sys.executable,'-I','-S','-B',str(source/kind/'scripts/build_images.py'),
                         '--hepta',first[6],'--retained-bootstrap',first[8],'--output',str(images_root/kind)]
                   for kind in('parent','adapter')}
    expected_argv['original-parent-link']=[sys.executable,'-I','-S','-B',str(source/'parent/scripts/link_callable.py'),
        '--images',str(images_root/'parent'),'--output',str(images_root/'original-parent-linked')]
    expected_argv['composition-fixture-author']=[sys.executable,'-I','-S','-B',str(source/'authoring/author_composition_fixture.py'),
        '--source',str(source),'--output',str(images_root/'authored')]
    for label,record in zip(labels,images['processes']):
        require(record==decode(raw(images_root,label+'.json')) and record['argv']==expected_argv[label]
                and type(record['returncode'])is int and record['returncode']==0
                and record['limit_seconds']==(120 if label in('parent','adapter')else 30)
                and 0<=record['elapsed_ns']<record['limit_seconds']*1000000000,'actual bounded fresh build subprocess')
        for stream in('stdout','stderr'):require(pin(images_root/(label+'.'+stream))==record[stream],'entire build subprocess stream')
        require(raw(images_root,label+'.stderr')==b'','build subprocess stderr')
    for name,destination in(('binary_write_composition_fixture.S','asm'),('binary_write_composition_fixture_edits.json','authoring')):
        require(raw(images_root,'authored/'+name)==raw(source,destination+'/'+name),'whole actual reauthored mechanical fixture')
    record=decode(raw(linked,"BUILD.json"))
    require(record["status"]=="ACTUAL_HIA_LINK_AND_PACK_PASS"and record["images_manifest"]==dict(bytes=len(manifest_raw),sha256=sha(manifest_raw))
            and record["application_executions"]==0 and record["runtime_python_required"]is False and record["runtime_libc_required"]is False,
            "actual HIA static composition scope")
    require(record["native_sources"]=={name:pin(source/name)for name in ASM},"every fixed mechanical native source")
    for index,(name,argv)in enumerate((
        ("assemble",["as","--64","-o",str(linked/"bridge.o"),str(linked/"combined.S")]),
        ("relocations",["readelf","-r",str(linked/"bridge.o")]))):
        process=decode(raw(linked,name+".json"))
        require(process==record["processes"][index] and process["argv"]==argv
                and process["locale"]=={"LC_ALL":"C","LANG":"C"}
                and type(process["returncode"])is int and process["returncode"]==0
                and process["timed_out"]is False and process["limit_seconds"]==30
                and 0<=process["elapsed_ns"]<31_000_000_000,"actual bounded mechanical tool completion")
        for stream in("stdout","stderr"):
            value=raw(linked,name+"."+stream)
            require(dict(bytes=len(value),sha256=sha(value))==process["streams"][stream],"entire mechanical tool stream")
        require(raw(linked,name+".stderr")==b"","actual mechanical tool stderr")
    require(len(record["processes"])==2 and b"There are no relocations"in raw(linked,"relocations.stdout"),
            "exact mechanical tool inventory and relocation report")
    original="\n".join(raw(source,name).decode()for name in ASM)
    flattened=raw(linked,"combined.S").decode();names=re.findall(r"^\.global ([A-Za-z_][A-Za-z_0-9]*)$",original,re.M)
    require(len(names)==len(set(names))and names.count("_start")==1,"fixed native export set")
    restored=flattened
    for name in reversed(names):
        if name=="_start":continue
        alias=name+"_flat"
        restored=restored.replace("\n"+alias+":","")
        restored=re.sub(r"\b(call|jmp) "+re.escape(alias)+r"\b",lambda match:match[1]+" "+name,restored)
        restored=restored.replace("[rip + "+alias+"]","[rip + "+name+"]")
    require(restored==original,"whole mechanical label flattening inverse")
    for name,row in record["artifacts"].items():require(pin(owned(linked,name))==row,"complete build artifact bytes")
    obj=raw(linked,"bridge.o");text,symbols=object_parts(obj)
    require(symbols==record["symbols"],"independent ELF symbol table")
    frame=b"HIALNK01"+struct.pack("<3Q",1,6,0)+b"_start"+struct.pack("<Q",len(obj))+obj
    require(raw(linked,"link.input.bin")==frame,"whole actual HIA linker input")
    output=raw(linked,"link.output.bin");prefix=raw(linked,"prefix.elf");end=256+len(text);code=record["linked_return"]
    require(len(output)==8<<20 and len(raw(linked,"link.workspace.bin"))==32<<20 and code==(end+4095)&~4095
            and prefix==output[:code]and prefix[256:end]==text and prefix[end:]==bytes(code-end)
            and output[code:]==bytes(len(output)-code)and struct.unpack_from("<Q",prefix,24)[0]==4194304+232
            and prefix[238]==0xe8 and 243+struct.unpack_from("<i",prefix,239)[0]==256+symbols["_start"],"actual linked static ELF bytes")
    patches=[(2,256+symbols[name],ORDER.index(member))for name,member in PATCHES]
    for _,at,_in in patches:require(prefix[at-1:at+4]==b"\xe9\0\0\0\0","fixed immutable image entry")
    frame=b"HIAIMG02"+struct.pack("<4Q",len(prefix),len(ORDER),len(patches),0)+prefix
    frame+=b"".join(struct.pack("<Q",len(bodies[name]))for name in ORDER)
    frame+=b"".join(struct.pack("<3Q",*patch)for patch in patches)+b"".join(bodies[name]for name in ORDER)
    require(raw(linked,"pack.input.bin")==frame,"whole actual HIA pack input")
    expected=bytearray(prefix);positions=[]
    for name in ORDER:
        expected+=bytes(-len(expected)%16);positions.append(len(expected));expected+=bodies[name]
    end=len(expected);expected+=bytes(-len(expected)%4096)
    for _,at,index in patches:struct.pack_into("<i",expected,at,positions[index]-at-4)
    struct.pack_into("<QQ",expected,96,end,end)
    struct.pack_into("<QQQ",expected,128,len(expected),4194304+len(expected),4194304+len(expected))
    require(record["patches"]==[list(patch)for patch in patches]and record["image_order"]==list(ORDER)
            and record["image_offsets"]==positions and record["packer_return"]==32,"fixed complete image map")
    require(raw(linked,"pack.output.bin")==b"HIAIMR02"+struct.pack("<3Q",0,len(expected),0)+expected
            and len(raw(linked,"pack.workspace.bin"))==4096,"actual complete HIA pack output/workspace")
    executable=raw(linked,"binary-write-composition.elf")
    require(executable==expected and record["executable"]==dict(bytes=len(executable),sha256=sha(executable)),"actual composed executable")
    for path,value in capture:require(path.read_bytes()==value,"raw build custody changed during DATA readback")
    require(source_evidence(source)==identity,"whole source changed during build readback")
    return dict(status='PASS_ACTUAL_BUILD_DATA_READBACK',source=identity,images=16,runtime_images=12,
                original_parent_executable=original_parent['executable'],executable=record['executable'],compiler_sha256=parent.B3,
                whole_runtime_replaced=False,public_binary_write_registered=False)

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    for name in('images','build'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();print(json.dumps(read_build(ROOT,args.images,args.build),sort_keys=True))
