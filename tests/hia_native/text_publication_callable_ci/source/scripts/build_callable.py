#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Fresh fixed HIA compilation, actual HIA ELF link and actual HIA image pack."""
from pathlib import Path
import argparse
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import time
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from callable_common import B3,HEPTA,SCOPE,decode,encoded,owned,pin,require,sha,sources,syntax
MEMBERS=(("publication","native/text_file_publication.hepta"),
    ("codec","native/binary_codec.hepta"),("errno","native/directory_errno.hepta"),
    ("linker","compiler/elf_static_linker.hepta"),("packer","native/runtime_mcp_image_packer.hepta"))
PATCHES=("text_publication_body_call_displacement","text_publication_codec_call_displacement","text_publication_errno_call_displacement")
def flattened(source):
    original=owned(source,"asm/text_publication_callable.S").read_text()+"\n"+owned(source,"asm/text_publication_fixture.S").read_text()
    value=original;names=re.findall(r"^\.global ([A-Za-z_][A-Za-z_0-9]*)$",value,re.M)
    require(len(names)==len(set(names)) and names.count("_start")==1,"global symbol declaration differs")
    for name in names:
        if name=="_start":continue
        alias=name+"_flat"
        require("\n"+alias+":" not in value,"existing flatten alias")
        value=value.replace("\n"+name+":","\n"+name+":\n"+alias+":")
        value=re.sub(r"\b(call|jmp) "+re.escape(name)+r"\b",lambda m:m[1]+" "+alias,value)
        value=value.replace("[rip + "+name+"]","[rip + "+alias+"]")
    restored=value
    for name in reversed(names):
        if name=="_start":continue
        alias=name+"_flat"
        restored=restored.replace("\n"+alias+":","")
        restored=re.sub(r"\b(call|jmp) "+re.escape(alias)+r"\b",lambda m:m[1]+" "+name,restored)
        restored=restored.replace("[rip + "+alias+"]","[rip + "+name+"]")
    require(restored==original,"mechanical label flattening is not reversible")
    return value
def object_layout(raw):
    require(raw[:6]==b"\x7fELF\x02\x01" and struct.unpack_from("<H",raw,16)[0]==1,"not a little-endian relocatable ELF")
    at=struct.unpack_from("<Q",raw,40)[0];count=struct.unpack_from("<H",raw,60)[0]
    sections=[struct.unpack_from("<IIQQQQIIQQ",raw,at+i*64) for i in range(count)]
    names=sections[struct.unpack_from("<H",raw,62)[0]];strings=raw[names[4]:names[4]+names[5]]
    labels=[strings[h[0]:strings.index(0,h[0])].decode() for h in sections]
    index=labels.index(".text");text=sections[index];symbols={}
    require(not any(h[2]&2 and h[5] and i!=index for i,h in enumerate(sections)),
        "callable object contains an unexpected non-text allocated section")
    require(not any(h[1] in (4,9) and h[5] for h in sections),"unexpected ELF relocation")
    for h in sections:
        if h[1]!=2:continue
        st=sections[h[6]];names=raw[st[4]:st[4]+st[5]]
        for p in range(h[4],h[4]+h[5],24):
            name,info,other,section,value,size=struct.unpack_from("<IBBHQQ",raw,p)
            if section==index:
                key=names[name:names.index(0,name)].decode();symbols[key]=value
    return raw[text[4]:text[4]+text[5]],symbols
def process(output,name,argv):
    start=time.monotonic_ns();record=dict(argv=[str(x) for x in argv],limit_seconds=30,timed_out=False)
    with (output/(name+".stdout")).open("xb") as out,(output/(name+".stderr")).open("xb") as err:
        try:
            child=subprocess.run(record["argv"],stdout=out,stderr=err,timeout=30,check=False)
            record["returncode"]=child.returncode
        except subprocess.TimeoutExpired:record["returncode"]=None;record["timed_out"]=True
    record["elapsed_ns"]=time.monotonic_ns()-start
    record["streams"]={s:pin(output/(name+"."+s)) for s in ("stdout","stderr")}
    (output/(name+".json")).write_bytes(encoded(record))
    require(record["returncode"]==0 and record["timed_out"] is False,"mechanical process failed: "+name)
    require((output/(name+".stderr")).read_bytes()==b"","mechanical process stderr: "+name)
    return record
def build(source,hepta,output):
    require(os.environ.get("GITHUB_ACTIONS")=="true","native build restricted to CI")
    require(not output.exists(),"fresh build required");output.mkdir(parents=True)
    identity=syntax(source)
    require(owned(source,"compiler/elf_static_linker.hepta").read_bytes()
        ==(hepta/"examples/hia_bootstrap/elf_static_linker.hepta").read_bytes(),"exact linker source differs")
    from hia_native_build import NativeBuild
    from hia_native_loader import NativeModule
    native=NativeBuild(hepta,output/"build");members={}
    for name,path in MEMBERS:
        result=native.compile("publication-callable-"+name,owned(source,path),standalone=None,buffer_profile="history.v1")
        meta=decode(result.read_bytes())
        members[name]=dict(source_path=path,manifest=result.relative_to(output).as_posix(),
            identity=pin(result),source=pin(owned(source,path)),image=pin(result.parent/meta["image"]))
    require(members["publication"]["image"]["sha256"]=="aa9da00952a7ed6c3036a58f88e498168bac09412a71196ea3cc6b5557597730"
        and members["codec"]["image"]["sha256"]=="469f2b555224499b2d9d3c95cc3d772f65fcbe6705fb79804f31fa7c473debe2",
        "qualified publication or codec image changed")
    compiler=output/"compiler-source";compiler.mkdir()
    for name in native.identity["files"]:
        path=compiler/name;path.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(hepta/name,path)
    (output/"combined.S").write_text(flattened(source))
    records=[process(output,"assemble",["as","--64","-o",output/"bridge.o",output/"combined.S"]),
        process(output,"relocations",["readelf","-r",output/"bridge.o"])]
    require(b"There are no relocations" in (output/"relocations.stdout").read_bytes(),"unexpected relocation report")
    obj=(output/"bridge.o").read_bytes();text,symbols=object_layout(obj)
    entry=b"_start";frame=b"HIALNK01"+struct.pack("<3Q",1,len(entry),0)+entry+struct.pack("<Q",len(obj))+obj
    (output/"link.input.bin").write_bytes(frame)
    link_manifest=output/members["linker"]["manifest"]
    with NativeModule(link_manifest,manifest_sha256=members["linker"]["identity"]["sha256"]) as module:
        code,raw,work=module.invoke_raw(frame,output_capacity=8<<20,workspace_capacity=32<<20,output_fill=0,workspace_fill=0)
    (output/"link.output.bin").write_bytes(raw);(output/"link.workspace.bin").write_bytes(work)
    text_end=256+len(text);aligned=(text_end+4095)&~4095
    require(256<text_end<=code==aligned<=len(raw),"linked output extent differs")
    prefix=raw[:code];(output/"prefix.elf").write_bytes(prefix)
    require(prefix[256:text_end]==text and prefix[text_end:]==bytes(code-text_end)
        and raw[code:]==bytes(len(raw)-code) and prefix[:4]==b"\x7fELF"
        and struct.unpack_from("<Q",prefix,24)[0]==4194304+232
        and prefix[238]==0xe8
        and 243+struct.unpack_from("<i",prefix,239)[0]==256+symbols["_start"]
        and struct.unpack_from("<QQ",prefix,96)==(text_end,text_end)
        and struct.unpack_from("<QQQ",prefix,128)==(code,4194304+code,4194304+code),
        "actual linker text, startup call, segments or zero padding differ")
    images=[]
    for name in ("publication","codec","errno"):
        m=output/members[name]["manifest"];meta=decode(m.read_bytes());images.append((m.parent/meta["image"]).read_bytes())
    patches=[(2,256+symbols[name],index) for index,name in enumerate(PATCHES)]
    for _,at,_ in patches:require(prefix[at-1:at+4]==b"\xe9\0\0\0\0","fixed HIA call patch differs")
    frame=b"HIAIMG02"+struct.pack("<4Q",len(prefix),len(images),len(patches),0)+prefix
    frame+=b"".join(struct.pack("<Q",len(raw)) for raw in images)+b"".join(struct.pack("<3Q",*p) for p in patches)+b"".join(images)
    (output/"pack.input.bin").write_bytes(frame)
    expected=bytearray(prefix);positions=[]
    for image in images:
        expected+=bytes(-len(expected)%16);positions.append(len(expected));expected+=image
    text_end=len(expected);expected+=bytes(-len(expected)%4096)
    for kind,at,index in patches:struct.pack_into("<I",expected,at,positions[index]-at-4)
    struct.pack_into("<QQ",expected,96,text_end,text_end)
    struct.pack_into("<QQQ",expected,128,len(expected),4194304+len(expected),4194304+len(expected))
    pack_manifest=output/members["packer"]["manifest"];workcap=4096
    with NativeModule(pack_manifest,manifest_sha256=members["packer"]["identity"]["sha256"]) as module:
        pack_code,raw,work=module.invoke_raw(frame,output_capacity=32+len(expected),workspace_capacity=workcap,
            output_fill=0xb3,workspace_fill=0xc7)
    (output/"pack.output.bin").write_bytes(raw);(output/"pack.workspace.bin").write_bytes(work)
    require(pack_code==32 and raw==b"HIAIMR02"+struct.pack("<3Q",0,len(expected),0)+expected,
        "actual HIA image pack differs from fixed layout")
    elf=output/"text-publication-callable.elf";elf.write_bytes(raw[32:]);elf.chmod(0o500)
    require(sources(source)==identity["source"],"source changed during build");native._recheck()
    result=dict(status="FRESH_FIXED_PUBLICATION_CALLABLE_BUILD_PASS",source=identity["source"],compiler=native.identity,
        members=members,actual_hia_compiles=5,runtime_images=3,mechanical_processes=records,
        linked_return=code,packer_return=pack_code,patches=patches,image_offsets=positions,
        image_order=["publication","codec","errno"],exports={k:v for k,v in symbols.items() if k.startswith("text_publication_")},
        artifacts={name:pin(output/name) for name in ("combined.S","bridge.o","link.input.bin",
            "link.output.bin","link.workspace.bin","prefix.elf","pack.input.bin","pack.output.bin","pack.workspace.bin")},
        executable=pin(elf),scope=SCOPE,native_semantics_executed=False,
        runtime_python_required=False,runtime_libc_required=False)
    (output/"BUILD.json").write_bytes(encoded(result));print(json.dumps(result,sort_keys=True))
    return result
def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("mode",choices=("check","build"))
    parser.add_argument("--source",type=Path,required=True);parser.add_argument("--hepta",type=Path);parser.add_argument("--output",type=Path)
    args=parser.parse_args();source=args.source.resolve(strict=True)
    if args.mode=="check":print(json.dumps(syntax(source),sort_keys=True))
    else:build(source,args.hepta.resolve(strict=True),args.output.absolute())
if __name__=="__main__":main()
