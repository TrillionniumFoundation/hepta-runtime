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
IMAGES=("body","metadata","codec","stat","error","publish","read","base64","entropy")
MEMBERS=(("body","native/binary_write_body.hepta"),
    ("metadata","native/file_metadata.hepta"),
    ("codec","native/binary_codec.hepta"),
    ("stat","native/stat_version.hepta"),
    ("error","native/path_error.hepta"),
    ("publish","native/publish_at.hepta"),("read","native/binary_read_body.hepta"),
    ("base64","native/binary_base64_decode.hepta"),("entropy","native/binary_entropy.hepta"),
    ("linker","compiler/elf_static_linker.hepta"),("packer","native/runtime_mcp_image_packer.hepta"))
PATCHES=(("binary_write_body_body_call_displacement",0),("binary_write_body_stat_call_displacement",3),
    ("binary_write_body_codec_call_displacement",2),("binary_write_body_base64_call_displacement",7),
    ("publish_at_body_call_displacement",5),("publish_at_stat_call_displacement",3),
    ("binary_read_body_body_call_displacement",6),("binary_read_body_codec_call_displacement",2),
    ("binary_read_body_stat_call_displacement",3),
    ("file_metadata_body_call_displacement",1),("file_metadata_codec_call_displacement",2),
    ("binary_entropy_body_call_displacement",8),("binary_write_body_error_call_displacement",4))
ASM=("asm/binary_write_body_callable.S","asm/publish_at_callable.S","asm/binary_read_body_callable.S",
    "asm/file_metadata_callable.S","asm/binary_entropy_callable.S","asm/process_orphans.S",
    "asm/binary_write_body_fixture.S")
def flattened(source):
    original="\n".join(owned(source,name).read_text() for name in ASM)
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
    author=process(output,"re-author",[sys.executable,"-I","-S","-B",source/"authoring/author_binary_write_body.py",
        "--source",source,"--hepta",hepta,"--output",output/"authored"])
    for name in("binary_write_body.hepta","binary_write_body_composition.json","binary_write_body.pseudo"):
        require((output/"authored"/name).read_bytes()==owned(source,"native/"+name).read_bytes(),
            "frozen source author output differs")
    require(owned(source,"compiler/elf_static_linker.hepta").read_bytes()
        ==(hepta/"examples/hia_bootstrap/elf_static_linker.hepta").read_bytes(),"exact linker source differs")
    from hia_native_build import NativeBuild
    from hia_native_loader import NativeModule
    native=NativeBuild(hepta,output/"build");members={}
    from bootstrap_input import prepare as prepare_bootstrap
    retained_bootstrap=prepare_bootstrap(source,output,native.identity)
    require((output/"build/bootstrap/bootstrap.json").is_file(),"retained actual B3 receipt is mandatory")
    compiler=native.bootstrap()
    require(pin(compiler)["sha256"]==B3 and native.compiler_sha256==B3,"only admitted copied B3")

    for name,path in MEMBERS:
        result=native.compile("binary-write-body-callable-"+name,owned(source,path),standalone=None,buffer_profile="history.v1")
        meta=decode(result.read_bytes())
        members[name]=dict(source_path=path,manifest=result.relative_to(output).as_posix(),
            identity=pin(result),source=pin(owned(source,path)),image=pin(result.parent/meta["image"]))
    expected_sources=decode(owned(source,"NATIVE_PROVENANCE.json").read_bytes())["hia_sources"]
    require({name:members[name]["source"]["sha256"] for name in IMAGES}==expected_sources,
        "frozen write or qualified dependency source changed")
    require(members["codec"]["image"]["sha256"]=="469f2b555224499b2d9d3c95cc3d772f65fcbe6705fb79804f31fa7c473debe2"
        and members["error"]["image"]["sha256"]=="531c65b74394565a9c2a8ba70f9daa0d466f9c0cb2567525d4397593b6c80943",
        "qualified codec or final literal-error34 formatter image changed")
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
    (output/"link.receipt.json").write_bytes(encoded(dict(actual_return=code,input=pin(output/"link.input.bin"),
        output=pin(output/"link.output.bin"),workspace=pin(output/"link.workspace.bin"))))
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
    for name in IMAGES:
        m=output/members[name]["manifest"];meta=decode(m.read_bytes());images.append((m.parent/meta["image"]).read_bytes())
    patches=[(2,256+symbols[name],index) for name,index in PATCHES]
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
    elf=output/"binary-write-body-callable.elf";elf.write_bytes(raw[32:]);elf.chmod(0o500)
    require(sources(source)==identity["source"],"source changed during build");native._recheck()
    result=dict(status="FRESH_FIXED_BINARY_WRITE_BODY_CALLABLE_BUILD_PASS",source=identity["source"],compiler=native.identity,
        members=members,source_author_process=author,actual_hia_compiles=11,runtime_images=9,mechanical_processes=records,
        retained_actual_b3=retained_bootstrap,
        linked_return=code,packer_return=pack_code,patches=patches,image_offsets=positions,
        image_order=list(IMAGES),exports={k:v for k,v in symbols.items() if k.startswith(("binary_write_body_","publish_at_","binary_read_body_","binary_entropy_","file_metadata_","hia_process_orphans_"))},
        artifacts={name:pin(output/name) for name in ("combined.S","bridge.o","link.input.bin",
            "link.output.bin","link.workspace.bin","link.receipt.json","prefix.elf","pack.input.bin","pack.output.bin","pack.workspace.bin")},
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
