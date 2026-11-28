#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""DATA-only independent verification of actual compilation, native link and pack."""
import hashlib
import json
from pathlib import Path
import re
import stat
import struct
from evidence_common import decode,pin,require,owned,source_evidence

B3="bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0"
ORDER=("parent","body","metadata","codec","stat","error","publish","read","base64","entropy")
SOURCES={"parent":"native/binary_parent_owner.hepta","body":"dependency/native/binary_write_body.hepta",
"metadata":"dependency/native/file_metadata.hepta","codec":"dependency/native/binary_codec.hepta",
"stat":"dependency/native/stat_version.hepta","error":"dependency/native/path_error.hepta",
"publish":"dependency/native/publish_at.hepta","read":"dependency/native/binary_read_body.hepta",
"base64":"dependency/native/binary_base64_decode.hepta","entropy":"dependency/native/binary_entropy.hepta",
"linker":"compiler/elf_static_linker.hepta","packer":"dependency/native/runtime_mcp_image_packer.hepta"}
PATCHES=(("binary_parent_owner_body_call_displacement","parent"),("binary_write_body_body_call_displacement","body"),
("binary_write_body_stat_call_displacement","stat"),("binary_write_body_codec_call_displacement","codec"),
("binary_write_body_base64_call_displacement","base64"),("publish_at_body_call_displacement","publish"),
("publish_at_stat_call_displacement","stat"),("binary_read_body_body_call_displacement","read"),
("binary_read_body_codec_call_displacement","codec"),("binary_read_body_stat_call_displacement","stat"),
("file_metadata_body_call_displacement","metadata"),("file_metadata_codec_call_displacement","codec"),
("binary_entropy_body_call_displacement","entropy"),("binary_write_body_error_call_displacement","error"))
ASM=tuple("dependency/asm/"+name+".S"for name in("binary_write_body_callable","publish_at_callable",
"binary_read_body_callable","file_metadata_callable","binary_entropy_callable","process_orphans"))+(
"asm/binary_parent_owner_callable.S","asm/binary_parent_owner_fixture.S")


def sha(raw):return hashlib.sha256(raw).hexdigest()


def object_parts(raw):
    require(raw[:6]==b"\x7fELF\x02\x01" and struct.unpack_from("<H",raw,16)[0]==1,"fixed relocatable input")
    base=struct.unpack_from("<Q",raw,40)[0];count=struct.unpack_from("<H",raw,60)[0]
    headers=[struct.unpack_from("<IIQQQQIIQQ",raw,base+64*i)for i in range(count)]
    names=headers[struct.unpack_from("<H",raw,62)[0]];table=raw[names[4]:names[4]+names[5]]
    strings=[table[h[0]:table.index(0,h[0])].decode()for h in headers]
    section=strings.index(".text");head=headers[section]
    require(not any(h[2]&2 and h[5]and i!=section for i,h in enumerate(headers)),"extra allocated ELF section")
    require(not any(h[1]in(4,9)and h[5]for h in headers),"unresolved relocations")
    symbols={}
    for h in headers:
        if h[1]!=2:continue
        names=headers[h[6]];table=raw[names[4]:names[4]+names[5]]
        for at in range(h[4],h[4]+h[5],24):
            name,info,other,owner,value,size=struct.unpack_from("<IBBHQQ",raw,at)
            if owner==section:symbols[table[name:table.index(0,name)].decode()]=value
    return raw[head[4]:head[4]+head[5]],symbols


def read_build(source,images_root,linked):
    source,images_root,linked=map(Path,(source,images_root,linked))
    identity=source_evidence(source)
    capture=[]
    def raw(root,name):
        path=owned(root,name);value=path.read_bytes();capture.append((path,value));return value
    frozen=decode(raw(source,"COMPILER_INPUT.json"))
    require(frozen["commit"]=="d3e2c90173cf733e42b299d0c4274df4b593a12f"
            and frozen["tree"]=="8d8b0fb8d015fb7edab302498bb9ed4c74ab6f49"and len(frozen["files"])==1080,
            "complete fixed compiler closure")
    manifest_raw=raw(images_root,"IMAGES.json");images=decode(manifest_raw)
    require(images["status"]=="FRESH_ACTUAL_B3_COMPILE_PASS" and images["source"]==identity and images["compiler"]==frozen
            and images["compiler_image"]["sha256"]==B3 and images["new_seed_executions"]==0
            and images["new_bootstrap_generations"]==0 and images["application_executions"]==0
            and images["qualification"]=="development_fixed_point" and set(images["members"])==set(SOURCES),
            "fresh actual compiler construction scope")
    copied=images_root/"compiler-source"
    require({p.relative_to(copied).as_posix()for p in copied.rglob("*")if p.is_file()}==set(frozen["files"]),"complete copied compiler source set")
    for name,digest in frozen["files"].items():require(sha(raw(copied,name))==digest,"copied compiler source bytes")
    bootstrap=images_root/"build/bootstrap"
    receipt=decode(raw(bootstrap,"bootstrap.json"))
    require(receipt["dependency"]==frozen and receipt["generation_sha256"]==B3
            and receipt["qualification"]=="development_fixed_point","actual retained B3 receipt")
    require({p.relative_to(bootstrap).as_posix()for p in bootstrap.rglob("*")if p.is_file()}==set(images["retained_bootstrap"]),"whole copied B3 inventory")
    for name,row in images["retained_bootstrap"].items():
        value=raw(bootstrap,name)
        require(dict(bytes=len(value),sha256=sha(value),mode=stat.S_IMODE((bootstrap/name).stat().st_mode))==row,"whole copied B3 bytes and modes")
    for name in("B1","B2","B3"):require(sha(raw(bootstrap,name+".image.bin"))==B3,"fixed B1/B2/B3 bytes")
    for index,(label,folder,names)in enumerate((
        ("hia-author","authored",("binary_parent_owner.hepta","binary_parent_owner_composition.json","binary_parent_owner.pseudo")),
        ("fixture-author","fixture-authored",("binary_parent_owner_fixture.S","binary_parent_owner_fixture_edits.json")))):
        record=decode(raw(images_root,label+".json"))
        require(record==images["reauthors"][index] and type(record["returncode"])is int and record["returncode"]==0
                and record["limit_seconds"]==30 and 0<=record["elapsed_ns"]<31_000_000_000,"actual author process completion")
        for stream in("stdout","stderr"):require(pin(images_root/(label+"."+stream))==record[stream],"actual source author streams")
        require(raw(images_root,label+".stderr")==b"","actual source author stderr")
        for name in names:
            destination="asm"if name.endswith(".S")else"native"
            require(raw(images_root,folder+"/"+name)==raw(source,destination+"/"+name),"entire reproduced authored source")
    bodies={}
    for name,path in SOURCES.items():
        row=images["members"][name];module=images_root/row["manifest"]
        meta_raw=raw(module.parent,module.name);meta=decode(meta_raw)
        require(row["source_path"]==path and row["source"]==pin(source/path)and row["identity"]==pin(module),"member source and manifest")
        text=raw(module.parent,meta["source"]);image=raw(module.parent,meta["image"])
        require(text==raw(source,path)and sha(text)==meta["source_sha256"]and sha(image)==meta["image_sha256"]
                and row["image"]==dict(bytes=len(image),sha256=sha(image)),"complete source/image binding")
        require(meta["compiler_commit"]==frozen["commit"]and meta["compiler_sha256"]==B3 and meta["buffer_profile"]=="history.v1"
                and meta["standalone"]is None and [meta[k]for k in("input_capacity","output_capacity","workspace_capacity")]
                ==[128<<20,128<<20,256<<20],"original compiler ABI and budgets")
        report=decode(raw(module.parent,"module.receipt.json"));request=decode(raw(module.parent,"module.request.json"))
        output=raw(module.parent,"module.output.bin")
        require(raw(module.parent,"module.input.bin")==text and report["status"]=="returned"and type(report["abi_status"])is int
                and report["abi_status"]==0 and report["core_u32"]==report["result_u64"]==report["produced_bytes"]==len(image)
                and output[:len(image)]==image and report["output_sha256"]==sha(output)and report["produced_sha256"]==sha(image)
                and report["input_sha256"]==sha(text)and report["input_bytes"]==len(text),"actual complete B3 compilation receipt")
        require(report["source_unchanged"]is True and report["forbidden_compiler_modules_loaded"]==[]
                and report["artifact_sha256"]==B3 and request["source_sha256"]==sha(text)
                and request["image_sha256"]==B3 and request["format"]=="flat-x86-64","actual native B3 invocation source custody")
        own=decode(raw(module.parent,"build.json"))
        require(own["compile_receipt"]==report and own["compiler_dependency"]==frozen,"complete compiler record")
        bodies[name]=image
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
    executable=raw(linked,"binary-parent-owner-callable.elf")
    require(executable==expected and record["executable"]==dict(bytes=len(executable),sha256=sha(executable)),"actual composed executable")
    for path,value in capture:require(path.read_bytes()==value,"raw build custody changed during DATA readback")
    require(source_evidence(source)==identity,"whole source changed during build readback")
    return dict(status="PASS_ACTUAL_BUILD_DATA_READBACK",source=identity,images=12,runtime_images=10,
                executable=record["executable"],compiler_sha256=B3,whole_runtime_replaced=False)
