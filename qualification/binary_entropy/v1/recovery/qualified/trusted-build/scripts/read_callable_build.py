#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Read actual compiler, linker, native bridge and HIA pack artifacts without executing."""
from pathlib import Path
import struct
from callable_common import B3,HEPTA,SCOPE,decode,encoded,owned,pin,require,sha,sources
from build_callable import MEMBERS,PATCHES,IMAGES,flattened,object_layout
from bootstrap_input import verify as verify_bootstrap

def verify(source,root):
    source,root=Path(source),Path(root);identity=sources(source)
    bundle=decode(owned(root,"BUILD.json").read_bytes())
    require(bundle["status"]=="FRESH_FIXED_BINARY_ENTROPY_CALLABLE_BUILD_PASS" and bundle["source"]==identity
        and bundle["actual_hia_compiles"]==3 and bundle["runtime_images"]==1 and bundle["scope"]==SCOPE
        and bundle["native_semantics_executed"] is False and bundle["runtime_python_required"] is False
        and bundle["runtime_libc_required"] is False,"actual fresh build identity differs")
    require(set(bundle["members"])=={name for name,_ in MEMBERS},"fixed three-image build set differs")
    boot=decode(owned(root,"build/bootstrap/bootstrap.json").read_bytes());dep=boot["dependency"]
    require(boot["generation_sha256"]==B3 and boot["qualification"]=="development_fixed_point"
        and dep["commit"]==HEPTA and dep["tree"]=="8d8b0fb8d015fb7edab302498bb9ed4c74ab6f49"
        and bundle["compiler"]==dep,"exact compiler dependency differs")
    actual={p.relative_to(root/"compiler-source").as_posix() for p in (root/"compiler-source").rglob("*") if p.is_file()}
    require(actual==set(dep["files"]),"compiler source file set differs")
    for name,digest in dep["files"].items():require(pin(owned(root,"compiler-source/"+name))["sha256"]==digest,"compiler byte differs")
    for name in ("B1","B2","B3"):require(pin(owned(root,"build/bootstrap/"+name+".image.bin"))["sha256"]==B3,"bootstrap generation differs")
    author=bundle["source_author_process"]
    require(author==decode(owned(root,"re-author.json").read_bytes())
        and author["returncode"]==0 and author["timed_out"]is False and author["limit_seconds"]==30
        and 0<=author["elapsed_ns"]<31_000_000_000,"actual source author process differs")
    for suffix in("stdout","stderr"):
        require(author["streams"][suffix]==pin(owned(root,"re-author."+suffix)),"source author stream differs")
    require(owned(root,"re-author.stderr").read_bytes()==b"","source author stderr differs")
    for name in("binary_entropy.hepta","binary_entropy_composition.json","binary_entropy.pseudo"):
        require(owned(root,"authored/"+name).read_bytes()==owned(source,"native/"+name).read_bytes(),
            "source author did not reproduce frozen native source")
    require(bundle["retained_actual_b3"]==verify_bootstrap(source,root,dep),"whole copied actual B3 custody")
    images={}
    for name,path in MEMBERS:
        row=bundle["members"][name];manifest=owned(root,row["manifest"]);meta=decode(manifest.read_bytes())
        require(row["source_path"]==path and row["source"]==pin(owned(source,path))
            and row["identity"]==pin(manifest),"member source/manifest differs")
        raw_source=owned(manifest.parent,meta["source"]).read_bytes();image=owned(manifest.parent,meta["image"]).read_bytes()
        require(raw_source==owned(source,path).read_bytes() and sha(raw_source)==meta["source_sha256"]
            and sha(image)==meta["image_sha256"] and row["image"]==pin(owned(manifest.parent,meta["image"])),"actual member bytes differ")
        require(meta["compiler_commit"]==HEPTA and meta["compiler_sha256"]==B3 and meta["buffer_profile"]=="history.v1"
            and meta["standalone"] is None and [meta[k] for k in ("input_capacity","output_capacity","workspace_capacity")]
            ==[128<<20,128<<20,256<<20],"module ABI differs")
        receipt=decode(owned(manifest.parent,"module.receipt.json").read_bytes())
        request=decode(owned(manifest.parent,"module.request.json").read_bytes())
        out=owned(manifest.parent,"module.output.bin").read_bytes()
        require(owned(manifest.parent,"module.input.bin").read_bytes()==raw_source,"actual compile input differs")
        require(receipt["status"]=="returned" and type(receipt["abi_status"]) is int and receipt["abi_status"]==0
            and receipt["core_u32"]==receipt["result_u64"]==receipt["produced_bytes"]==len(image)
            and out[:len(image)]==image and receipt["output_sha256"]==sha(out)
            and receipt["produced_sha256"]==sha(image) and receipt["input_sha256"]==sha(raw_source)
            and receipt["input_bytes"]==len(raw_source),"actual complete compile return differs")
        require(receipt["source_unchanged"] is True and receipt["forbidden_compiler_modules_loaded"]==[]
            and receipt["artifact_sha256"]==B3 and request["source_sha256"]==sha(raw_source)
            and request["image_sha256"]==B3 and request["format"]=="flat-x86-64","compile custody differs")
        record=decode(owned(manifest.parent,"build.json").read_bytes())
        require(record["compile_receipt"]==receipt and record["compiler_dependency"]==dep,"compile record differs")
        images[name]=image
    expected_artifacts={"combined.S","bridge.o","link.input.bin","link.output.bin","link.workspace.bin",
        "link.receipt.json","prefix.elf","pack.input.bin","pack.output.bin","pack.workspace.bin"}
    require(set(bundle["artifacts"])==expected_artifacts,"build artifact set differs")
    for name,row in bundle["artifacts"].items():require(pin(owned(root,name))==row,"full build artifact bytes differ")
    require(owned(root,"combined.S").read_text()==flattened(source),"fixed native bridge source differs")
    process=bundle["mechanical_processes"];require(len(process)==2,"mechanical process count differs")
    origin=Path(process[0]["argv"][3]).parent
    commands=(["as","--64","-o",str(origin/"bridge.o"),str(origin/"combined.S")],["readelf","-r",str(origin/"bridge.o")])
    for name,record,argv in zip(("assemble","relocations"),process,commands):
        require(record==decode(owned(root,name+".json").read_bytes()) and record["argv"]==argv
            and record["returncode"]==0 and record["timed_out"] is False and record["limit_seconds"]==30
            and 0<=record["elapsed_ns"]<31_000_000_000,"actual assembler process differs")
        for stream in ("stdout","stderr"):require(record["streams"][stream]==pin(owned(root,name+"."+stream)),"assembler stream differs")
        require(owned(root,name+".stderr").read_bytes()==b"","assembler stderr differs")
    require(b"There are no relocations" in owned(root,"relocations.stdout").read_bytes(),"unresolved relocation")
    obj=owned(root,"bridge.o").read_bytes();text,symbols=object_layout(obj)
    frame=b"HIALNK01"+struct.pack("<3Q",1,6,0)+b"_start"+struct.pack("<Q",len(obj))+obj
    require(owned(root,"link.input.bin").read_bytes()==frame,"complete actual linker input differs")
    receipt=decode(owned(root,"link.receipt.json").read_bytes());code=bundle["linked_return"]
    require(receipt==dict(actual_return=code,input=pin(root/"link.input.bin"),output=pin(root/"link.output.bin"),
        workspace=pin(root/"link.workspace.bin")),"link receipt/full workspace differs")
    raw=owned(root,"link.output.bin").read_bytes();prefix=owned(root,"prefix.elf").read_bytes()
    end=256+len(text)
    require(len(raw)==8<<20 and (root/"link.workspace.bin").stat().st_size==32<<20
        and code==(end+4095)&~4095 and prefix==raw[:code] and prefix[256:end]==text
        and prefix[end:]==bytes(code-end) and raw[code:]==bytes(len(raw)-code)
        and struct.unpack_from("<Q",prefix,24)[0]==4194304+232 and prefix[238]==0xe8
        and 243+struct.unpack_from("<i",prefix,239)[0]==256+symbols["_start"]
        and struct.unpack_from("<QQ",prefix,96)==(end,end)
        and struct.unpack_from("<QQQ",prefix,128)==(code,4194304+code,4194304+code),"actual linked ELF contract differs")
    ordered=[images[name] for name in IMAGES]
    patches=[(2,256+symbols[name],i) for name,i in PATCHES]
    for _,at,_ in patches:require(prefix[at-1:at+4]==b"\xe9\0\0\0\0","fixed call binding changed")
    frame=b"HIAIMG02"+struct.pack("<4Q",len(prefix),len(IMAGES),len(PATCHES),0)+prefix
    frame+=b"".join(struct.pack("<Q",len(im)) for im in ordered)+b"".join(struct.pack("<3Q",*p) for p in patches)+b"".join(ordered)
    require(owned(root,"pack.input.bin").read_bytes()==frame,"full fixed pack input differs")
    expected=bytearray(prefix);positions=[]
    for im in ordered:expected+=bytes(-len(expected)%16);positions.append(len(expected));expected+=im
    end=len(expected);expected+=bytes(-len(expected)%4096)
    for _,at,index in patches:struct.pack_into("<I",expected,at,positions[index]-at-4)
    struct.pack_into("<QQ",expected,96,end,end)
    struct.pack_into("<QQQ",expected,128,len(expected),4194304+len(expected),4194304+len(expected))
    require(bundle["patches"]==[list(p) for p in patches] and bundle["image_offsets"]==positions
        and bundle["image_order"]==list(IMAGES)
        and bundle["exports"]=={k:v for k,v in symbols.items() if k.startswith(("binary_entropy_","hia_process_orphans_"))},"fixed complete pack map differs")
    require(bundle["packer_return"]==32 and owned(root,"pack.output.bin").read_bytes()
        ==b"HIAIMR02"+struct.pack("<3Q",0,len(expected),0)+expected
        and owned(root,"pack.workspace.bin").stat().st_size==4096,"actual pack output/workspace differs")
    elf=owned(root,"binary-entropy-callable.elf")
    require(elf.read_bytes()==expected and pin(elf)==bundle["executable"] and elf.stat().st_mode&0o777==0o500,
        "actual executable or permissions differ")
    return dict(status="FRESH_BINARY_ENTROPY_CALLABLE_BUILD_READBACK_PASS",source=identity,executable=pin(elf),
        build=pin(root/"BUILD.json"),fresh_hia_compiles=3,runtime_images=1,actual_hia_link_and_pack=True,scope=SCOPE)
