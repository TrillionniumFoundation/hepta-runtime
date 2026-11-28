#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Compile, link and pack the complete raw-declaration catalog capability."""
from __future__ import annotations
import argparse,hashlib,json,shutil,struct,sys,time
from pathlib import Path
sys.dont_write_bytecode=True
def sha(raw): return hashlib.sha256(raw).hexdigest()
def pin(path):
    raw=Path(path).read_bytes()
    return {"bytes":len(raw),"sha256":sha(raw)}
def require(value,message):
    if not value: raise ValueError(message)
def encoded(value): return (json.dumps(value,sort_keys=True,indent=2)+"\n").encode()
IMAGES=("owner","policy","value","sdk","retained")
PATCHES=tuple(("full_catalog_"+name+"_displacement",i) for i,name in enumerate(IMAGES))
def main():
    p=argparse.ArgumentParser(description=__doc__)
    for key in ("source","hepta","bootstrap","output"):
        p.add_argument("--"+key,required=True,type=Path)
    a=p.parse_args();root=a.source.resolve(strict=True);hepta=a.hepta.resolve(strict=True);out=a.output.absolute()
    require(not out.exists(),"fresh build output required");out.mkdir(parents=True)
    sys.path.insert(0,str(root/"scripts"))
    from hia_native_public_file_info_walk import process
    from hia_native_build import NativeBuild
    from hia_native_loader import NativeModule
    policy=root/"tests/hia_native/catalog_policy_ci/source"
    sys.path.insert(0,str(policy))
    import read_catalog
    policy_before=dict(read_catalog.source_check(policy)[0].files)
    q=root/"qualification/multi_read_body/v1/codec_reserved_native_build"
    sys.path.insert(0,str(q/"scripts"))
    from build_callable import object_layout
    paths=("authoring/full_catalog/pipeline.pseudo","authoring/full_catalog/author_pipeline.py",
        "native/full_catalog_pipeline.hepta","native/full_catalog_pipeline_composition.json",
        "asm/full_catalog_capability.S","scripts/hia_native_full_catalog.py",
        "native/runtime_mcp_catalog_ninth.hepta","native/runtime_mcp_catalog_ninth_composition.json",
        "scripts/hia_native_build.py","scripts/hia_native_loader.py","scripts/hia_native_public_file_info_walk.py")
    bindings={name:pin(root/name) for name in paths}
    author=process(out,"author",[sys.executable,"-I","-B",root/"authoring/full_catalog/author_pipeline.py",
        "--source",root,"--hepta",hepta,"--output",out/"authored"],60)
    for name in ("full_catalog_pipeline.hepta","full_catalog_pipeline_composition.json"):
        require((out/"authored"/name).read_bytes()==(root/"native"/name).read_bytes(),"author reproduction differs")
    composition=json.loads((root/"native/full_catalog_pipeline_composition.json").read_bytes())
    constants=composition["constants"]
    build=out/"build";build.mkdir()
    shutil.copytree(a.bootstrap.resolve(strict=True),build/"bootstrap")
    native=NativeBuild(hepta,build)
    require(sha(native.bootstrap().read_bytes())==read_catalog.GENERATION,"qualified compiler differs")
    members={}
    sources=(
        ("owner",root/"native/full_catalog_pipeline.hepta","serde-json.v1"),
        ("policy",policy/"native/catalog_policy.hepta","standard"),
        ("value",policy/"native/serde_json.hepta","serde-json.v1"),
        ("sdk",policy/"native/sdk_catalog.hepta","serde-json.v1"),
        ("retained",root/"native/runtime_mcp_catalog_ninth.hepta","standard"),
        ("linker",q/"compiler/elf_static_linker.hepta","history.v1"),
        ("packer",q/"native/runtime_mcp_image_packer.hepta","history.v1"))
    for name,path,profile in sources:
        started=time.monotonic()
        manifest=native.compile("full-catalog-"+name,path,standalone=None,buffer_profile=profile)
        md=json.loads(manifest.read_bytes())
        image=manifest.parent/md["image"]
        members[name]={"source_path":str(path.relative_to(root)),"source":pin(path),"profile":profile,
            "manifest":str(manifest.relative_to(out)),"manifest_pin":pin(manifest),
            "image":str(image.relative_to(out)),"image_pin":pin(image),"seconds":time.monotonic()-started}
        print(json.dumps({"compiled":name,**members[name]["image_pin"]}),flush=True)
    for name,source_pin in (("policy","catalog-policy"),("value","serde-json"),("sdk","sdk-catalog-wide")):
        require(members[name]["source"]["sha256"]==read_catalog.SOURCE_PINS[source_pin][1],"original policy pipeline source differs")
    images=[(out/members[name]["image"]).read_bytes() for name in IMAGES]
    require(pin(root/"native/runtime_mcp_catalog_ninth.hepta")==composition["retained_catalog"],"retained catalog changed")
    work=out/"capability";work.mkdir()
    declarations=policy/"catalog-input.json";require(pin(declarations)==composition["declaration"],"complete declarations changed")
    declaration_copy=work/"declarations.bin";declaration_copy.write_bytes(declarations.read_bytes())
    boundary=(root/"asm/full_catalog_capability.S").read_text()
    require(boundary.count('"__DECLARATIONS__"')==1,"fixed data boundary anchor differs")
    prefix="".join(".set FC_"+key+","+str(constants[key])+"\n" for key in
        ("FRAME","TOTAL","REQUEST","FRAME_CAP","REPLY","WORK","SDK_WORK","DECLARATION_BYTES"))
    (work/"combined.S").write_text(prefix+boundary.replace('"__DECLARATIONS__"',json.dumps(str(declaration_copy))))
    mechanical=[process(work,"assemble",["as","--64","-o",work/"bridge.o",work/"combined.S"]),
        process(work,"relocations",["readelf","-r",work/"bridge.o"])]
    require(b"There are no relocations" in (work/"relocations.stdout").read_bytes(),"unresolved relocations")
    obj=(work/"bridge.o").read_bytes();text,symbols=object_layout(obj)
    require(symbols["_start"]==0,"flat entry is not offset zero")
    frame=b"HIALNK01"+struct.pack("<3Q",1,6,0)+b"_start"+struct.pack("<Q",len(obj))+obj
    (work/"link.input.bin").write_bytes(frame)
    with NativeModule(out/members["linker"]["manifest"],manifest_sha256=members["linker"]["manifest_pin"]["sha256"]) as module:
        code,raw,arena=module.invoke_raw(frame,output_capacity=8<<20,workspace_capacity=32<<20,output_fill=0,workspace_fill=0)
    (work/"link.output.bin").write_bytes(raw);(work/"link.workspace.bin").write_bytes(arena)
    end=256+len(text);aligned=(end+4095)&~4095
    require(code==aligned and raw[:4]==b"\x7fELF" and raw[256:end]==text
        and raw[end:]==bytes(len(raw)-end),"actual linked prefix differs")
    elf_prefix=raw[:code];(work/"prefix.elf").write_bytes(elf_prefix)
    patches=[(2,256+symbols[name],index) for name,index in PATCHES]
    for _,at,_ in patches:
        require(elf_prefix[at-1:at+4]==b"\xe9\0\0\0\0","fixed image patch differs")
    frame=b"HIAIMG02"+struct.pack("<4Q",len(elf_prefix),len(images),len(patches),0)+elf_prefix
    frame+=b"".join(struct.pack("<Q",len(im)) for im in images)
    frame+=b"".join(struct.pack("<3Q",*x) for x in patches)+b"".join(images)
    (work/"pack.input.bin").write_bytes(frame)
    expected=bytearray(elf_prefix);positions=[]
    for im in images:
        expected+=bytes(-len(expected)%16);positions.append(len(expected));expected+=im
    end=len(expected);expected+=bytes(-len(expected)%4096)
    for _,at,index in patches:
        struct.pack_into("<I",expected,at,positions[index]-at-4)
    struct.pack_into("<QQ",expected,96,end,end)
    struct.pack_into("<QQQ",expected,128,len(expected),4194304+len(expected),4194304+len(expected))
    with NativeModule(out/members["packer"]["manifest"],manifest_sha256=members["packer"]["manifest_pin"]["sha256"]) as module:
        packed,raw,arena=module.invoke_raw(frame,output_capacity=32+len(expected),workspace_capacity=4096,output_fill=0xb3,workspace_fill=0xc7)
    (work/"pack.output.bin").write_bytes(raw);(work/"pack.workspace.bin").write_bytes(arena)
    require(packed==32 and raw==b"HIAIMR02"+struct.pack("<3Q",0,len(expected),0)+expected,"actual HIA pack differs")
    container=work/"full-catalog.elf";container.write_bytes(raw[32:])
    flat=work/"full-catalog.image.bin";flat.write_bytes(raw[32+256:])
    require(flat.read_bytes()==container.read_bytes()[256:],"complete flat image slice differs")
    source_before=bindings
    require(bindings=={name:pin(root/name) for name in paths},"source changed during build")
    require(policy_before==dict(read_catalog.source_check(policy)[0].files),"complete original policy closure changed during build")
    native._recheck()
    result={"schema":"hepta.runtime.full-catalog-capability-build.v1","status":"PASS",
        "source_files":source_before,"compiler":native.identity,"members":members,"author":author,
        "policy_source_closure":policy_before,"mechanical":mechanical,"patches":patches,
        "image_offsets":dict(zip(IMAGES,positions,strict=True)),"link_return":code,"pack_return":packed,
        "container":{"path":str(container.relative_to(out)),**pin(container)},
        "flat_image":{"path":str(flat.relative_to(out)),**pin(flat),"entry_offset":0,"container_offset":256},
        "declaration":{"source_path":str(declarations.relative_to(root)),**pin(declarations),"tools":136},
        "external_abi":"three separate buffers, HRMCD002 / HRCATR02 / HGRWS002",
        "runtime_images":list(IMAGES),"runtime_hia_images":5,"runtime_python_required":False,
        "runtime_libc_required":False,"precomputed_result_wire_used":False,"public_dispatch_qualified":False,
        "whole_runtime_replaced":False,"artifacts":{name:pin(work/name) for name in
            ("combined.S","bridge.o","declarations.bin","link.input.bin","link.output.bin","link.workspace.bin",
             "prefix.elf","pack.input.bin","pack.output.bin","pack.workspace.bin")}}
    (out/"BUILD.json").write_bytes(encoded(result))
    print(json.dumps({"status":"PASS","flat_image":result["flat_image"],"runtime_images":list(IMAGES)}),flush=True)
if __name__=="__main__":main()
