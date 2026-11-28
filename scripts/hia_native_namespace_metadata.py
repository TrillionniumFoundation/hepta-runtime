#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Reproduce and build the HIA Rust metadata policy with a closed raw syscall boundary."""
from __future__ import annotations
import argparse,hashlib,json,shutil,struct,subprocess,sys,time
from pathlib import Path
sys.dont_write_bytecode=True
def sha(raw):return hashlib.sha256(raw).hexdigest()
def pin(path):
    raw=Path(path).read_bytes();return {"bytes":len(raw),"sha256":sha(raw)}
def require(value,message):
    if not value:raise ValueError(message)
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+"\n").encode()
def process(folder,name,args,timeout=60):
    started=time.monotonic()
    completed=subprocess.run([str(x) for x in args],cwd=folder,capture_output=True,timeout=timeout)
    (folder/(name+".stdout")).write_bytes(completed.stdout)
    (folder/(name+".stderr")).write_bytes(completed.stderr)
    row={"argv":[str(x) for x in args],"returncode":completed.returncode,"seconds":time.monotonic()-started,
         "stdout":pin(folder/(name+".stdout")),"stderr":pin(folder/(name+".stderr"))}
    (folder/(name+".json")).write_bytes(encoded(row))
    require(completed.returncode==0,name+" process failed")
    return row
def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("source","hepta","bootstrap","output"):p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args();root=a.source.resolve(strict=True);hepta=a.hepta.resolve(strict=True);out=a.output.absolute()
    require(not out.exists(),"fresh build output required");out.mkdir(parents=True)
    paths=("authoring/namespace_metadata/policy.pseudo","authoring/namespace_metadata/author.py",
        "authoring/namespace_metadata/reference/rust195-unix.rs",
        "authoring/namespace_metadata/reference/glibc-statx.c","authoring/namespace_metadata/reference/glibc-statx-generic.c",
        "authoring/namespace_metadata/reference/COPYING.glibc","native/namespace_metadata.hepta",
        "native/namespace_metadata_composition.json","asm/namespace_metadata.S",
        "scripts/hia_native_namespace_metadata.py","scripts/hia_native_build.py","scripts/hia_native_loader.py",
        "authoring/public_publication_v1/source_support.py",
        "native/runtime_mcp_catalog_ninth.hepta","native/runtime_mcp_catalog_ninth_composition.json")
    source_before={name:pin(root/name) for name in paths}
    author=process(out,"author",[sys.executable,"-I","-B",root/"authoring/namespace_metadata/author.py",
        "--source",root,"--hepta",hepta,"--output",out/"authored"])
    for name in ("namespace_metadata.hepta","namespace_metadata_composition.json"):
        require((out/"authored"/name).read_bytes()==(root/"native"/name).read_bytes(),"author reproduction differs")
    sys.path.insert(0,str(root/"scripts"))
    from hia_native_build import NativeBuild
    from hia_native_loader import NativeModule
    q=root/"qualification/multi_read_body/v1/codec_reserved_native_build"
    sys.path.insert(0,str(q/"scripts"))
    from build_callable import object_layout
    linker_source=q/"compiler/elf_static_linker.hepta"
    source_before[str(linker_source.relative_to(root))]=pin(linker_source)
    source_before[str((q/"scripts/build_callable.py").relative_to(root))]=pin(q/"scripts/build_callable.py")
    build=out/"build";build.mkdir()
    shutil.copytree(a.bootstrap.resolve(strict=True),build/"bootstrap")
    native=NativeBuild(hepta,build)
    require(sha(native.bootstrap().read_bytes())=="bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0",
        "qualified compiler image differs")
    members={}
    for name,path,profile in (("policy",root/"native/namespace_metadata.hepta","standard"),
                              ("linker",linker_source,"history.v1")):
        started=time.monotonic()
        manifest=native.compile("namespace-metadata-"+name,path,standalone=None,buffer_profile=profile)
        md=json.loads(manifest.read_bytes());image=manifest.parent/md["image"]
        members[name]={"source_path":str(path.relative_to(root)),"source":pin(path),"profile":profile,
            "manifest":str(manifest.relative_to(out)),"manifest_pin":pin(manifest),
            "image":str(image.relative_to(out)),"image_pin":pin(image),"seconds":time.monotonic()-started}
        print(json.dumps({"compiled":name,**members[name]["image_pin"]}),flush=True)
    work=out/"capability";work.mkdir()
    policy=out/members["policy"]["image"]
    boundary=(root/"asm/namespace_metadata.S").read_text()
    require(boundary.count('"namespace-metadata-policy.bin"')==1,"fixed image anchor differs")
    (work/"combined.S").write_text(boundary.replace('"namespace-metadata-policy.bin"',json.dumps(str(policy))))
    mechanical=[process(work,"assemble",["as","--64","-o",work/"bridge.o",work/"combined.S"]),
        process(work,"relocations",["readelf","-r",work/"bridge.o"]),
        process(work,"symbols",["nm","-n",work/"bridge.o"])]
    require(b"There are no relocations" in (work/"relocations.stdout").read_bytes(),"unresolved relocations")
    obj=(work/"bridge.o").read_bytes();text,symbols=object_layout(obj)
    require(symbols["_start"]==symbols["namespace_metadata_entry"]==0,"flat entry differs")
    policy_at=symbols["namespace_metadata_policy"]
    require(text[policy_at:policy_at+len(policy.read_bytes())]==policy.read_bytes(),"embedded HIA image differs")
    frame=b"HIALNK01"+struct.pack("<3Q",1,6,0)+b"_start"+struct.pack("<Q",len(obj))+obj
    (work/"link.input.bin").write_bytes(frame)
    with NativeModule(out/members["linker"]["manifest"],manifest_sha256=members["linker"]["manifest_pin"]["sha256"]) as module:
        code,raw,arena=module.invoke_raw(frame,output_capacity=8<<20,workspace_capacity=32<<20,output_fill=0,workspace_fill=0)
    (work/"link.output.bin").write_bytes(raw);(work/"link.workspace.bin").write_bytes(arena)
    (work/"link.result.json").write_bytes(encoded({"return":code,"output":pin(work/"link.output.bin"),"workspace":pin(work/"link.workspace.bin")}))
    end=256+len(text);aligned=(end+4095)&~4095
    require(code==aligned and raw[:4]==b"\x7fELF" and raw[256:end]==text and raw[end:]==bytes(len(raw)-end),
        "actual native HIA linked image differs")
    container=work/"namespace-metadata.elf";container.write_bytes(raw[:code])
    flat=work/"namespace-metadata.image.bin";flat.write_bytes(raw[256:code])
    native._recheck()
    require(source_before=={name:pin(root/name) for name in source_before},"source changed during build")
    result={"schema":"hepta.runtime.namespace-metadata-build.v1","status":"PASS",
        "source_files":source_before,"compiler":native.identity,"members":members,"author":author,
        "mechanical":mechanical,"symbols":{name:symbols[name] for name in
            ("namespace_metadata_entry","namespace_metadata_policy","namespace_metadata_end")},
        "container":{"path":str(container.relative_to(out)),**pin(container)},
        "flat_image":{"path":str(flat.relative_to(out)),**pin(flat),"entry_offset":0,"container_offset":256},
        "private_request_capture":True,"shared_cache_bytes":1,
        "request_magic":"HNSMQ001","response_magic":"HNSMR001",
        "terminal_scalar":32,"success_response_extent":176,"error_response_extent":32,
        "runtime_python_required":False,"runtime_libc_required":False,
        "actual_metadata_qualified":False,"whole_namespace_qualified":False,"whole_runtime_replaced":False}
    (out/"BUILD.json").write_bytes(encoded(result))
    print(json.dumps({"status":"PASS","flat_image":result["flat_image"]}),flush=True)
if __name__=="__main__":main()
