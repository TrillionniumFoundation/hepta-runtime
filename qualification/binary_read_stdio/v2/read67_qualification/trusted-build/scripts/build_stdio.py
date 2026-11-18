#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Fresh HIA compilation and fixed one-shot stdio ELF packing; zero application calls."""
from pathlib import Path
import argparse,json,os,re,shutil,struct,subprocess,sys,time
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from callable_common import B3,HEPTA,SCOPE,decode,encoded,owned,pin,require,sha,sources,syntax
MEMBERS=(("body","native/binary_read_body.hepta"),("codec","native/binary_codec.hepta"),
    ("stat","native/stat_version.hepta"),("error","native/path_error.hepta"),
    ("linker","compiler/elf_static_linker.hepta"),("packer","native/runtime_mcp_image_packer.hepta"))
PATCHES=("binary_read_body_body_call_displacement","binary_read_body_codec_call_displacement",
    "binary_read_body_stat_call_displacement","binary_read_helper_error_call_displacement")
def flattened(source,observed):
    require(observed in(0,1),"fixed observer build mode")
    original=".equ HBRH_OBSERVE, "+str(observed)+"\n"+owned(source,"asm/binary_read_body_callable.S").read_text()+"\n"+owned(source,"asm/process_orphans.S").read_text()+"\n"+owned(source,"asm/binary_read_stdio.S").read_text()
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
def build_variant(source,output,build_root,members,observed):
    from hia_native_loader import NativeModule
    (output/"combined.S").write_text(flattened(source,observed))
    records=[process(output,"assemble",["as","--64","-o",output/"bridge.o",output/"combined.S"]),
        process(output,"relocations",["readelf","-r",output/"bridge.o"])]
    require(b"There are no relocations" in (output/"relocations.stdout").read_bytes(),"unexpected relocation report")
    obj=(output/"bridge.o").read_bytes();text,symbols=object_layout(obj)
    entry=b"_start";frame=b"HIALNK01"+struct.pack("<3Q",1,len(entry),0)+entry+struct.pack("<Q",len(obj))+obj
    (output/"link.input.bin").write_bytes(frame)
    link_manifest=build_root/members["linker"]["manifest"]
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
    for name in ("body","codec","stat","error"):
        m=build_root/members[name]["manifest"];meta=decode(m.read_bytes());images.append((m.parent/meta["image"]).read_bytes())
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
    pack_manifest=build_root/members["packer"]["manifest"];workcap=4096
    with NativeModule(pack_manifest,manifest_sha256=members["packer"]["identity"]["sha256"]) as module:
        pack_code,raw,work=module.invoke_raw(frame,output_capacity=32+len(expected),workspace_capacity=workcap,
            output_fill=0xb3,workspace_fill=0xc7)
    (output/"pack.output.bin").write_bytes(raw);(output/"pack.workspace.bin").write_bytes(work)
    require(pack_code==32 and raw==b"HIAIMR02"+struct.pack("<3Q",0,len(expected),0)+expected,
        "actual HIA image pack differs from fixed layout")
    elf=output/"binary-read-stdio.elf";elf.write_bytes(raw[32:]);elf.chmod(0o500)
    result=dict(status="FIXED_BINARY_READ_STDIO_VARIANT_BUILD_PASS",observed=bool(observed),
        linked_return=code,packer_return=pack_code,patches=patches,image_offsets=positions,
        image_order=["body","codec","stat","error"],mechanical_processes=records,
        exports={k:v for k,v in symbols.items()if k.startswith(("binary_read_body_","binary_read_helper_"))},
        artifacts={name:pin(output/name)for name in("combined.S","bridge.o","link.input.bin","link.output.bin",
            "link.workspace.bin","link.receipt.json","prefix.elf","pack.input.bin","pack.output.bin","pack.workspace.bin")},
        executable=pin(elf),application_calls=0)
    (output/"VARIANT.json").write_bytes(encoded(result));return result
def build(source,hepta,output):
    require(os.environ.get("GITHUB_ACTIONS")=="true","native build restricted to CI")
    require(not output.exists(),"fresh build required");output.mkdir(parents=True)
    identity=syntax(source);bindings=decode(owned(source,"SOURCE_BINDINGS.json").read_bytes())
    for name,expected in bindings["exact_unchanged_preimages"].items():
        require(pin(owned(source,name))==expected,"qualified native preimage changed")
    require(owned(source,"compiler/elf_static_linker.hepta").read_bytes()==
        (hepta/"examples/hia_bootstrap/elf_static_linker.hepta").read_bytes(),"exact HIA linker source")
    from hia_native_build import NativeBuild
    native=NativeBuild(hepta,output/"build");members={}
    from bootstrap_input import prepare as prepare_bootstrap
    retained_bootstrap=prepare_bootstrap(source,output,native.identity)
    require((output/"build/bootstrap/bootstrap.json").is_file(),"actual retained B3 receipt required")
    compiler=native.bootstrap()
    require(pin(compiler)["sha256"]==B3 and native.compiler_sha256==B3,"only copied and reverified B3")
    for name,path in MEMBERS:
        result=native.compile("binary-read-stdio-"+name,owned(source,path),standalone=None,buffer_profile="history.v1")
        meta=decode(result.read_bytes())
        members[name]=dict(source_path=path,manifest=result.relative_to(output).as_posix(),
            identity=pin(result),source=pin(owned(source,path)),image=pin(result.parent/meta["image"]))
    require(native.compiler_sha256==B3 and members["error"]["image"]==bindings["formatter_image"],
        "fixed compiler or qualified formatter image changed")
    compiler=output/"compiler-source";compiler.mkdir()
    for name in native.identity["files"]:
        path=compiler/name;path.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(hepta/name,path);path.chmod((hepta/name).stat().st_mode&0o777)
    variants={}
    for name,observed in(("production",0),("observed",1)):
        folder=output/name;folder.mkdir()
        variants[name]=build_variant(source,folder,output,members,observed)
    require(sources(source)==identity["source"],"source changed during build");native._recheck()
    result=dict(status="FRESH_FIXED_BINARY_READ_STDIO_BUILD_PASS",source=identity["source"],compiler=native.identity,
        compiler_modes={name:(compiler/name).stat().st_mode&0o777 for name in native.identity["files"]},
        members=members,variants=variants,actual_hia_compiles=6,runtime_images=4,executable_variants=2,
        scope=SCOPE,native_semantics_executed=False,runtime_python_required=False,runtime_libc_required=False,
        qualified_source_bindings=bindings,retained_actual_b3=retained_bootstrap)
    (output/"BUILD.json").write_bytes(encoded(result));print(json.dumps(result,sort_keys=True));return result
def main():
    p=argparse.ArgumentParser();p.add_argument("mode",choices=("check","build"))
    p.add_argument("--source",type=Path,required=True);p.add_argument("--hepta",type=Path);p.add_argument("--output",type=Path)
    a=p.parse_args();source=a.source.resolve(strict=True)
    if a.mode=="check":print(json.dumps(syntax(source),sort_keys=True))
    else:build(source,a.hepta.resolve(strict=True),a.output.absolute())
if __name__=="__main__":main()
