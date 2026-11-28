#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Build exact qualified native read dependencies for the public integration."""
from pathlib import Path
import argparse
import hashlib
import json
import shutil
import struct
import sys
import time
sys.dont_write_bytecode = True

def require(condition, message):
    if not condition:
        raise ValueError(message)

def pin(path):
    raw = path.read_bytes()
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2)+"\n").encode()

def elf_layout(raw):
    require(raw[:6] == b"\x7fELF\x02\x01", "ELF64 little endian required")
    sections = []
    at = struct.unpack_from("<Q", raw, 40)[0]
    count = struct.unpack_from("<H", raw, 60)[0]
    for index in range(count):
        sections.append(struct.unpack_from("<IIQQQQIIQQ", raw, at+index*64))
    symbols = {}
    relocations = []
    for section in sections:
        if section[1] == 2:
            table = sections[section[6]]
            names = raw[table[4]:table[4]+table[5]]
            for at in range(section[4], section[4]+section[5], 24):
                name, info, _, shndx, value, _ = struct.unpack_from("<IBBHQQ", raw, at)
                if shndx != 0:
                    label = names[name:names.index(0, name)].decode()
                    if label.startswith("ssh_direct_"):
                        symbols[label] = value
        elif section[1] in (4,9):
            stride = 24 if section[1] == 4 else 16
            for at in range(section[4], section[4]+section[5], stride):
                _, info = struct.unpack_from("<QQ", raw, at)
                relocations.append(info & 0xffffffff)
    segments = []
    at = struct.unpack_from("<Q", raw, 32)[0]
    count = struct.unpack_from("<H", raw, 56)[0]
    for index in range(count):
        kind, flags, offset, address, physical, filesz, memsz, align = struct.unpack_from("<II6Q",raw,at+index*56)
        require(kind not in (2,3), "dynamic ELF dependency")
        if kind == 1:
            require(address == physical and filesz <= memsz and offset+filesz <= len(raw),
                    "invalid fixed native LOAD segment")
            require(flags in (4,5,6), "read-only, read/execute or read/write segment required")
            segments.append(dict(offset=offset,address=address,file_bytes=filesz,memory_bytes=memsz,flags=flags,alignment=align))
    return symbols, segments, relocations

def build_ssh(root, hepta, output, bootstrap):
    from hia_native_ssh_direct_build import sources, tool
    from hia_native_build import NativeBuild
    binding = sources(root)
    output.mkdir(parents=True, exist_ok=False)
    shutil.copytree(bootstrap, output/"build/bootstrap")
    builder = NativeBuild(hepta, output/"build")
    layout = [("ssh_original_child","child"),("ssh_request_admission","admission"),
              ("ssh_shared_owner","core"),("ssh_capture_io","io"),("ssh_capture_future","future")]
    members = {}; images = {}
    for name,label in layout:
        manifest = builder.compile(name.replace("_","-"),root/("native/"+name+".hepta"),
                                   standalone=None,buffer_profile="history.v1")
        meta = json.loads(manifest.read_bytes()); image = manifest.parent/meta["image"]
        composition = json.loads((root/("native/"+name+"_composition.json")).read_bytes())
        require(pin(image) == composition["qualified_image"], "qualified SSH HIA image differs: "+name)
        members[name] = dict(manifest=str(manifest),manifest_identity=pin(manifest),
                            source=pin(root/("native/"+name+".hepta")), image=pin(image),entry=composition["entry"])
        images[name] = image
    native = output/"native"; native.mkdir()
    parts = ["core.S","api.S","spawn.S","ownership.S","io.S","owner.S","future.S"]
    text = "\n".join((root/("asm/ssh_direct/"+name)).read_text() for name in parts)+'\n.section .note.GNU-stack,"",@progbits\n'
    (native/"owner.S").write_text(text)
    embedded = [".intel_syntax noprefix",".section .text"]
    for name,label in layout:
        path = native/(name+".bin"); shutil.copyfile(images[name],path)
        embedded += [".balign 16",".global ssh_hia_"+label,"ssh_hia_"+label+":",'.incbin "'+path.name+'"']
    embedded += ['.section .note.GNU-stack,"",@progbits']
    (native/"images.S").write_text("\n".join(embedded)+"\n")
    layout_source=root/"asm/ssh_direct/qualified-relocatable.ld"
    layout_pin=pin(layout_source)
    shutil.copyfile(layout_source,native/"qualified-relocatable.ld")
    records = [
        tool(["as","--64","-o","owner.o","owner.S"],native,"assemble-owner"),
        tool(["as","--64","-o","images.o","images.S"],native,"assemble-images"),
        tool(["ld","-r","-T","qualified-relocatable.ld","-o","ssh-direct-owner.o","owner.o","images.o"],native,"link-relocatable"),
        tool(["ld","-nostdlib","-z","noexecstack","-e","ssh_direct_start","-o","ssh-direct-owner.elf","ssh-direct-owner.o"],native,"link-inspection"),
        tool(["readelf","--all","ssh-direct-owner.elf"],native,"readelf"),
    ]
    obj = native/"ssh-direct-owner.o"; image = native/"ssh-direct-owner.elf"
    require(pin(obj) == dict(bytes=565456,sha256="137d7d004e6dc0ffaaf9f29528d9d7ffb5879b4a4df2dd085fb0fdddbd324695"),
            "qualified complete SSH object differs")
    require(pin(image) == dict(bytes=571920,sha256="0fd61a340a62c398cf0f8f00c8d7cf1696fe45a33b69f9bbb46b76375c3cb341"),
            "qualified complete SSH ELF differs")
    exports, segments, final_relocations = elf_layout(image.read_bytes())
    _, _, relocations = elf_layout(obj.read_bytes())
    require(set(relocations) <= {2,4} and not final_relocations, "library is not position independent")
    base = min(row["address"] for row in segments)
    extent = max(row["address"]+row["memory_bytes"] for row in segments)-base
    require(base % 4096 == 0 and len(exports) >= 9, "native library export/layout admission")
    builder._recheck()
    require(sources(root) == binding, "SSH source changed during real build")
    require(pin(layout_source)==layout_pin==pin(native/"qualified-relocatable.ld"),
            "fixed original SSH object layout changed")
    result = dict(schema="hepta.runtime.public-read-ssh-dependency.v1",status="PASS",
                  source=binding,members=members,object=pin(obj),elf=str(image),elf_identity=pin(image),
                  build_tools=records,segments=segments,origin=base,memory_bytes=(extent+4095)&~4095,
                  relocatable_layout=layout_pin,original_complete_object_exact=True,
                  exports={name:value-base for name,value in sorted(exports.items())},
                  original_object_relocation_types=sorted(set(relocations)),
                  applications_executed=0,public_route_qualified=False)
    (output/"BUILD.json").write_bytes(encoded(result))
    return result

def build_read(root, hepta, output, bootstrap):
    import importlib.util
    from hia_native_build import NativeBuild
    historical = root/"qualification/binary_read_stdio/v1/build"
    sys.path.insert(0,str(historical/"scripts"))
    spec = importlib.util.spec_from_file_location("public_read_stdio_build",historical/"scripts/build_stdio.py")
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    output.mkdir(parents=True,exist_ok=False)
    shutil.copytree(bootstrap,output/"build/bootstrap")
    builder = NativeBuild(hepta,output/"build")
    layout = (("body",root/"native/binary_read_body.hepta"),("codec",root/"native/binary_codec.hepta"),
              ("stat",root/"native/stat_version.hepta"),("error",root/"native/binary_error.hepta"),
              ("linker",hepta/"examples/hia_bootstrap/elf_static_linker.hepta"),
              ("packer",root/"native/runtime_mcp_image_packer.hepta"))
    source_pins = {str(path):pin(path) for _,path in layout}
    for name in ("asm/binary_read_body_callable.S","asm/binary_read_stdio.S"):
        source_pins[str(root/name)] = pin(root/name)
    members = {}
    for name,path in layout:
        manifest = builder.compile("public-read-stdio-"+name,path,standalone=None,buffer_profile="history.v1")
        meta = json.loads(manifest.read_bytes())
        members[name] = dict(manifest=str(manifest.relative_to(output)),identity=pin(manifest),
                             source=pin(path),image=pin(manifest.parent/meta["image"]))
    baseline = output/"baseline"; baseline.mkdir()
    baseline_result = module.build_variant(historical,baseline,output,members,0)
    require(baseline_result["executable"] == dict(bytes=634880,sha256="3c29fcc0a6e9081079808cc52cb667f90ec2dc8d873371f289bb018e53cc6d83"),
            "exact qualified remote read predecessor differs")
    current_path=root/"native/public_binary_read_body.hepta"
    current_proof_path=root/"native/public_binary_read_body_composition.json"
    current_proof=json.loads(current_proof_path.read_bytes())
    source_pins[str(current_path)]=pin(current_path)
    source_pins[str(current_proof_path)]=pin(current_proof_path)
    require(current_proof["baseline"]==pin(root/"native/binary_read_body.hepta"),"current read predecessor differs")
    require(current_proof["source_bytes"]==current_path.stat().st_size and current_proof["source_sha256"]==pin(current_path)["sha256"],"current read body identity differs")
    original=(root/"native/binary_read_body.hepta").read_bytes()
    current=current_path.read_bytes();function=current_proof["changed_functions"]
    require(function==["f40"],"current read changes a nonliteral function")
    marker=b"fn f40("
    begin=original.index(marker);end=original.index(b"\nend",begin)+4
    current_begin=current.index(marker);current_end=current.index(b"\nend",current_begin)+4
    require(current[:current_begin]+original[begin:end]+current[current_end:]==original,"current read whole-body inverse differs")
    manifest=builder.compile("public-read-stdio-current-body",current_path,standalone=None,buffer_profile="history.v1")
    meta=json.loads(manifest.read_bytes())
    production_members=dict(members)
    production_members["body"]=dict(manifest=str(manifest.relative_to(output)),identity=pin(manifest),
        source=pin(current_path),image=pin(manifest.parent/meta["image"]))
    production = output/"production"; production.mkdir()
    production_result = module.build_variant(root,production,output,production_members,0)
    require(all(pin(Path(path)) == expected for path,expected in source_pins.items()),"read source changed")
    builder._recheck()
    result = dict(schema="hepta.runtime.public-read-stdio-dependency.v1",status="PASS",members=production_members,baseline_members=members,current_body=current_proof,
                  baseline=baseline_result,production=production_result,sources=source_pins,
                  elf=str(production/"binary-read-stdio.elf"),
                  applications_executed=0,public_route_qualified=False)
    (output/"BUILD.json").write_bytes(encoded(result))
    return result

def build_public_ssh(root,hepta,output,bootstrap):
    from hia_native_ssh_direct_build import tool
    baseline=build_ssh(root,hepta,output,bootstrap)
    (output/"BUILD.json").rename(output/"PREDECESSOR_BUILD.json")
    original=(output/"native/owner.S").read_text()
    old=("    mov rdi, QWORD PTR [r13+R_COMMAND]\n"
         "    add rdi, 64\n"
         "    mov rsi, QWORD PTR [r13+R_ARGV]\n"
         "    mov rdx, QWORD PTR [r13+R_ENVP]\n"
         "    mov eax, 59\n"
         "    syscall\n")
    new=old.replace("    mov eax, 59\n    syscall\n","    call ssh_public_execvp\n")
    require(original.count(old)==1,"original child execve boundary anchor differs")
    boundary=root/"asm/ssh_public_exec_path.S"; boundary_pin=pin(boundary)
    native=output/"public-native";native.mkdir()
    text=original.replace(old,new)+boundary.read_text()
    require(text[:-len(boundary.read_text())].replace(new,old)==original,
            "whole original native source inverse differs")
    (native/"owner.S").write_text(text)
    shutil.copyfile(output/"native/qualified-relocatable.ld",native/"qualified-relocatable.ld")
    shutil.copyfile(output/"native/images.S",native/"images.S")
    for path in (output/"native").glob("*.bin"):
        shutil.copyfile(path,native/path.name)
    records=[
        tool(["as","--64","-o","owner.o","owner.S"],native,"assemble-owner"),
        tool(["as","--64","-o","images.o","images.S"],native,"assemble-images"),
        tool(["ld","-r","-T","qualified-relocatable.ld","-o","ssh-direct-owner.o","owner.o","images.o"],native,"link-relocatable"),
        tool(["ld","-nostdlib","-z","noexecstack","-e","ssh_direct_start","-o","ssh-direct-owner.elf","ssh-direct-owner.o"],native,"link-inspection"),
        tool(["readelf","--all","ssh-direct-owner.elf"],native,"readelf"),
    ]
    obj=native/"ssh-direct-owner.o";elf=native/"ssh-direct-owner.elf"
    exports,segments,final_relocations=elf_layout(elf.read_bytes())
    _,_,relocations=elf_layout(obj.read_bytes())
    require(set(relocations)<={2,4} and not final_relocations,"public library is not position independent")
    base=min(row["address"] for row in segments)
    extent=max(row["address"]+row["memory_bytes"] for row in segments)-base
    require(pin(boundary)==boundary_pin,"exec path source changed")
    result=dict(schema="hepta.runtime.public-read-ssh-exec-path-dependency.v1",status="PASS",
        predecessor=baseline,object=pin(obj),elf=str(elf),elf_identity=pin(elf),
        build_tools=records,segments=segments,origin=base,memory_bytes=(extent+4095)&~4095,
        exports={name:value-base for name,value in sorted(exports.items())},
        original_object_relocation_types=sorted(set(relocations)),
        exec_path_source=boundary_pin,whole_original_native_source_inverse_exact=True,
        applications_executed=0,public_route_qualified=False)
    (output/"BUILD.json").write_bytes(encoded(result))
    return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source","hepta","output","bootstrap"):
        parser.add_argument("--"+name,type=Path,required=True)
    parser.add_argument("--kind",choices=("ssh","ssh-public","read"),default="ssh")
    args = parser.parse_args()
    root = args.source.resolve(strict=True)
    sys.path.insert(0,str(root/"scripts"))
    started = time.monotonic()
    build = {"ssh":build_ssh,"ssh-public":build_public_ssh,"read":build_read}[args.kind]
    result = build(root,args.hepta.resolve(strict=True),args.output.absolute(),args.bootstrap.resolve(strict=True))
    print(json.dumps(dict(status=result["status"],elf=result["elf"],exports=result.get("exports"),
                          segments=result.get("segments"),elapsed_seconds=time.monotonic()-started),sort_keys=True))
if __name__ == "__main__":
    main()
