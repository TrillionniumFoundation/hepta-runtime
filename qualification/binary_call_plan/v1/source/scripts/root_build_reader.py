#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Complete byte-only original/native root proof. Never load a native image."""
from __future__ import annotations
from pathlib import Path
import gzip
import hashlib
import re
import struct
from common import B3,HEPTA,SCOPE,canonical,decode,owned,pin,require,sha,source_evidence
PACK=lambda *v:struct.pack("<"+"Q"*len(v),*v)
word=lambda raw,at:struct.unpack_from("<Q",raw,at)[0]
GROW=0xffffffd0
INVALID=0xffffffff
SHORT=0xfffffffe
def original_location(output,path):
    origin=decode(owned(output,"ORIGIN.json").read_bytes())
    p=Path(path);at=Path(origin["output"])
    require(p.is_relative_to(at),"retained process path escaped actual output")
    return owned(output,p.relative_to(at).as_posix())
def build_evidence(source,output):
    built=decode(owned(output,"build/result.json").read_bytes())
    require(built["schema"]=="hepta.runtime.config-span-build.v1"and built["status"]=="PASS"
        and built["installed_config_startup"]is True and len(built["members"])==19,"actual installed build missing")
    require(built["compiler_commit"]==HEPTA and built["compiler_sha256"]==B3,"actual compiler differs")
    bootstrap=decode(owned(output,"build/build/bootstrap/bootstrap.json").read_bytes())
    dep=bootstrap["dependency"]
    require(dep["commit"]==HEPTA and dep["tree"]=="8d8b0fb8d015fb7edab302498bb9ed4c74ab6f49"
        and len(dep["files"])==1080 and bootstrap["generation_sha256"]==B3
        and bootstrap["qualification"]=="development_fixed_point","complete compiler closure differs")
    for path,digest in dep["files"].items():
        require(pin(owned(output,"compiler-source/"+path))["sha256"]==digest,"complete compiler source changed")
    for generation in("B1","B2","B3"):
        require(pin(owned(output,"build/build/bootstrap/"+generation+".image.bin"))==dict(bytes=673413,sha256=B3),"actual generation differs")
    source_profile=decode(owned(source,"native/config_span_sources.json").read_bytes())
    require(source_profile==built["source_binding"],"actual build input profile changed")
    for path,want in source_profile["sources"].items():require(pin(owned(source,path))==want,"native closure source changed")
    origin=decode(owned(output,"ORIGIN.json").read_bytes())
    rows=[]
    for row in built["members"]:
        path=original_location(output,row["manifest"])
        require(pin(path)["sha256"]==row["manifest_sha256"],"native manifest changed")
        metadata=decode(path.read_bytes())
        native_source=original_location(output,row["source"])
        require(pin(native_source)["sha256"]==metadata["source_sha256"]==row["source_sha256"],"actual native source changed")
        require(metadata["image_sha256"]==row["image_sha256"]and metadata["compiler_commit"]==HEPTA
            and metadata["compiler_sha256"]==B3 and metadata["standalone"]is None
            and metadata["buffer_profile"]=="history.v1","actual member image/ABI changed")
        rows.append((path,metadata))
    link=built["link"];path=original_location(output,link["manifest"])
    require(pin(path)["sha256"]==link["manifest_sha256"],"actual native linker manifest changed")
    metadata=decode(path.read_bytes())
    require(metadata["source_sha256"]==pin(owned(output,"compiler-source/examples/hia_bootstrap/elf_static_linker.hepta"))["sha256"]
        and "buffer_profile"not in metadata and metadata["standalone"]is None
        and [metadata[k]for k in("input_capacity","output_capacity","workspace_capacity")]==[8<<20,8<<20,32<<20],
        "native linker source/ABI changed")
    rows.append((path,metadata))
    for path,metadata in rows:
        module_source=owned(path.parent,metadata["source"]).read_bytes()
        image=owned(path.parent,metadata["image"]).read_bytes()
        require(sha(module_source)==metadata["source_sha256"]and sha(image)==metadata["image_sha256"],"complete native bytes differ")
        request=decode(owned(path.parent,"module.request.json").read_bytes())
        receipt=decode(owned(path.parent,"module.receipt.json").read_bytes())
        raw_output=owned(path.parent,"module.output.bin").read_bytes()
        require(owned(path.parent,"module.input.bin").read_bytes()==module_source,"compiled input source differs")
        require(receipt["status"]=="returned"and receipt["abi_status"]==0
            and receipt["core_u32"]==receipt["result_u64"]==receipt["produced_bytes"]==len(image)
            and image==raw_output[:len(image)],"actual complete native compile output differs")
        require(receipt["source_unchanged"]is True and receipt["forbidden_compiler_modules_loaded"]==[]
            and receipt["artifact_sha256"]==B3 and receipt["input_sha256"]==sha(module_source)
            and receipt["output_sha256"]==sha(raw_output)and receipt["produced_sha256"]==sha(image),"native compile custody differs")
        require(request["source_sha256"]==sha(module_source)and request["image_sha256"]==B3
            and request["format"]=="flat-x86-64","native compile request differs")
        build=decode(owned(path.parent,"build.json").read_bytes())
        require(build["compile_receipt"]==receipt and build["compiler_dependency"]==dep,"member build closure differs")
    binary=original_location(output,built["binary"])
    require(pin(binary)["sha256"]==built["binary_sha256"]==link["output_sha256"]
        and pin(binary)["bytes"]==link["output_bytes"],"actual ELF changed")
    headers=owned(output,"build/readelf.stdout").read_bytes()
    require(b"INTERP"not in headers and b"RWE"not in headers and b"GNU_STACK"in headers,"ELF memory permissions differ")
    frame=owned(output,"build/link.input.bin").read_bytes();obj=owned(output,"build/bridge.o").read_bytes()
    require(frame==b"HIALNK01"+PACK(1,6,0)+b"_start"+PACK(len(obj))+obj
        and sha(frame)==link["input_sha256"]and len(frame)==link["input_bytes"],"actual native link input changed")
    return dict(images=19,linker_images=1,compiler_source_files=1080,binary=pin(binary))
