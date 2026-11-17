#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Read complete fresh original build custody; never execute the executable."""
from pathlib import Path
import hashlib,importlib.util,io,json,stat,tarfile,tomllib
from common import decode,pin,require,sha
from dependency import declaration

def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

def prepare(dependency):
    root=Path(dependency)/"extracted"
    verifier=module("publisher_async_original_verifier",root/"recipe-source/recipe/verify_reference.py")
    verifier.verify(root/"recipe-source/reference")
    return verifier

def verify(dependency,prepared):
    dependency=Path(dependency)
    d=declaration()
    require(pin(dependency/"reference.zip")==d["zip"],"original uploaded ZIP bytes")
    require(pin(dependency/"outer/evidence.tar.gz")==d["tar"],"original complete TAR bytes")
    index=decode((dependency/"outer/FILES.json").read_bytes())
    root=dependency/"extracted"
    expected={r["path"]:r for r in index["files"]}
    actual={p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}
    require(len(expected)==len(index["files"])==d["files"] and actual==set(expected),"reference file set")
    for name,row in expected.items():
        p=root/name;info=p.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_mode&0o777==row["mode"],"reference file mode/type")
        require(pin(p)=={k:row[k] for k in ("bytes","sha256")},"reference complete bytes: "+name)
    source=root/d["source_relative"];build=root/d["build_relative"]
    require(pin(source/"SOURCE_MANIFEST.json")=={k:d["source_manifest"][k] for k in ("bytes","sha256")},"compiled source package pin")
    manifest=decode((source/"SOURCE_MANIFEST.json").read_bytes())
    require({p.relative_to(source).as_posix() for p in source.rglob("*") if p.is_file()}
        =={r["path"] for r in manifest["files"]}|{"SOURCE_MANIFEST.json"},"compiled source package set")
    for row in manifest["files"]:
        raw=(source/row["path"]).read_bytes()
        require(dict(bytes=len(raw),sha256=sha(raw))=={k:row[k] for k in ("bytes","sha256")},"compiled source member")
        require(hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()==row["git_blob"],"compiled source Git object")
    proof=prepared.verify(source/"reference")
    result=decode((build/"BUILD.json").read_bytes())
    require(result["status"]=="FRESH_CURRENT_PUBLISHER_ASYNC_REFERENCE_BUILD_PASS","fresh build status")
    require(result["source_proof"]==proof and result["original_spans"]==120,"original source-span proof")
    require({k:result[k] for k in ("bytes","sha256")}==d["binary"]
        and pin(root/d["binary_relative"])==d["binary"],"actual original ELF")
    closure=decode((build/"source-closure.json").read_bytes())
    actual_source={p.relative_to(source/"reference").as_posix():pin(p)
        for p in (source/"reference").rglob("*") if p.is_file()}
    require(actual_source==closure and len(closure)==47,"actual compiler input closure")
    processes=decode((build/"processes.json").read_bytes())
    require([r["name"] for r in processes]==["rustc-version","cargo-version","cargo-fetch","cargo-metadata","cargo-build"],"complete original build process set")
    for row in processes:
        require(row["exit_code"]==0 and not row["timed_out"] and row["timeout_seconds"]==180,"fresh build process terminal")
        for stream in ("stdout","stderr"):
            require(pin(build/(row["name"]+"."+stream))=={k:row[stream][k] for k in ("bytes","sha256")},"complete build process stream")
    require((build/"rustc-version.stdout").read_bytes()==b"rustc 1.95.0 (59807616e 2026-04-14)\n","actual Rust toolchain")
    target={(p["name"],p["version"]):p for p in tomllib.loads((source/"reference/target/Cargo.lock").read_text())["package"] if "source" in p}
    registry=decode((build/"registry-sources.json").read_bytes())
    require(len(registry)==d["registry_crates"]==86,"complete current registry closure")
    total=0;archives=set();source_files=set()
    for crate in registry:
        name=crate["name"]+"-"+crate["version"]
        wanted=target[(crate["name"],crate["version"])]
        archive=build/"registry-archives"/(name+".crate")
        require(pin(archive)["sha256"]==wanted["checksum"]==crate["checksum"],"exact target crate checksum")
        archives.add(archive.name);seen=set()
        with tarfile.open(archive,"r:gz") as stream:
            for member in stream:
                parts=Path(member.name).parts
                require(parts[0]==name and ".." not in parts,"crate source path")
                if member.isdir():continue
                require(member.isfile(),"crate member type")
                relative=Path(*parts[1:]).as_posix()
                require(relative not in seen and relative in crate["files"],"crate exact source set")
                seen.add(relative)
                raw=stream.extractfile(member).read()
                path=build/"registry-source"/name/relative
                require(path.read_bytes()==raw,"retained registry source differs from target archive")
                require(dict(bytes=len(raw),sha256=sha(raw))==crate["files"][relative],"registry complete member bytes")
                source_files.add(path.relative_to(build/"registry-source").as_posix())
        require(seen==set(crate["files"]),"crate source omitted")
        total+=len(seen)
    require(total==d["registry_files"]==4401,"complete registry file count")
    require({p.name for p in (build/"registry-archives").iterdir()}==archives,"registry archive set")
    require({p.relative_to(build/"registry-source").as_posix() for p in (build/"registry-source").rglob("*") if p.is_file()}==source_files,"registry source set")
    return dict(status="FRESH_ORIGINAL_REFERENCE_COMPLETE_CUSTODY_PASS",files=len(expected),
        logical_bytes=sum(r["bytes"] for r in expected.values()),original_spans=120,registry_crates=len(registry),
        registry_files=total,binary=d["binary"],native_executed=False,rust_executed=False)
