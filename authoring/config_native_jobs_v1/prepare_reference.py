#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""QA only: retain the original locked oracle and add exact current HostConfig domains."""
from __future__ import annotations
import argparse,difflib,hashlib,json,os,stat,subprocess,tarfile
from pathlib import Path,PurePosixPath
SHA=lambda b:hashlib.sha256(b).hexdigest()
BASE="abc9ecb95ee9538518ec3f36c47b881974107021"
def whole_struct(raw,name):
    anchor="#[derive(Debug, Clone, Deserialize, Serialize)]\npub struct "+name+" {"
    a=raw.index(anchor);b=raw.index("\n}\n",a)+3
    return raw[a:b]
def whole_validate(raw):
    a=raw.index("\tpub fn validate(&self) -> Result<()> {")
    b=raw.index("\n\t}\n",a)+4
    return raw[a:b]
def main():
    ap=argparse.ArgumentParser();ap.add_argument("--repo",required=True,type=Path);ap.add_argument("--output",required=True,type=Path);a=ap.parse_args()
    repo=a.repo.resolve(strict=True);out=a.output.resolve();out.mkdir(mode=0o700,parents=True,exist_ok=False)
    names=("src/mcp/runtime/config.rs","tests/hia_native/config_reference.tar.gz","tests/hia_native/config_reference_sources.json")
    inputs={n:(repo/n).read_bytes() for n in names}
    for n,raw in inputs.items():
        assert subprocess.check_output(["/usr/bin/git","-C",str(repo),"show",BASE+":"+n])==raw,n
    source=inputs[names[0]].decode();oldfiles={};modes={}
    with tarfile.open(repo/names[1],"r:gz") as archive:
        for member in archive.getmembers():
            path=PurePosixPath(member.name);assert not path.is_absolute() and ".." not in path.parts
            assert member.isfile(),member.name
            assert member.name not in oldfiles
            raw=archive.extractfile(member).read();assert len(raw)==member.size
            oldfiles[member.name]=raw;modes[member.name]=member.mode
            p=out/member.name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw);p.chmod(member.mode)
    oldhost=whole_struct(oldfiles["typed/oracle.rs"].decode(),"HostConfig")
    newhost=whole_struct(source,"HostConfig")
    native_field='\t/// Complete administrator-bound native job bundle; absence retains legacy configuration identity.\n\t#[serde(default, skip_serializing_if = "Option::is_none")]\n\tpub native_jobs: Option<NativeJobEntries>,\n'
    assert newhost.count(native_field)==1 and newhost.replace(native_field,"")==oldhost
    start=source.index("/// One administrator-selected installed role.")
    end=source.index("#[derive(Debug, Clone, Deserialize, Serialize)]\npub struct HostConfig {",start)
    native=source[start:end]
    assert native.count("pub struct NativeJobPin")==1 and native.count("pub struct NativeJobEntries")==1 and native.count("impl NativeJobEntries")==1
    typed=oldfiles["typed/oracle.rs"].decode()
    assert typed.count(oldhost)==1
    imports="mod current_native_jobs {\nuse serde::{Deserialize,Serialize};\nuse anyhow::{bail,Result};\nuse std::path::Path;\n"+native+"}\nuse current_native_jobs::{NativeJobPin,NativeJobEntries};\n"
    typed=typed.replace(oldhost,imports+newhost)
    anchor="            108=>typed::<mcp::hia_provider::HiaWorkerProfile>(raw),"
    assert typed.count(anchor)==1
    typed=typed.replace(anchor,anchor+"\n            109=>typed::<NativeJobEntries>(raw),\n            110=>typed::<NativeJobPin>(raw),")
    p=out/"current-typed/oracle.rs";p.parent.mkdir();p.write_text(typed)
    semantic_old=oldfiles["semantics/mcp/runtime/config.rs"].decode()
    assert whole_struct(semantic_old,"HostConfig")==oldhost
    semantic=semantic_old.replace(oldhost,native+newhost)
    prior_validate=whole_validate(semantic_old);current_validate=whole_validate(source)
    assert semantic.count(prior_validate)==1
    semantic=semantic.replace(prior_validate,current_validate)
    for n,raw in oldfiles.items():
        if not n.startswith("semantics/"):continue
        p=out/("current-"+n);p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(semantic.encode() if n=="semantics/mcp/runtime/config.rs" else raw);p.chmod(modes[n])
    cargo=oldfiles["Cargo.toml"]+b'\n[[bin]]\nname="hia-runtime-config-current-typed"\npath="current-typed/oracle.rs"\n[[bin]]\nname="hia-runtime-config-current-semantics"\npath="current-semantics/oracle.rs"\n'
    (out/"Cargo.toml").write_bytes(cargo)
    records={}
    for p in sorted(out.rglob("*")):
        if p.is_file():raw=p.read_bytes();records[str(p.relative_to(out))]={"bytes":len(raw),"sha256":SHA(raw),"mode":stat.S_IMODE(p.stat().st_mode)}
    for n,raw in oldfiles.items():
        if n!="Cargo.toml":assert (out/n).read_bytes()==raw,n
    assert (out/"Cargo.lock").read_bytes()==oldfiles["Cargo.lock"]
    current=(out/"current-semantics/mcp/runtime/config.rs").read_text()
    assert whole_validate(current)==current_validate and whole_struct(current,"HostConfig")==newhost and native in current
    for n,raw in inputs.items():assert (repo/n).read_bytes()==raw,n
    report={"schema":"hepta.runtime.current-native-jobs-rust-reference.v1","baseline_commit":BASE,
        "actual_inputs":{str(repo/n):{"bytes":len(b),"sha256":SHA(b)} for n,b in inputs.items()},
        "original_archive_members_unchanged_except_bin_declarations":True,"cargo_lock_unchanged":True,
        "native_job_source_bytes":len(native.encode()),"native_job_source_sha256":SHA(native.encode()),
        "host_complete_source_sha256":SHA(newhost.encode()),"validate_complete_source_sha256":SHA(current_validate.encode()),
        "validate_whole_file_diff":"\n".join(difflib.unified_diff(prior_validate.splitlines(),current_validate.splitlines())),
        "original_files":{n:{"bytes":len(b),"sha256":SHA(b)} for n,b in oldfiles.items()},
        "prepared_files":records,"compiled":False,"native_runtime_dependency":False}
    (out/"current-reference-inputs.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"status":"PREPARED","files":len(records),"lock_sha256":SHA(oldfiles["Cargo.lock"]),"native_job_source_sha256":SHA(native.encode()),"host_sha256":SHA(newhost.encode()),"validate_sha256":SHA(current_validate.encode())}))
if __name__=="__main__":main()
