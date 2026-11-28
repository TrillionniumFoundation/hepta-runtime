#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Real three-owner HIA compilation only; no direct SSH child is spawned."""
from pathlib import Path
import argparse, json, os, shutil, sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import canonical,pin,require,source_evidence
p=argparse.ArgumentParser()
for n in ("source","hepta","output"):p.add_argument("--"+n,type=Path,required=True)
a=p.parse_args();source=a.source.resolve();hepta=a.hepta.resolve();output=a.output.absolute()
require(os.environ.get("GITHUB_ACTIONS")=="true","HIA build restricted to CI")
require(not output.exists(),"fresh output required");output.mkdir(parents=True)
identity=source_evidence(source)
for path in source.rglob("*.py"):compile(path.read_bytes(),str(path),"exec")
shutil.copytree(source,output/"recipe-source")
sys.path.insert(0,str(source/"authoring"));from author import author
proof=author(source,hepta,output/"generated")
sys.path.insert(0,str(source/"scripts"));from hia_native_build import NativeBuild
builder=NativeBuild(hepta,output/"build");members={}
for name in proof["modules"]:
    path=builder.compile(name.replace("_","-"),output/("generated/"+name+".hepta"),standalone=None,buffer_profile="history.v1")
    manifest=json.loads(path.read_bytes())
    members[name]=dict(manifest=pin(path),manifest_path=path.relative_to(output).as_posix(),
        source=pin(path.parent/manifest["source"]),image=pin(path.parent/manifest["image"]))
compiler=output/"compiler-source";compiler.mkdir()
for name in builder.identity["files"]:
    destination=compiler/name;destination.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(hepta/name,destination)
result=dict(status="FRESH_SSH_RUNTIME_POLICY_BUILD_PASS",source=identity,author=proof,
    members=members,compiler_identity=builder.identity,applications_executed=0,
    independent_native_actor=False,public_ssh_qualified=False,full_sdk=False)
require(source_evidence(source)==identity,"source changed during build")
(output/"BUILD.json").write_bytes(canonical(result));print(json.dumps(result,sort_keys=True))
