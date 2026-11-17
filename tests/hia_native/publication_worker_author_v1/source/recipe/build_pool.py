#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Source authoring and fresh HIA build only, without application execution."""
from pathlib import Path
import argparse,hashlib,json,os,shutil,sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import canonical,pin,require,source_evidence
p=argparse.ArgumentParser()
for n in ("source","hepta","output"):p.add_argument("--"+n,type=Path,required=True)
a=p.parse_args();source=a.source.resolve();hepta=a.hepta.resolve();output=a.output.absolute()
require(os.environ.get("GITHUB_ACTIONS")=="true","HIA build allowed only in CI")
require(not output.exists(),"fresh output required");output.mkdir(parents=True)
identity=source_evidence(source)
for f in source.rglob("*.py"):compile(f.read_bytes(),str(f),"exec")
shutil.copytree(source,output/"recipe-source")
sys.path.insert(0,str(source/"authoring"));from author_worker import author
proof=author(source,hepta,output/"generated")
sys.path.insert(0,str(source/"scripts"));from hia_native_build import NativeBuild
builder=NativeBuild(hepta,output/"build")
manifest=builder.compile("publication-worker",output/"generated/publication_worker.hepta",standalone=None,buffer_profile="history.v1")
compiler=output/"compiler-source";compiler.mkdir()
for name in builder.identity["files"]:
    dst=compiler/name;dst.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(hepta/name,dst)
result={"status":"FRESH_HIA_BUILD_PASS","source":identity,"author":proof,"manifest":pin(manifest),
        "compiler_identity":builder.identity,"application_executed":False,"public_route_qualified":False,
        "full_sdk":False,"old_stack_removed":False}
require(source_evidence(source)==identity,"source changed")
(output/"BUILD.json").write_bytes(canonical(result));print(json.dumps(result,sort_keys=True))
