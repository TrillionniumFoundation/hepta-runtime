#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Compile exact remote request and bootstrap HIA sources; execute zero apps."""
from pathlib import Path
import argparse,hashlib,json,os,sys
sys.dont_write_bytecode=True
def pin(p):
    p=Path(p)
    with p.open("rb")as f:return dict(bytes=p.stat().st_size,sha256=hashlib.file_digest(f,"sha256").hexdigest())
def main():
    p=argparse.ArgumentParser()
    for n in("source","hepta","output"):p.add_argument("--"+n,type=Path,required=True)
    a=p.parse_args();root=a.source.resolve(strict=True);out=a.output.absolute()
    assert os.environ.get("GITHUB_ACTIONS")=="true"and not out.exists()
    sys.path.insert(0,str(root/"recipe"));from common import source_evidence,canonical
    binding=source_evidence(root);out.mkdir(parents=True)
    sys.path.insert(0,str(root/"scripts"));from hia_native_build import NativeBuild
    builder=NativeBuild(a.hepta.resolve(strict=True),out/"build")
    members={}
    for name in("binary_remote_fields","ssh_native_bootstrap"):
        src=root/("native/"+name+".hepta");comp=root/("native/"+name+"_composition.json");c=json.loads(comp.read_bytes())
        assert pin(src)==dict(bytes=c["source_bytes"],sha256=c["source_sha256"])and c["entry"]=="f0"
        manifest=builder.compile(name.replace("_","-"),src,standalone=None,buffer_profile="history.v1")
        meta=json.loads(manifest.read_bytes());image=manifest.parent/meta["image"]
        members[name]=dict(source=pin(src),composition=pin(comp),image=pin(image),manifest=pin(manifest),
            manifest_path=manifest.relative_to(out).as_posix(),image_path=image.relative_to(out).as_posix(),entry="f0",
            functions=c["functions"],instructions=c["instructions"],blocks=c["blocks"])
    assert source_evidence(root)==binding
    result=dict(status="REMOTE_HELPER_FIELDS_AND_BOOTSTRAP_NATIVE_BUILD_PASS",source=binding,members=members,
        applications_executed=0,original_calls=0,public_route=False,json_items_pending=True,remote_helper_pending=True)
    (out/"BUILD.json").write_bytes(canonical(result));print(canonical(result).decode(),end="")
if __name__=="__main__":main()
