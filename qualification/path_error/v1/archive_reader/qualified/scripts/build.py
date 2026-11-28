#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Fresh pinned HIA compilation; no formatter application invocation."""
from pathlib import Path
import argparse,shutil,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from common import canonical,decode,require,source_evidence,pin,B3,HEPTA
def main():
    from hia_native_build import NativeBuild
    p=argparse.ArgumentParser();p.add_argument("--hepta",type=Path,required=True)
    p.add_argument("--capture",type=Path,required=True);a=p.parse_args();frozen=source_evidence(ROOT)
    builder=NativeBuild(a.hepta,a.capture/"build")
    manifest=builder.compile("path-error",ROOT/"native/path_error.hepta",standalone=None)
    require(builder.compiler_sha256==B3,"pinned compiler fixed point")
    meta=decode(manifest.read_bytes())
    dep=a.capture/"compiler-source";dep.mkdir()
    for name,digest in builder.identity["files"].items():
        target=dep/name;target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(a.hepta/name,target);target.chmod((a.hepta/name).stat().st_mode&0o777)
        require(pin(target)["sha256"]==digest,"compiler source copy")
    result=dict(schema="hepta.runtime.path-error.native-build.v1",
        compiler_commit=HEPTA,compiler_sha256=B3,member=dict(manifest=manifest.relative_to(a.capture).as_posix(),
            manifest_sha256=pin(manifest)["sha256"],source_sha256=meta["source_sha256"],image_sha256=meta["image_sha256"]),
        application_calls=0,source=frozen,compiler_cold_gate_repeated=False,
        compiler_modes={name:(dep/name).stat().st_mode&0o777 for name in builder.identity["files"]})
    (a.capture/"build/formatter.json").write_bytes(canonical(result))
    require(source_evidence(ROOT)==frozen,"source changed during build")
    print(canonical(result).decode(),end="")
if __name__=="__main__":main()
