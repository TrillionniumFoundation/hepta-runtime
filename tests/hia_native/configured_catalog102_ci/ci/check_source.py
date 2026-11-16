"""Pure source admission; no compiler, HIA image or Rust process is executed."""
from pathlib import Path
import argparse,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import catalog_ci_support as c
import read_all

def check(package):
    manifest=c.source_check(package);count=0
    for name in manifest["files"]:
        if name.endswith(".py"):
            compile(c.regular(package/name),str(package/name),"exec",dont_inherit=True);count+=1
    read_all.prepare(package)
    for name in ("public_reference.rs","configured_projection.rs"):
        raw=c.regular(package/"ci"/name)
        c.need(raw.startswith(b"// Copyright 2026 Muvon Un Limited\n//\n// Licensed under the Apache License, Version 2.0"),
            "new Rust source license")
    c.need(not (package/"ci/common.py").exists(),"no collision with unchanged retained common module")
    return {"status":"CONFIGURED_CATALOG_COMPLETE_SOURCE_ADMISSION_PASS","files":len(manifest["files"]),
        "python_sources_compiled":count,"retained_helpers_preloaded":True,"native_executions":0,
        "rust_executions":0,"process_launches":0,"package":c.pin(c.regular(package/"PACKAGE.json"))}

if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--package",type=Path,default=HERE.parent);a=p.parse_args()
    print(c.encoded(check(a.package.resolve(strict=True))).decode())
