#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Execute only the immutable qualified native worker; original Rust is retained, never replayed."""
from pathlib import Path
import argparse,ast,json,os,subprocess,sys,time
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(HERE/"recipe"))
from common import canonical,decode,pin,require,source_evidence
import dependency,read_native,controls,readonly
def check_source():
    result=source_evidence(HERE)
    for p in HERE.rglob("*"):
        if p.is_file() and p.suffix in (".py",".pseudo"):compile(p.read_bytes(),str(p),"exec")
    require((HERE/"recipe/retained_process.py").read_bytes()==(HERE/"retained/observer_process.py.txt").read_bytes(),
        "retained complete owned-process loops")
    actual=ast.parse((HERE/"recipe/process.py").read_text())
    c=next(x for x in actual.body if isinstance(x,ast.ClassDef))
    require([x.name for x in c.body if isinstance(x,ast.FunctionDef)]==["__init__","frame","finish"],
        "all pipe I/O/deadline loops remain actual retained methods")
    proof=decode((HERE/"PROVENANCE.json").read_bytes())
    for row in proof["retained"]:
        require(pin(HERE/row["path"])=={k:row[k] for k in ("bytes","sha256")},"whole retained source byte identity")
    return result
def read(root):
    root=Path(root);identity=check_source()
    require(decode((root/"SOURCE.json").read_bytes())==identity,"complete current qualification source")
    dep=dependency.read(root/"dependency");controls.receipt(root/"DEPENDENCY_READ.json",dep)
    native=read_native.verify(root/"native",dependency.declaration()["binary"])
    controls.receipt(root/"NATIVE_READ.json",native)
    physical=controls.read(HERE,root/"native",root/"controls")
    rows=native["rows"];require(len(rows)==24,"complete native lifecycle input set")
    for name in read_native.DIRECT+("borrow_lifetime","close_queued","fifo_growth","invalid_lifecycle"):
        pair=[r for r in rows if r["name"]==name];require(len(pair)==2,"one complete observer pair")
        require(pair[0]["files"]==pair[1]["files"] and pair[0]["jobs"]==pair[1]["jobs"],
            "observer-off complete file effect equality")
    expected=dict(status="PRIVATE_NATIVE_PUBLICATION_WORKER_LIFECYCLE_PASS",cases=24,observer_on=12,observer_off=12,
        actual_original_direct_projections=16,physical_mutations=4,relocations=2,
        original_rust_replayed=False,public_async_qualified=False,full_sdk=False,production_installed=False)
    require(decode((root/"RESULT.json").read_bytes())==expected,"exact qualification scope")
    require(set(p.name for p in root.iterdir())=={"SOURCE.json","dependency","DEPENDENCY_READ.json","native",
        "capture.stdout","capture.stderr","NATIVE_READ.json","controls","RESULT.json"},"full source/build/capture evidence closure")
    require((root/"capture.stderr").read_bytes()==b"","actual native capture completed without diagnostics")
    return dict(status="COMPLETE_PRIVATE_NATIVE_PUBLICATION_WORKER_READ_PASS",source=identity,dependency=dep,
        native=native,controls=physical,original_rust_replayed=False,public_async_qualified=False,full_sdk=False)
def execute(output):
    require(os.environ.get("GITHUB_ACTIONS")=="true","actual application execution only in frozen CI")
    output=Path(output);require(not output.exists(),"fresh actual capture");output.mkdir(parents=True)
    identity=check_source();(output/"SOURCE.json").write_bytes(canonical(identity))
    dependency.restore(output/"dependency")
    proof=readonly.guarded(lambda:dependency.read(output/"dependency"),roots=(HERE,output/"dependency"))
    (output/"DEPENDENCY_READ.json").write_bytes(canonical(proof))
    binary=output/"dependency/extracted"/dependency.declaration()["binary_relative"]
    with (output/"capture.stdout").open("xb") as out,(output/"capture.stderr").open("xb") as err:
        # The fixed inner process manager has 60/180 limits and actual child cleanup.
        # No incorrect outer killpg timeout is introduced around its setsid children.
        p=subprocess.run([sys.executable,"-I","-S","-B",str(HERE/"recipe/capture.py"),
            "--binary",str(binary),"--output",str(output/"native")],stdout=out,stderr=err)
    require(p.returncode==0,"actual native worker lifecycle capture failed; complete files retained")
    started=time.monotonic()
    proof=readonly.guarded(lambda:read_native.verify(output/"native",dependency.declaration()["binary"]),roots=(HERE,output/"native"))
    require(time.monotonic()-started<180,"complete native read unchanged 180-second bound")
    (output/"NATIVE_READ.json").write_bytes(canonical(proof))
    controls.create(HERE,output/"native",output/"controls")
    result=dict(status="PRIVATE_NATIVE_PUBLICATION_WORKER_LIFECYCLE_PASS",cases=24,observer_on=12,observer_off=12,
        actual_original_direct_projections=16,physical_mutations=4,relocations=2,
        original_rust_replayed=False,public_async_qualified=False,full_sdk=False,production_installed=False)
    (output/"RESULT.json").write_bytes(canonical(result))
    started=time.monotonic();proof=readonly.guarded(lambda:read(output),roots=(HERE,output))
    require(time.monotonic()-started<180,"complete whole evidence reader 180 seconds")
    Path(str(output)+"-readonly.json").write_bytes(canonical(proof))
    return dict(status=proof["evidence"]["status"],cases=24,entries=proof["entries"],guards=len(proof["probes"]),
        private_native_application_executed=True,public_async_qualified=False,full_sdk=False)
def main():
    p=argparse.ArgumentParser();p.add_argument("mode",choices=("source","capture","read"))
    p.add_argument("--output",type=Path);p.add_argument("--capture",type=Path);a=p.parse_args()
    if a.mode=="source":value=check_source()
    elif a.mode=="capture":value=execute(a.output.absolute())
    else:
        require(a.output is not None and not a.output.exists(),"fresh pure read receipt")
        started=time.monotonic();proof=readonly.guarded(lambda:read(a.capture),roots=(HERE,a.capture))
        require(time.monotonic()-started<180,"whole retained read180")
        a.output.write_bytes(canonical(proof));value=dict(status=proof["evidence"]["status"],entries=proof["entries"],guards=len(proof["probes"]))
    print(json.dumps(value,sort_keys=True))
if __name__=="__main__":main()
