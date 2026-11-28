#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Frozen build of four runtime HIA images and its wholly passive evidence reader."""
from pathlib import Path
import argparse,ast,json,os,sys,time
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(HERE/"scripts"));sys.path.insert(0,str(HERE/"recipe"))
from common import canonical,decode,pin,require,source_evidence
import build_worker,read_worker_build,build_controls,readonly
def check_source():
    result=source_evidence(HERE)
    for path in HERE.rglob("*"):
        if path.is_file() and path.suffix in (".py",".pseudo"):compile(path.read_bytes(),str(path),"exec")
    proof=decode((HERE/"PROVENANCE.json").read_bytes())
    for row in proof["retained"]:
        require(pin(HERE/row["path"])=={k:row[k] for k in ("bytes","sha256")},"retained complete source bytes")
    old=(HERE/"retained/text_publication_fixture.S.txt").read_text()
    fragment=old[old.index(".Lpf_read_exact:"):old.index("/* Immutable observer binding:")]
    require((HERE/"asm/publication_worker_fixture.S").read_text().endswith(fragment),"retained exact binary I/O functions")
    original=ast.parse((HERE/"retained/build_callable.py.txt").read_text())
    current=ast.parse((HERE/"scripts/build_worker.py").read_text())
    for name in ("object_layout","process"):
        a=next(x for x in original.body if isinstance(x,ast.FunctionDef) and x.name==name)
        b=next(x for x in current.body if isinstance(x,ast.FunctionDef) and x.name==name)
        require(ast.dump(a,include_attributes=False)==ast.dump(b,include_attributes=False),"retained fixed ELF/process AST")
    return result
def read(root):
    root=Path(root);identity=check_source()
    require(decode((root/"SOURCE.json").read_bytes())==identity,"source preflight")
    prior=decode((HERE/"retained/worker-author-AUTHOR.json").read_bytes())
    require(decode((root/"generated/AUTHOR.json").read_bytes())==prior
        and (root/"generated/publication_worker.hepta").read_bytes()==(HERE/"native/publication_worker.hepta").read_bytes(),
        "whole generated HIA and retained author evidence")
    build=read_worker_build.verify(HERE,root/"native")
    build_controls.guard_receipt(root/"BUILD_READ.json",build)
    controls=build_controls.read(HERE,root/"native",root/"controls")
    expected=dict(status="PUBLICATION_WORKER_FRESH_BUILD_AND_CONTROLS_PASS",source=identity,
        fresh_hia_compiles=6,runtime_hia_images=4,physical_mutations=4,relocations=2,
        application_executed=False,public_route=False,full_sdk=False,old_stack_removed=False)
    require(decode((root/"CAPTURE.json").read_bytes())==expected,"exact build-only scope")
    require(set(p.name for p in root.iterdir())=={"SOURCE.json","generated","native","BUILD_READ.json","controls","CAPTURE.json"},"whole build evidence root")
    return dict(status="COMPLETE_PUBLICATION_WORKER_BUILD_READ_PASS",source=identity,build=build,controls=controls,
        application_executed=False,public_async_qualified=False,full_sdk=False)
def capture(hepta,output):
    require(os.environ.get("GITHUB_ACTIONS")=="true","new HIA/GAS build only in frozen CI")
    require(not output.exists(),"fresh capture");output.mkdir(parents=True)
    identity=check_source();(output/"SOURCE.json").write_bytes(canonical(identity))
    sys.path.insert(0,str(HERE/"authoring"));from author_worker import author
    author(HERE,hepta,output/"generated")
    require((output/"generated/publication_worker.hepta").read_bytes()==(HERE/"native/publication_worker.hepta").read_bytes(),"repeat exact HIA author")
    build_worker.build(HERE,hepta,output/"native")
    proof=readonly.guarded(lambda:read_worker_build.verify(HERE,output/"native"),roots=(HERE,output/"native"))
    (output/"BUILD_READ.json").write_bytes(canonical(proof))
    build_controls.create(HERE,output/"native",output/"controls")
    value=dict(status="PUBLICATION_WORKER_FRESH_BUILD_AND_CONTROLS_PASS",source=identity,
        fresh_hia_compiles=6,runtime_hia_images=4,physical_mutations=4,relocations=2,
        application_executed=False,public_route=False,full_sdk=False,old_stack_removed=False)
    (output/"CAPTURE.json").write_bytes(canonical(value))
    start=time.monotonic()
    proof=readonly.guarded(lambda:read(output),roots=(HERE,output))
    require(time.monotonic()-start<180,"complete pure build-reader 180 seconds")
    Path(str(output)+"-readonly.json").write_bytes(canonical(proof))
    return dict(status=proof["evidence"]["status"],entries=proof["entries"],guards=len(proof["probes"]),
        executable=proof["evidence"]["build"]["executable"],application_executed=False)
def main():
    p=argparse.ArgumentParser();p.add_argument("mode",choices=("source","build","read"))
    p.add_argument("--hepta",type=Path);p.add_argument("--output",type=Path);p.add_argument("--capture",type=Path)
    a=p.parse_args()
    if a.mode=="source":v=check_source()
    elif a.mode=="build":v=capture(a.hepta.resolve(strict=True),a.output.absolute())
    else:
        require(a.output is not None and not a.output.exists(),"fresh passive receipt")
        start=time.monotonic();proof=readonly.guarded(lambda:read(a.capture),roots=(HERE,a.capture))
        require(time.monotonic()-start<180,"passive complete build-reader 180 seconds")
        a.output.write_bytes(canonical(proof));v=dict(status=proof["evidence"]["status"],entries=proof["entries"],guards=len(proof["probes"]))
    print(json.dumps(v,sort_keys=True))
if __name__=="__main__":main()
