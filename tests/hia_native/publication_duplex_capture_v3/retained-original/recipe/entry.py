#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Complete original lifecycle capture and separately guarded immutable reread."""
from pathlib import Path
import argparse,ast,hashlib,json,os,signal,subprocess,sys,time
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import canonical,decode,pin,require,source_evidence
import dependency,read_build,read_capture,controls,readonly
from input_domain import declaration,cases
HERE=Path(__file__).resolve().parents[1]
_PREPARED=None
_PREPARED_ROOT=None

def inputs():
    raw=source_evidence(HERE)
    require(decode((HERE/"DOMAIN.json").read_bytes())==declaration(),"frozen lifecycle input declaration")
    origin=decode((HERE/"AUTHOR.json").read_bytes())
    old=(HERE/"retained/capture_gateway.py").read_text()
    current=(HERE/"recipe/observer_process.py").read_text()
    left=next(n for n in ast.parse(old).body if isinstance(n,ast.ClassDef) and n.name=="Process")
    right=next(n for n in ast.parse(current).body if isinstance(n,ast.ClassDef) and n.name=="Process")
    require(ast.dump(left,include_attributes=False)==ast.dump(right,include_attributes=False),"retained whole Process AST")
    exact=old[old.index("class Process:\n"):old.index("\ndef setup(",old.index("class Process:\n"))]
    require(exact in current and pin(HERE/"retained/capture_gateway.py")=={k:origin["retained_process_source"][k] for k in ("bytes","sha256")},"exact original Process text")
    require(hashlib.sha256(exact.encode()).hexdigest()==origin["exact_class"]["sha256"],"exact Process class identity")
    for path,expected in origin["unchanged_full_files"].items():
        require(pin(HERE/path)=={k:expected[k] for k in ("bytes","sha256")},"unchanged helper source")
    for path in HERE.rglob("*.py"):compile(path.read_bytes(),str(path),"exec")
    return dict(files=raw["files"]+1,manifest=raw["manifest"],domain=declaration(),
        exact_process_ast=True,time_limits=origin["time_limits"])

def prepare(capture):
    global _PREPARED,_PREPARED_ROOT
    _PREPARED_ROOT=Path(capture).resolve(strict=True)
    _PREPARED=read_build.prepare(_PREPARED_ROOT/"dependency")
    return _PREPARED

def execute(root,name,command,timeout):
    root=Path(root);root.mkdir(exist_ok=True)
    begin=time.monotonic();timed=False
    with (root/(name+".stdout")).open("xb") as out,(root/(name+".stderr")).open("xb") as err:
        p=subprocess.Popen(list(map(str,command)),stdin=subprocess.DEVNULL,stdout=out,stderr=err,start_new_session=True)
        try:p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed=True;os.killpg(p.pid,signal.SIGKILL);p.wait()
    receipt=dict(name=name,command=list(map(str,command)),pid=p.pid,exit_code=p.returncode,
        timed_out=timed,outer_timeout_seconds=timeout,elapsed_seconds=time.monotonic()-begin,
        stdout=pin(root/(name+".stdout")),stderr=pin(root/(name+".stderr")),
        child_process_limit_seconds=180 if name=="actual-original-domain" else None,
        child_exchange_limit_seconds=60 if name=="actual-original-domain" else None)
    (root/(name+".json")).write_bytes(canonical(receipt))
    if p.returncode or timed:sys.stderr.buffer.write((root/(name+".stderr")).read_bytes())
    require(p.returncode==0 and not timed,"actual phase did not succeed: "+name)
    return receipt

def capture(output):
    output=Path(output).absolute();output.mkdir(parents=True,exist_ok=False)
    source=inputs();(output/"SOURCE_CHECK.json").write_bytes(canonical(source))
    dependency.restore(output/"dependency")
    prepare(output)
    proof=readonly.guarded(lambda:read_build.verify(output/"dependency",_PREPARED),roots=[HERE,output/"dependency"])
    (output/"BUILD_READ.json").write_bytes(canonical(proof))
    d=dependency.declaration();binary=output/"dependency/extracted"/d["binary_relative"]
    require(pin(binary)==d["binary"],"admitted original executable")
    execute(output/"processes","actual-original-domain",
        [sys.executable,"-I","-S","-B",HERE/"recipe/capture.py","--binary",binary,"--output",output/"domain"],None)
    execute(output/"processes","physical-reader-controls",
        [sys.executable,"-I","-S","-B",HERE/"recipe/entry.py","controls",
            "--capture",output,"--output",output/"controls"],180)
    value=dict(status="ACTUAL_ORIGINAL_PUBLISHER_ASYNC_CAPTURE_COMPLETE",source=source,
        cases=30,public_cases=22,direct_cases=8,physical_mutations=8,relocations=2,
        reference_head=d["head"],reference_run=d["run_id"],reference_binary=d["binary"],
        native_async=False,full_sdk=False,production_installed=False)
    (output/"CAPTURE.json").write_bytes(canonical(value))
    return value

def read(capture_root):
    root=Path(capture_root).resolve(strict=True)
    require(_PREPARED is not None and _PREPARED_ROOT==root,"reader dependencies must be prepared before guard")
    source=inputs()
    require(decode((root/"SOURCE_CHECK.json").read_bytes())==source,"exact source preflight receipt")
    build=read_build.verify(root/"dependency",_PREPARED)
    prior=decode((root/"BUILD_READ.json").read_bytes())
    require(prior["status"]=="READONLY_PASS" and prior["before"]==prior["after"]
        and len(prior["probes"])==11 and all(p["rejected"] for p in prior["probes"])
        and prior["evidence"]==build,"original complete build custody read")
    observed=read_capture.verify(root/"domain")
    require(observed["full_domain"] and observed["cases"]==30,"full 30-case lifecycle domain")
    physical=controls.verify(root/"domain",root/"controls",HERE)
    stages=[]
    for name,limit in (("actual-original-domain",None),("physical-reader-controls",180)):
        row=decode((root/"processes"/(name+".json")).read_bytes())
        require(row["name"]==name and row["exit_code"]==0 and not row["timed_out"]
            and row["outer_timeout_seconds"]==limit,"complete phase terminal")
        for stream in ("stdout","stderr"):
            require(pin(root/"processes"/(name+"."+stream))==row[stream],"complete phase stream")
        require(row["stderr"]["bytes"]==0,"actual phase stderr")
        if name=="actual-original-domain":
            require(row["child_process_limit_seconds"]==180 and row["child_exchange_limit_seconds"]==60,"inner original budgets")
        else:require(row["elapsed_seconds"]<180,"physical controls180-second budget")
        stages.append({k:row[k] for k in ("name","exit_code","timed_out","outer_timeout_seconds")})
    require(set(p.name for p in (root/"processes").iterdir())=={
        name+suffix for name in ("actual-original-domain","physical-reader-controls")
        for suffix in (".json",".stdout",".stderr")},"full phase process record set")
    d=dependency.declaration()
    expected=dict(status="ACTUAL_ORIGINAL_PUBLISHER_ASYNC_CAPTURE_COMPLETE",source=source,
        cases=30,public_cases=22,direct_cases=8,physical_mutations=8,relocations=2,
        reference_head=d["head"],reference_run=d["run_id"],reference_binary=d["binary"],
        native_async=False,full_sdk=False,production_installed=False)
    require(decode((root/"CAPTURE.json").read_bytes())==expected,"complete original qualification scope")
    require(set(p.name for p in root.iterdir())=={"SOURCE_CHECK.json","dependency","BUILD_READ.json",
        "processes","domain","controls","CAPTURE.json"},"complete qualification capture closure")
    return dict(status="COMPLETE_ACTUAL_PUBLISHER_ASYNC_REFERENCE_PASS",source=source,build=build,
        original=observed,physical_controls=physical,stages=stages,
        reader_native_executed=False,reader_rust_executed=False,
        native_async_qualified=False,full_sdk=False,production_installed=False)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("mode",choices=("source","capture","controls","read"))
    p.add_argument("--capture",type=Path)
    p.add_argument("--output",type=Path)
    a=p.parse_args()
    if a.mode=="source":result=inputs()
    elif a.mode=="capture":
        require(os.environ.get("GITHUB_ACTIONS")=="true","original application execution restricted to the frozen CI")
        result=capture(a.output)
    elif a.mode=="controls":
        inputs();result=controls.create(a.capture/"domain",a.output,HERE)
    else:
        require(a.output is not None and not a.output.exists(),"fresh readonly proof path")
        prepare(a.capture)
        started=time.monotonic()
        result=readonly.guarded(lambda:read(a.capture),roots=[HERE,a.capture])
        require(time.monotonic()-started<180,"complete pure-reader180-second bound")
        a.output.write_bytes(canonical(result))
    if a.mode=="read":
        print(json.dumps(dict(status=result["status"],entries=result["entries"],guards=len(result["probes"]),
            evidence_status=result["evidence"]["status"],cases=result["evidence"]["original"]["cases"]),sort_keys=True))
    else:print(json.dumps(result,sort_keys=True))
if __name__=="__main__":main()
