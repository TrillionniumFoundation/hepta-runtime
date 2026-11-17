#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Read retained concurrent responses and exact SDK source; execute no application."""
from pathlib import Path
import argparse,json,sys,time
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
def main():
    p=argparse.ArgumentParser()
    for name in ("retained","build-recipe","output","restored"):p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    sys.path.insert(0,str(a.retained))
    from common import canonical,decode,pin,require,sha,source_evidence
    from buffer_store import Reader
    import readonly,wire_versions
    source=source_evidence(a.retained)
    for row in decode((HERE/"SOURCE_MANIFEST.json").read_bytes())["files"]:
        require(pin(HERE/row["path"])=={k:row[k] for k in ("bytes","sha256")},"exact independent inspector source")
    sys.path.insert(0,str(a.build_recipe/"current"))
    from restore_full import restore
    inputs=decode((HERE/"INPUTS.json").read_bytes())
    a.restored.mkdir(parents=True,exist_ok=False)
    archives={key:restore(a.restored/key,value) for key,value in inputs.items()}
    def operation():
        original=archives["original"][0]
        original_domain=original/"capture/domain"
        plan=decode((original_domain/"PLAN.json").read_bytes())
        roots={}
        for label,(root,receipt) in archives.items():
            if label=="original":continue
            native=root/"capture/native";current=decode((native/"PLAN.json").read_bytes())
            selected=plan["cases"][current["first"]:current["first"]+current["count"]]
            require(current["cases"]==selected,"whole unchanged cases")
            cases=[]
            for case in selected:
                n=native/"cases"/("%03d"%case["case"]);o=original_domain/"cases"/("%03d"%case["case"])
                np=decode((n/"process/PROCESS.json").read_bytes())
                result=decode((n/"RESULT.json").read_bytes())
                require(result["process"]==np and np["exit_code"]==0 and not np["timed_out"]
                    and np["completion_error"] is None and np["cleanup_errors"]==[]
                    and np["process_group_absent"] is True,"actual terminal process")
                ns=Reader(n/"buffers");os=Reader(o/"buffers")
                nc=decode((n/"COMMANDS.json").read_bytes());oc=decode((o/"COMMANDS.json").read_bytes())
                require(len(nc)==len(oc),"full command count")
                nf=decode((n/"FILESYSTEM.json").read_bytes())[-1]["files"]
                of=decode((o/"FILESYSTEM.json").read_bytes())[-1]["files"]
                changes=[];wire_count=0;last_events=[]
                for i,(nr,orr) in enumerate(zip(nc,oc,strict=True)):
                    nq=ns.get(nr["request"]);oq=os.get(orr["request"])
                    require(nq==oq and nr["source_step"]==orr["source_step"],"exact original command")
                    q=decode(nq);ov=decode(os.get(orr["response"]));last_events=ov["state"]["events"]
                    if q["kind"] not in ("read","drain"):continue
                    nrw=bytes.fromhex(nr["result"]["wire_hex"]);orw=bytes.fromhex(ov["result"]["wire_hex"])
                    nl,nv=wire_versions.lines(nrw,case,nf,ns)
                    ol,ovp=wire_versions.lines(orw,case,of,os)
                    wire_count+=len(nl.splitlines())
                    if nl!=ol:
                        changes.append(dict(command=i,kind=q["kind"],session=q["session"],
                            native_wire_hex=nrw.hex(),original_wire_hex=orw.hex(),
                            native_versions=nv,original_versions=ovp,
                            native_ids=[decode(line).get("id") for line in nl.splitlines()],
                            original_ids=[decode(line).get("id") for line in ol.splitlines()],
                            complete_lines_permutation_only=sorted(nl.splitlines(keepends=True))==sorted(ol.splitlines(keepends=True))))
                cases.append(dict(case=case["case"],name=case["name"],era=case["era"],commands=len(nc),
                    process=np,complete_wire_lines=wire_count,differences=changes,
                    original_future_events=[e for e in last_events if e["event"] in ("entered","returned","dropped")]))
            roots[label]=dict(archive=receipt,cases=cases,
                retained_reader_stderr=(root/"capture/read.stderr").read_text())
        registry=original/"capture/dependency/extracted/capture/registry-source/rmcp-3.9.0"
        require(registry.is_dir(),"exact current SDK retained registry source")
        patterns=("response_send_tasks","request_tasks","tokio::spawn","JoinSet","FuturesUnordered")
        sdk=[]
        for path in sorted((registry/"src").rglob("*.rs")):
            if "service" not in path.relative_to(registry).as_posix():continue
            lines=path.read_text().splitlines();indices=[i for i,line in enumerate(lines) if any(s in line for s in patterns)]
            if not indices:continue
            wanted=sorted({j for i in indices for j in range(max(0,i-12),min(len(lines),i+30))})
            sdk.append(dict(path=path.relative_to(registry).as_posix(),source=pin(path),
                excerpts=[dict(line=i+1,text=lines[i]) for i in wanted]))
        require(sdk,"actual SDK scheduling source retained")
        return dict(status="COMPLETE_RETAINED_PUBLIC_RESPONSE_ORDER_DIAGNOSTIC_ONLY",source=source,
            original_archive=archives["original"][1],roles=roots,sdk_source=sdk,
            native_executed=False,rust_executed=False,production_changed=False,qualification=False)
    start=time.monotonic()
    proof=readonly.guarded(operation,roots=[HERE,a.retained,*[r[0] for r in archives.values()]])
    require(time.monotonic()-start<180,"complete independent diagnostic original180s")
    (a.output/"READONLY.json").write_bytes(canonical(proof))
    (a.output/"DIAGNOSTIC.json").write_bytes(canonical(proof["evidence"]))
    print("COMPLETE_RESPONSE_ORDER_DIAGNOSTIC "+json.dumps(proof["evidence"],sort_keys=True),flush=True)
if __name__=="__main__":main()
