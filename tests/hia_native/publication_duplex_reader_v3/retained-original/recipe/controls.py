#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Physical evidence changes; no application, compiler, or original code replay."""
from pathlib import Path
import gzip,hashlib,os,shutil
from common import canonical,decode,pin,require
from buffer_store import Reader,Writer
from input_domain import cases
from read_capture import verify_case
from readonly import guarded

def index(root):
    return {p.relative_to(root).as_posix():dict(**pin(p),mode=p.stat().st_mode&0o777)
        for p in sorted(Path(root).rglob("*")) if p.is_file()}

def resign(root):
    result=decode((root/"RESULT.json").read_bytes())
    result["commands"]=len(decode((root/"COMMANDS.json").read_bytes()))
    result["snapshots"]=len(decode((root/"FILESYSTEM.json").read_bytes()))
    result["files"]=dict(commands=pin(root/"COMMANDS.json"),host=pin(root/"HOST.json"),filesystem=pin(root/"FILESYSTEM.json"))
    if (root/"process/PROCESS.json").exists():
        result["process"]=decode((root/"process/PROCESS.json").read_bytes())
    (root/"RESULT.json").write_bytes(canonical(result))

def rewrite_responses(root,transform):
    commands=decode((root/"COMMANDS.json").read_bytes())
    snapshots=decode((root/"FILESYSTEM.json").read_bytes())
    old=Reader(root/"buffers")
    inputs=[old.get(r["request"]) for r in commands]
    responses=[old.get(r["response"]) for r in commands]
    file_data={(i,j):old.get(row["data"]) for i,snap in enumerate(snapshots)
        for j,row in enumerate(snap["files"]) if row["kind"]=="file"}
    changed=0
    for i,raw in enumerate(responses):
        value=decode(raw)
        if transform(value):responses[i]=canonical(value);changed+=1
    require(changed>0,"physical response mutation was not applied")
    temp=root/"buffers-new";new=Writer(temp)
    for i,row in enumerate(commands):
        row["request"]=new.put(inputs[i]);row["response"]=new.put(responses[i])
    for (i,j),raw in file_data.items():snapshots[i]["files"][j]["data"]=new.put(raw)
    shutil.rmtree(root/"buffers");temp.rename(root/"buffers")
    (root/"COMMANDS.json").write_bytes(canonical(commands))
    (root/"FILESYSTEM.json").write_bytes(canonical(snapshots))
    stdout=b"".join(responses)
    with (root/"process/stdout.gz").open("wb") as dest:
        with gzip.GzipFile(fileobj=dest,filename="",mode="wb",compresslevel=1,mtime=0) as z:z.write(stdout)
    process=decode((root/"process/PROCESS.json").read_bytes())
    process["stdout_gzip"]=pin(root/"process/stdout.gz")
    process["full_stdout"]=dict(bytes=len(stdout),sha256=hashlib.sha256(stdout).hexdigest())
    (root/"process/PROCESS.json").write_bytes(canonical(process))
    result=decode((root/"RESULT.json").read_bytes())
    result["complete_buffer_images"]=new.images;result["logical_buffer_bytes"]=new.logical_bytes
    (root/"RESULT.json").write_bytes(canonical(result));resign(root)

def mutations():
    def configuration(root,fixture):
        value=decode((root/"config.json").read_bytes());value["controller_workspace_roots"]=["/"]
        (root/"config.json").write_bytes(canonical(value))
    def source_step(root,fixture):
        value=decode((root/"COMMANDS.json").read_bytes());value[0]["source_step"]+=1
        (root/"COMMANDS.json").write_bytes(canonical(value));resign(root)
    def missing_snapshot(root,fixture):
        value=decode((root/"FILESYSTEM.json").read_bytes());del value[1]
        (root/"FILESYSTEM.json").write_bytes(canonical(value));resign(root)
    def holder_identity(root,fixture):
        value=decode((root/"HOST.json").read_bytes());value[0]["identity"]["ino"]+=1
        (root/"HOST.json").write_bytes(canonical(value));resign(root)
    def wait_inode(root,fixture):
        def change(value):
            if value["kind"]=="wait_blocked":value["result"]["ino"]+=1;return True
            return False
        rewrite_responses(root,change)
    def drop_order(root,fixture):
        def change(value):
            changed=False
            for event in value["state"]["events"]:
                if event["event"]=="dropped":
                    event["after_return"]=not event["after_return"];changed=True
            return changed
        rewrite_responses(root,change)
    def final_file(root,fixture):
        path=fixture/"held/a.txt"
        before=path.stat();raw=path.read_bytes();require(raw,"actual final file must exist for mutation")
        path.write_bytes(bytes([raw[0]^1])+raw[1:])
        os.utime(path,ns=(before.st_atime_ns,before.st_mtime_ns))
    def process_limit(root,fixture):
        value=decode((root/"process/PROCESS.json").read_bytes());value["timeout_seconds"]=181
        (root/"process/PROCESS.json").write_bytes(canonical(value));resign(root)
    return [
        ("configuration-root",configuration,"complete actual runtime configuration"),
        ("source-step",source_step,"input-only step completeness"),
        ("missing-stable-snapshot",missing_snapshot,"stable-point filesystem snapshot domain"),
        ("holder-inode",holder_identity,"same holder FD released once"),
        ("coherent-worker-inode",wait_inode,"actual worker/holder inode match"),
        ("coherent-future-drop",drop_order,"actual future Drop order"),
        ("final-file-byte",final_file,"actual retained publication bytes"),
        ("process-limit",process_limit,"unchanged process/exchange bounds")]

def create(capture,output,source):
    capture=Path(capture);output=Path(output);source=Path(source)
    output.mkdir(parents=True,exist_ok=False)
    plan=decode((capture/"PLAN.json").read_bytes())
    case=plan["cases"][0];name="%03d"%case["case"]
    base=capture/"cases"/name;fixture=capture/"fixtures"/Path(case["root"]).name
    common=(case,plan["binary"],plan["binary_path"])
    expected=verify_case(base,case,fixture,plan["binary"],plan["binary_path"])
    rows=[]
    for label in ("relocation-one","relocation-two"):
        here=output/label;here.mkdir()
        shutil.copytree(base,here/"case");shutil.copytree(fixture,here/"fixture")
        proof=guarded(lambda:verify_case(here/"case",case,here/"fixture",common[1],common[2]),roots=[here,source])
        require(proof["evidence"]==expected,"complete relocated actual evidence differs")
        (here/"PROOF.json").write_bytes(canonical(proof))
        rows.append(dict(name=label,rejected=False,proof=pin(here/"PROOF.json")))
    for label,mutation,message in mutations():
        here=output/label;here.mkdir()
        shutil.copytree(base,here/"case");shutil.copytree(fixture,here/"fixture")
        before=index(here);mutation(here/"case",here/"fixture");after=index(here)
        changed=sorted(k for k in set(before)|set(after) if before.get(k)!=after.get(k))
        require(changed,"physical control did not change bytes or mode")
        def observe():
            try:verify_case(here/"case",case,here/"fixture",common[1],common[2])
            except ValueError as error:
                require(message in str(error),"negative reached the wrong rejection: "+str(error))
                return dict(rejected=True,error=str(error))
            raise ValueError("physical altered evidence accepted")
        proof=guarded(observe,roots=[here,source])
        data=dict(name=label,expected_message=message,before=before,after=after,
            changed=changed,readonly=proof)
        (here/"PROOF.json").write_bytes(canonical(data))
        rows.append(dict(name=label,rejected=True,proof=pin(here/"PROOF.json")))
    result=dict(status="ACTUAL_PHYSICAL_READER_CONTROLS_PASS",mutations=8,relocations=2,
        base_case=case["case"],rows=rows,application_executed=False,rust_executed=False)
    (output/"RESULT.json").write_bytes(canonical(result))
    return result

def verify(capture,output,source):
    capture=Path(capture);output=Path(output);source=Path(source)
    plan=decode((capture/"PLAN.json").read_bytes())
    case=plan["cases"][0];number="%03d"%case["case"]
    base=capture/"cases"/number;fixture=capture/"fixtures"/Path(case["root"]).name
    expected=verify_case(base,case,fixture,plan["binary"],plan["binary_path"])
    result=decode((output/"RESULT.json").read_bytes())
    names=["relocation-one","relocation-two"]+[label for label,_,_ in mutations()]
    require([r["name"] for r in result["rows"]]==names
        and result["mutations"]==8 and result["relocations"]==2
        and result["base_case"]==case["case"],"complete physical control domain")
    require(set(p.name for p in output.iterdir())==set(names)|{"RESULT.json"},"physical control file set")
    baseline={**{"case/"+k:v for k,v in index(base).items()},
        **{"fixture/"+k:v for k,v in index(fixture).items()}}
    evidence=[]
    for row in result["rows"]:
        here=output/row["name"]
        require(pin(here/"PROOF.json")==row["proof"],"complete physical control receipt")
        proof=decode((here/"PROOF.json").read_bytes())
        readonly=proof["readonly"] if row["rejected"] else proof
        require(readonly["status"]=="READONLY_PASS" and readonly["before"]==readonly["after"]
            and len(readonly["before"])==readonly["entries"] and len(readonly["probes"])==11
            and all(p["rejected"] for p in readonly["probes"]),"original physical control readonly proof")
        if not row["rejected"]:
            actual=verify_case(here/"case",case,here/"fixture",plan["binary"],plan["binary_path"])
            require(canonical(actual)==canonical(expected)
                and canonical(readonly["evidence"])==canonical(expected),"relocated complete evidence result")
            evidence.append(dict(name=row["name"],relocation=True))
        else:
            require(proof["before"]==baseline,"negative before-copy complete bytes")
            current={k:v for k,v in index(here).items() if k!="PROOF.json"}
            require(current==proof["after"],"negative complete physical bytes")
            changed=sorted(k for k in set(baseline)|set(current) if baseline.get(k)!=current.get(k))
            require(changed==proof["changed"] and changed,"physical mutation set")
            wanted=next(message for label,_,message in mutations() if label==row["name"])
            require(proof["expected_message"]==wanted,"frozen rejection seam")
            try:verify_case(here/"case",case,here/"fixture",plan["binary"],plan["binary_path"])
            except ValueError as error:
                require(wanted in str(error) and readonly["evidence"]==dict(rejected=True,error=str(error)),"actual physical rejection mismatch")
                evidence.append(dict(name=row["name"],rejected=True,error=str(error)))
            else:raise ValueError("existing physical mutation accepted")
    return dict(status="COMPLETE_PHYSICAL_CONTROLS_READ_PASS",mutations=8,relocations=2,rows=evidence,
        application_executed=False,rust_executed=False,evidence_written=False)
