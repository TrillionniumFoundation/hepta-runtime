#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Independent complete uploaded current124/retained-original read. Never run apps."""
from pathlib import Path
import argparse,copy,json,shutil,sys,time
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent

def main():
    p=argparse.ArgumentParser()
    for name in ("source","build-recipe","public-reader","stage","output"):
        p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--shard",type=int,required=True);a=p.parse_args()
    require_early=lambda value: None if value else (_ for _ in ()).throw(ValueError("fresh pure-read roots"))
    require_early(not a.stage.exists() and not a.output.exists())
    a.stage.mkdir(parents=True);a.output.mkdir(parents=True)
    sys.path.insert(0,str(a.source/"recipe"));sys.path.insert(0,str(a.source))
    sys.path.insert(0,str(HERE))
    from common import canonical,decode,pin,require,source_evidence
    import check_current,current_dependencies,qualify_current,readonly,run_current
    from restore import restore
    own=source_evidence(HERE);check=check_current.check()
    inputs=decode((HERE/"INPUTS.json").read_bytes())
    expected=decode((a.source/"CURRENT_INPUTS.json").read_bytes())
    require(pin(a.source/"SOURCE_MANIFEST.json")==inputs["source_manifest"]
        and inputs["source_commit"]=="274c4481b357820e6ae044a4fdd9bcd379a80de1"
        and 0<=a.shard<len(inputs["shards"]),"exact ordinary reader/source/shard")
    for path in HERE.glob("*.py"):compile(path.read_bytes(),str(path),"exec")
    (a.output/"SOURCE_CHECK.json").write_bytes(canonical(dict(wrapper=own,ordinary=check)))
    wrapper=a.public_reader/"timed_build_read.py"
    require(pin(wrapper)==expected["build_wrapper"],"exact whole graph restore and unchanged complete guard")
    graphdir=a.stage/"complete-actual-graph";g=expected["graph"]
    cmd=[sys.executable,"-I","-S","-B",str(wrapper),"--build-recipe",str(a.build_recipe),
        "--output",str(graphdir),"--artifact",str(g["artifact"]),"--bytes",str(g["zip"]["bytes"]),
        "--sha256",g["zip"]["sha256"]]
    proc=run_current.process(cmd,a.output/"graph-read-process",pure=True)
    require(proc["exit_code"]==0 and not proc["timed_out"],"complete actual graph pure read")
    fresh=decode((graphdir/"READ_ONLY.json").read_bytes());current_dependencies.verify_guard(fresh)
    graph=fresh["evidence"]["current"]
    saved=a.output/"graph";saved.mkdir()
    for name in ("READ_ONLY.json","READ.json","FILES.json","ARCHIVE.json","SUMMARY.json"):
        shutil.copy2(graphdir/name,saved/name)
    require(decode((saved/"READ.json").read_bytes())["archive"]==g["archive"],"complete original build archive")
    def graph_identity(value):
        value=copy.deepcopy(value)
        for row in value["entries"].values():
            for name in ("elf","manifest"):
                require(set(row[name])=={"path","bytes","sha256"},"complete actual graph descriptor")
                row[name].pop("path")
        return value
    def guard(proof):
        require(proof["status"]=="READONLY_PASS" and proof["before"]==proof["after"]
            and proof["entries"]==len(proof["before"]) and len(proof["probes"])==11
            and all(row["rejected"] is True for row in proof["probes"])
            and proof["native_executed"] is proof["rust_executed"] is proof["evidence_written"] is False,
            "whole retained ordinary pure-reader guard")
    groups=[r for r in inputs["groups"] if r["group"] in inputs["shards"][a.shard]]
    require(len(groups)==3 and {r["group"] for r in groups}==set(inputs["shards"][a.shard]),
        "complete three-group pure shard")
    results=[]
    for item in groups:
        group=item["group"];out=a.output/group;out.mkdir()
        root,archive=restore(item,a.stage/group)
        require(pin(root/"recipe-source/SOURCE_MANIFEST.json")==inputs["source_manifest"]
            and (root/"recipe-source/SOURCE_MANIFEST.json").read_bytes()==(a.source/"SOURCE_MANIFEST.json").read_bytes(),
            "whole uploaded exact ordinary source manifest")
        source_evidence(root/"recipe-source")
        for row in decode((a.source/"SOURCE_MANIFEST.json").read_bytes())["files"]:
            require((root/"recipe-source"/row["path"]).read_bytes()==(a.source/row["path"]).read_bytes(),
                "every original checked reader/capture/domain source")
        before=readonly.snapshot([root])
        capture=root/"capture";summary=decode((capture/"SUMMARY.json").read_bytes())
        require(summary["status"]=="COMPLETE_CURRENT124_TWO_ERA_ORDINARY_PASS"
            and summary["group"]==group and summary["cases"]==item["cases"]
            and summary["native_processes"]==2 and summary["original_processes"]==0
            and summary["runtime_hia_images"]==124 and summary["physical_images"]==117
            and summary["source"]==check["source"]
            and {r["key"] for r in summary["roles"]}==set(item["keys"]),"complete actual two-era summary")
        require(decode((capture/"RESULTS.json").read_bytes())==summary["roles"],
            "complete actual role result records")
        oldgraph=decode((capture/"dependencies/GRAPH_READ.json").read_bytes())
        current_dependencies.verify_guard(oldgraph)
        require(graph_identity(oldgraph["evidence"]["current"])==graph_identity(graph),
            "every path-independent field of actual revalidated graph")
        for name,key in (("filesystem.elf","instances"),("runtime-mcp.elf","production")):
            binary=capture/"dependencies"/name
            require(pin(binary)==expected["binaries"][key] and binary.stat().st_mode&0o111,
                "whole actually executed binary and executable mode")
        lanes=[]
        for role in sorted(summary["roles"],key=lambda r:r["key"]):
            key=role["key"];lane=capture/"lanes"/key
            prior=decode((lane/"READONLY.json").read_bytes());guard(prior["proof"])
            require(pin(lane/"READONLY.json")==role["proof"] and role["guards"]==11
                and role["native_executions"]==1 and role["original_executions"]==0
                and prior["elapsed_seconds"]<180,"complete original role reader witness")
            for label,suffix in (("application",""),("reader","-read")):
                stem=capture/"processes"/(key+suffix)
                record=decode(Path(str(stem)+".json").read_bytes())
                require(record==role[label] and record["exit_code"]==0 and record["timed_out"] is False
                    and record["stdout"]==pin(Path(str(stem)+".stdout"))
                    and record["stderr"]==pin(Path(str(stem)+".stderr"))
                    and record["original_executed"] is False,"whole actual process witness "+label)
            retained=capture/"retained"/key/"retained/capture"
            proof,elapsed=qualify_current.verify(lane/"capture",retained,capture/"dependencies/GRAPH_READ.json")
            require(proof["evidence"]==prior["proof"]["evidence"]==role["result"],
                "complete uploaded original/current semantic result unchanged")
            path=out/(key+".json");path.write_bytes(canonical(dict(proof=proof,elapsed_seconds=elapsed)))
            found=proof["evidence"]["current"]
            lanes.append(dict(key=key,cases=found["cases"],responses=found["responses"],
                publisher_successes=found["publisher_successes"],guards=len(proof["probes"]),
                entries=proof["entries"],elapsed_seconds=elapsed,proof=pin(path)))
        after=readonly.snapshot([root])
        require(before==after,"every uploaded byte and physical metadata stayed unchanged")
        (out/"FULL_UPLOAD_BEFORE.json").write_bytes(canonical(before))
        (out/"FULL_UPLOAD_AFTER.json").write_bytes(canonical(after))
        for name in ("READ.json","FILES.json","ARCHIVE.json"):shutil.copy2(a.stage/group/name,out/name)
        result=dict(status="COMPLETE_UPLOADED_CURRENT124_ORDINARY_GROUP_PASS",group=group,archive=archive,
            cases=sum(r["cases"] for r in lanes),roles=lanes,whole_upload_entries=len(before),
            application_executions=0,native_or_rust_executions=0)
        require(result["cases"]==item["cases"],"whole uploaded group case count")
        (out/"SUMMARY.json").write_bytes(canonical(result));results.append(result)
        (a.output/"RESULTS.json").write_bytes(canonical(results))
        print("UPLOADED_ORDINARY "+json.dumps(result,sort_keys=True),flush=True)
    final=dict(status="COMPLETE_UPLOADED_CURRENT124_ORDINARY_SHARD_PASS",shard=a.shard,
        source=own,ordinary_source=check["source"],groups=results,cases=sum(r["cases"] for r in results),
        application_executions=0,native_or_rust_executions=0,full_sdk=False,all_136_handlers=False)
    (a.output/"SUMMARY.json").write_bytes(canonical(final));print(json.dumps(final,sort_keys=True),flush=True)
if __name__=="__main__":main()
