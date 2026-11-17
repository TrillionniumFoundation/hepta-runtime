#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Byte-only diagnostic custody. This does not qualify public async semantics."""
from pathlib import Path
import argparse,hashlib,json,os,sys,urllib.request
sys.dont_write_bytecode=True;HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE/"build-reference"))
from async_build_common import require,pin,raw,doc,put,files
import restore_full,read_only_guard as guard
def verify(target):
    require(files(target/"recipe-source")==files(HERE),"exact diagnostic source bytes and modes")
    root=target/"capture/probes";domain=doc(root/"DOMAIN.json");info=doc(root/"BUILD_INPUT.json")
    require(domain==doc(HERE/"DOMAIN.json") and info==doc(HERE/"BUILD_INPUT.json"),"exact input/source identity")
    require(doc(root/"SUMMARY.json")["public_async_qualified"] is False,"diagnostic has no qualification upgrade")
    result=[]
    for i,case in enumerate(domain["cases"]):
        folder=root/("%02d-%s-%s"%(i,case["era"],case["action"]));process=folder/"process"
        r=doc(process/"PROCESS.json")
        require(r["exit_code"]==0 and not r["timed_out"] and r["timeout_seconds"]==180 and r["exchange_limit_seconds"]==60
            and not r["cleanup_errors"] and r["completion_error"] is None and r["process_group_absent"],"complete diagnostic process custody")
        for n,expected in r["files"].items():require(pin(process/n)==expected,"complete raw stream/journal bytes")
        wire=b"".join(bytes.fromhex(v["wire_hex"]) for v in doc(process/"RESPONSES.json"))
        require(raw(process/"stdout")==wire and raw(process/"stderr")==b"","complete observed wire and stderr")
        for row in doc(process/"RESPONSES.json"):
            value=bytes.fromhex(row["wire_hex"])
            require(row["bytes"]==len(value) and row["sha256"]==hashlib.sha256(value).hexdigest(),"exact response range")
            json.loads(value)
        result.append(dict(case=i,era=case["era"],action=case["action"],responses=len(doc(process/"RESPONSES.json")),files=r["files"]))
    return dict(status="PUBLIC_PENDING_DIAGNOSTIC_COMPLETE_BYTES_PASS",cases=len(result),results=result,
        application_reexecuted=False,public_async_qualified=False,full_original_domain=False)
def main():
    a=argparse.ArgumentParser();a.add_argument("--artifact",type=int,required=True);a.add_argument("--head",required=True);a.add_argument("--digest",required=True);a.add_argument("--output",type=Path,required=True);v=a.parse_args()
    request=urllib.request.Request("https://api.github.com/repos/TrillionniumFoundation/hepta-runtime/actions/artifacts/"+str(v.artifact),
        headers={"Authorization":"Bearer "+os.environ["GH_TOKEN"],"Accept":"application/vnd.github+json","User-Agent":"public-probe-byte-reader"})
    with urllib.request.urlopen(request,timeout=60) as response:m=json.load(response)
    require(m["id"]==v.artifact and m["workflow_run"]["head_sha"]==v.head and m["digest"]=="sha256:"+v.digest and not m["expired"],"same-CI uploaded identity")
    target,receipt=restore_full.restore(v.output,dict(artifact=v.artifact,zip=dict(bytes=m["size_in_bytes"],sha256=v.digest)))
    full=guard.guarded(lambda:verify(target),roots=[target,HERE],foreign_path=Path("/dev/null"))
    put(v.output/"READ_ONLY.json",full);summary=dict(status=full["evidence"]["status"],artifact=receipt,
        cases=full["evidence"]["cases"],guards=len(full["probes"]),snapshot_entries=len(full["before"]),
        application_reexecuted=False,public_async_qualified=False)
    put(v.output/"SUMMARY.json",summary);print(json.dumps(summary,sort_keys=True))
if __name__=="__main__":main()
