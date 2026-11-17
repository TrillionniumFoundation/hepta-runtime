#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""New pure comparison of the complete already uploaded first actual capture."""
from pathlib import Path
import argparse,json,shutil,sys,time
sys.dont_write_bytecode=True;HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
from common import canonical,decode,pin,require,source_evidence
import read_native,readonly
def main():
    p=argparse.ArgumentParser();p.add_argument("--prepared",type=Path,required=True)
    p.add_argument("--build-recipe",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False);source_evidence(HERE)
    prep=decode((a.prepared/"PREPARED.json").read_bytes())
    sys.path.insert(0,str(a.build_recipe/"current"))
    from restore_full import restore
    identity=dict(artifact=14339243128,zip=dict(bytes=4126054,sha256="3505b508966a12198c2235860c84186662f59628d64cf70a782da9e465880c1c"),
        archive=dict(bytes=4021796,sha256="53d1846429b20e2c52adaebf7e67d3415aa43ccd3a5a83a933b34daeb7fd5795"))
    root,archive=restore(a.output/"retained",identity)
    original=Path(prep["original"]);plan=decode((original/"PLAN.json").read_bytes())
    source=decode((root/"recipe-source/SOURCE_MANIFEST.json").read_bytes())
    require(pin(root/"recipe-source/SOURCE_MANIFEST.json")==dict(bytes=8201,sha256="d5b8d7f974b749973f8377eabe3b4e04ac18a05009b7e960a8de56aa7c384416"),
        "unchanged first producer source identity")
    for row in source["files"]:
        require(pin(root/"recipe-source"/row["path"])=={k:row[k] for k in ("bytes","sha256")},"complete first producer source bytes")
    native=root/"capture/native"
    np=decode((native/"PLAN.json").read_bytes())
    require(np["first"]==0 and np["count"]==1 and np["cases"]==plan["cases"][:1]
        and np["original_plan"]==pin(original/"PLAN.json"),"same actual unchanged input-only case")
    expected=prep["inputs"]["build"]["binary"];binary=Path(prep["binary"])
    require(pin(binary)=={k:expected[k] for k in ("bytes","sha256")}==np["binary"],"whole actual graph binary")
    start=time.monotonic()
    def operation():
        return read_native.compare(native/"cases/000",original/"cases/000",plan["cases"][0],np["binary"])
    proof=readonly.guarded(operation,roots=[HERE,root,original])
    elapsed=time.monotonic()-start;require(elapsed<180,"complete independent reader180s")
    (a.output/"READONLY.json").write_bytes(canonical(proof))
    summary=dict(status=proof["evidence"]["status"],case=0,elapsed_seconds=elapsed,
        guards=len(proof["probes"]),entries=proof["entries"],archive=archive,
        hia_executed=False,rust_executed=False,reader_writes=0,full_30_domain=False,
        worker_journal_semantic_read_pending=True,full_sdk=False,evidence=proof["evidence"])
    (a.output/"SUMMARY.json").write_bytes(canonical(summary))
    print(json.dumps({k:v for k,v in summary.items() if k!="evidence"},sort_keys=True),flush=True)
if __name__=="__main__":main()
