#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Read exact retained Tokio source; execute no application or compiler."""
from pathlib import Path
import argparse,json,sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from dependency import restore
from common import canonical,decode,pin,require
p=argparse.ArgumentParser()
p.add_argument("--output",type=Path,required=True)
a=p.parse_args()
restore(a.output)
root=a.output/"extracted"
index=decode((a.output/"outer/FILES.json").read_bytes())
wanted=["src/runtime/blocking/pool.rs","src/runtime/blocking/task.rs",
        "src/runtime/blocking/shutdown.rs","src/runtime/builder.rs",
        "src/runtime/task/abort.rs","src/runtime/task/join.rs"]
selected={}
for suffix in wanted:
    matches=[r for r in index["files"] if "/tokio-1.53.3/"+suffix in r["path"]
             and r["path"].endswith("/tokio-1.53.3/"+suffix)]
    require(len(matches)==1,"exact retained Tokio source "+suffix)
    row=matches[0];path=root/row["path"]
    require(pin(path)=={k:row[k] for k in ("bytes","sha256")},"retained source identity")
    text=path.read_text();lines=text.splitlines()
    if suffix.endswith("builder.rs"):
        hits=[i for i,line in enumerate(lines) if any(x in line for x in
             ["max_blocking_threads: 512","thread_keep_alive:","blocking::create_blocking_pool",
              "max_blocking_threads +", "max_blocking_threads,"])]
        keep=sorted({j for i in hits for j in range(max(0,i-10),min(len(lines),i+15))})
        excerpts=[{"line":i+1,"text":lines[i]} for i in keep]
    else:
        excerpts=[{"line":i+1,"text":line} for i,line in enumerate(lines)]
    selected[suffix]={"path":row["path"],"identity":pin(path),"excerpts":excerpts}
    print("TOKIO_SOURCE "+json.dumps({"name":suffix,**selected[suffix]},sort_keys=True))
(a.output/"TOKIO_SOURCE.json").write_bytes(canonical(selected))
print(json.dumps({"status":"EXACT_RETAINED_TOKIO_SOURCE_READ","files":len(selected),
                  "application_executed":False,"compiler_executed":False},sort_keys=True))
