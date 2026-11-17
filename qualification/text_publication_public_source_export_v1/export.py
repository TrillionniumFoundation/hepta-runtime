#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Export exact already-built public123 source bytes; no source authoring or implementation execution."""
from pathlib import Path
import argparse,hashlib,json,shutil,sys
sys.dont_write_bytecode=True
p=argparse.ArgumentParser()
for name in ("reader-source","work","output"):p.add_argument("--"+name,required=True,type=Path)
a=p.parse_args()
sys.path.insert(0,str(a.reader_source/"recipe"))
from common import require,pin,canonical,source_evidence
import dependencies as dep
require(not a.work.exists() and not a.output.exists(),"fresh source-byte read")
a.work.mkdir(parents=True);a.output.mkdir(parents=True)
source_evidence(a.reader_source)
root=dep.extract(dep.GRAPH,a.work/"graph")
_,report=dep.read_graph(root)
source=root/"capture/composition/source"
binding=json.loads((source/"native/runtime_mcp_sources.json").read_bytes())
wanted=set(binding["sources"])|{"native/runtime_mcp_sources.json"}
rows=[]
for name in sorted(wanted):
    raw=(source/name).read_bytes()
    identity=dict(path=name,mode="100644",bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),
        git_blob=hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest())
    rows.append(identity)
    print(json.dumps(dict(kind="SOURCE_ROW",row=identity),sort_keys=True),flush=True)
selected=["scripts/runtime_mcp_extra_engine.S","scripts/public_nine_build.py",
    "scripts/runtime_mcp_transport.S","scripts/runtime_mcp_filesystem_fixture.S",
    "native/runtime_mcp_publication_graph_composition.json","native/runtime_mcp_sources.json"]
for name in selected:
    raw=(source/name).read_bytes();text=raw.decode()
    require(text.encode()==raw,"complete UTF8 source")
    target=a.output/"source"/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
    chunks=[text[i:i+12000] for i in range(0,len(text),12000)]
    for number,chunk in enumerate(chunks):
        print(json.dumps(dict(kind="SOURCE_TEXT_CHUNK",path=name,index=number,total=len(chunks),text=chunk)),flush=True)
require(len(rows)==486,"complete built source inventory")
(a.output/"SOURCE_ROWS.json").write_bytes(canonical(dict(schema="hepta.runtime.public123.exact-git-source-rows.v1",
    graph_source=dep.GRAPH["commit"],graph_artifact=dep.GRAPH,rows=rows,
    hia_executed=False,rust_executed=False)))
(a.output/"GRAPH_READ.json").write_bytes(canonical(report))
for name in ("FILES.json","ARCHIVE.json"):shutil.copyfile(a.work/"graph"/name,a.output/name)
print(json.dumps(dict(kind="SOURCE_EXPORT_COMPLETE",files=486,selected=len(selected),
    source_rows=pin(a.output/"SOURCE_ROWS.json"),hia_executed=False,rust_executed=False)),flush=True)
