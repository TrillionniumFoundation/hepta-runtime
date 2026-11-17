#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Replace only an independently verified physical publication version span."""
from pathlib import Path
import json,stat
from common import require,sha
BODY_KEYS={"path","mode","published","bytes","sha256","version","was_new_file",
    "same_path_atomic_publication","external_writers_transactionally_excluded"}
def version(s):
    return ":".join(str(x) for x in (s["dev"],s["ino"],s["size"],
        s["mtime_ns"]//1_000_000_000,s["mtime_ns"]%1_000_000_000,
        s["ctime_ns"]//1_000_000_000,s["ctime_ns"]%1_000_000_000))
def lines(raw,case,final_files,reader):
    """All bytes outside the exact verified numeric version token are retained."""
    require(type(raw) is bytes and (not raw or raw.endswith(b"\n")),"complete public response lines")
    by_path={row["path"]:row for row in final_files}
    require(len(by_path)==len(final_files),"one final observed path identity")
    requests=[]
    for row in case["steps"]:
        if row.get("kind")=="send":
            q=json.loads(bytes.fromhex(row["wire_hex"]))
            p=q.get("params")
            if q.get("method")=="tools/call" and isinstance(p,dict) and p.get("name")=="text_file_write":
                requests.append(p["arguments"])
    inputs={p["path"]:p for p in requests};require(len(inputs)==len(requests),"this frozen domain creates each publication path once")
    result=[];proof=[]
    for line in raw.splitlines(keepends=True):
        value=json.loads(line);content=value.get("result",{}).get("content")
        if not isinstance(content,list) or len(content)!=1 or content[0].get("type")!="text":
            result.append(line);continue
        text=content[0].get("text")
        if not isinstance(text,str):result.append(line);continue
        try:body=json.loads(text)
        except json.JSONDecodeError:result.append(line);continue
        if not isinstance(body,dict) or "version" not in body:
            result.append(line);continue
        require(set(body)==BODY_KEYS and set(content[0])=={"type","text"}
            and value["result"].get("isError") is False,"exact successful publisher body")
        require(body["path"] in inputs,"version belongs to a real submitted publication")
        submitted=inputs[body["path"]];require(submitted["mode"]=="create" and submitted["expected_sha256"]=="absent",
            "only this unchanged create-only lifecycle domain")
        relative=Path(body["path"]).relative_to(case["root"]).as_posix()
        require(relative in by_path and by_path[relative]["kind"]=="file","actual final publication file")
        row=by_path[relative];s=row["stat"];data=reader.get(row["data"])
        require(stat.S_ISREG(s["mode"]) and s["nlink"]==1 and data==submitted["content"].encode()
            and len(data)==s["size"]==body["bytes"] and sha(data)==body["sha256"],"whole actual resulting file body")
        require(body["mode"]=="create" and body["published"] is True and body["was_new_file"] is True
            and body["same_path_atomic_publication"] is True and body["external_writers_transactionally_excluded"] is False,
            "unchanged typed publication semantics")
        exact=version(s)
        require(type(body["version"]) is str and body["version"]==exact,"all seven version fields equal actual final stat")
        needle=b'\\"version\\":\\"'+exact.encode("ascii")+b'\\"'
        require(line.count(needle)==1,"one exact escaped ASCII version token")
        normalized=line.replace(needle,b'\\"version\\":\\"<actual-seven-field-stat>\\"',1)
        result.append(normalized)
        proof.append(dict(path=relative,version=exact,actual_stat={k:s[k] for k in ("dev","ino","size","mtime_ns","ctime_ns")},
            full_wire_sha256=sha(line),normalized_wire_sha256=sha(normalized),file_sha256=sha(data)))
    return b"".join(result),proof
