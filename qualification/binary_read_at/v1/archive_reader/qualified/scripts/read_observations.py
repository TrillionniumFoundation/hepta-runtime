#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Pure admission of complete fixtures and actual cross-process effect barriers."""
from pathlib import Path
import ast,stat
from common import canonical,decode,owned,pin,require,sha,source_evidence
from cases import domain,validate
from filesystem import data,describe,selected,version
from buffer_store import Reader
from read_journal import U
META=("mode","uid","gid","dev","inode","links","size","mtime_ns","ctime_ns")
def meta(row):return {k:row[k]for k in META}
def snapshots(rows,reader):
    require("."in rows and rows["."]["kind"]=="directory","fixture root missing")
    result={}
    for path,row in rows.items():
        require(type(path)is str and(path=="."or not path.startswith("/")and".."not in path.split("/")),"fixture path differs")
        kind=row["kind"];require(kind in("file","directory","symlink","fifo"),"fixture kind differs")
        require(stat.S_IFMT(row["mode"])==dict(file=stat.S_IFREG,directory=stat.S_IFDIR,symlink=stat.S_IFLNK,fifo=stat.S_IFIFO)[kind],
            "fixture mode/kind differ")
        require(all(type(row[k])is int for k in META),"fixture metadata type differs")
        if kind=="file":
            raw=reader.get(row["content"]);require(len(raw)==row["size"],"complete fixture size differs")
            result[path]=dict(row,raw=raw)
        else:result[path]=row
    return result
def initial(rows,reader,case):
    values=snapshots(rows,reader);expected={".","parent","parent/data.bin","parent/dir"}
    if case["path"]in("sidecar","unicode","control"):expected.add("parent/"+selected(case))
    if case["path"]in("fifo","symlink","hardlink"):expected.add("parent/"+selected(case))
    if case["mutation"]=="replace":expected.add("parent/replacement.bin")
    require(set(rows)==expected,"complete frozen fixture set differs")
    for path,row in values.items():
        if row["kind"]=="file":
            expected_raw=bytes([199])*case["size"]if path=="parent/replacement.bin"else data(case)
            require(row["raw"]==expected_raw and stat.S_IMODE(row["mode"])==case["permissions"],"initial full file input differs")
    if case["path"]=="hardlink":
        require(meta(values["parent/data.bin"])==meta(values["parent/hard.bin"])and values["parent/data.bin"]["links"]==2,
            "actual hardlink input differs")
    if case["path"]=="symlink":require(values["parent/link"]["target"]=="data.bin","actual symlink input differs")
    return values
def setup(source,root):
    validate();identity=source_evidence(source);summary=decode(owned(root,"SETUP.json").read_bytes())
    saved=decode(owned(root,"inputs.json").read_bytes());reader=Reader(root/"buffers");queries={};fixtures={}
    require(summary["status"]=="FROZEN_BORROWED_PARENT_INPUTS_CREATED"and summary["source"]==identity
        and summary["cases"]==59 and summary["immutable_shared_cases"]==38 and summary["separate_mutable_pairs"]==21
        and summary["original_or_native_application_calls"]==0 and [r["id"]for r in saved]==list(range(1,60)),
        "input-only setup domain/custody differs")
    for case,row in zip(domain()["cases"],saved):
        roles=row["roles"];require(set(roles)==({"original","native"}if case["mutation"]else{"shared"}),"fixture role domain differs")
        queries[row["id"]]=roles;fixtures[row["id"]]={}
        for role,q in roles.items():
            values=initial(q["snapshot"],reader,case)
            require(q==describe(Path(q["fixture"]),case,q["snapshot"]),"input-only query differs")
            fixtures[row["id"]][role]=values
    counts=reader.finish()
    require(counts["complete_images"]==summary["images"]and counts["logical_buffer_bytes"]==summary["logical_bytes"],
        "setup full buffer inventory differs")
    return queries,fixtures,counts
def mutation(case,before,after):
    name=case["mutation"];require(name is not None,"unexpected mutation")
    if name=="rename_parent":
        translated={("moved"+p[6:]if p=="parent"or p.startswith("parent/")else p):r for p,r in before.items()}
        require(set(after)==set(translated),"renamed directory complete set differs")
        for path,row in translated.items():
            got=after[path]
            stable=set(row)-({"mtime_ns","ctime_ns","size","links"}if path in(".","moved")else set())
            require({k:row[k]for k in stable}=={k:got[k]for k in stable},"directory rename changed an unrelated byte/field")
        return
    require("parent/data.bin"in before,"mutation source missing")
    old=before["parent/data.bin"];expected=set(before)
    if name=="hardlink":expected.add("parent/mutation-link.bin")
    if name=="unlink":expected.remove("parent/data.bin")
    if name=="replace":expected.remove("parent/replacement.bin")
    require(set(after)==expected,"mutated complete file set differs")
    special={".","parent","parent/data.bin","parent/mutation-link.bin","parent/replacement.bin"}
    for path,row in before.items():
        if path not in special:require(after[path]==row,"mutation changed an unrelated entry")
    for path in(".","parent"):
        for key in set(before[path])-{"mtime_ns","ctime_ns","size","links"}:
            require(after[path][key]==before[path][key],"mutation replaced parent identity/permissions")
    if name=="unlink":return
    got=after["parent/data.bin"]
    if name=="replace":
        replacement=before["parent/replacement.bin"]
        require(got["raw"]==replacement["raw"]and all(got[k]==replacement[k]for k in META if k!="ctime_ns"),
            "actual replacement bytes/inode differ")
        return
    require(all(got[k]==old[k]for k in("dev","inode","uid","gid")),"mutation replaced retained source identity")
    raw=old["raw"]
    if name=="append":expected_raw=raw+b"\x99\x01"
    elif name=="truncate":expected_raw=raw[:1]
    elif name=="overwrite":expected_raw=bytes([raw[0]^255])+raw[1:]
    else:expected_raw=raw
    require(got["raw"]==expected_raw,"complete actual mutation bytes differ")
    require(got["mode"]==(old["mode"]^0o100 if name=="chmod"else old["mode"]),"mutation mode differs")
    require(got["links"]==old["links"]+(1 if name=="hardlink"else 0),"mutation link count differs")
    if name=="utime":require(got["mtime_ns"]==old["mtime_ns"]+2_000_000_001,"explicit mutation time differs")
    elif name in("chmod","hardlink"):require(got["mtime_ns"]==old["mtime_ns"],"metadata-only mutation changed mtime")
    if name=="hardlink":require(after["parent/mutation-link.bin"]==got,"new link is not the same actual inode")
def hooks(row,reader,case,native,generation,pid):
    query=row["input"];saved=row["hooks"];events=saved["events"];mutations=saved["mutations"]
    require(len(mutations)==int(case["mutation"]is not None),"mutation count differs")
    actual=[]
    for m in mutations:
        require(m["name"]==case["mutation"]and m["separate_process"]is True
            and m["actor_pid"]!=m["target_pid"]==pid,"mutation owner differs")
        trigger=(3,1)if case["mutation"]=="rename_parent"else(6,3)
        require((m["operation"],m["occurrence"])==trigger and m["before"]==row["before"]and m["after"]==row["after"],
            "actual barrier mutation snapshots differ")
        before=snapshots(m["before"],reader);after=snapshots(m["after"],reader);mutation(case,before,after)
        actual.append((before,after))
    counts={};last_call=0;last_sequence=0;changed=False
    initial_rows=row["before"];final_rows=row["after"];decoded=[]
    for e in events:
        raw=reader.get(e["raw"]);ack=reader.get(e["ack"])
        require(len(raw)==64 and raw[:8]==b"HBRDHK01"and U(raw,8)==generation
            and U(raw,16)>last_call and U(raw,24)>last_sequence and ack==bytes(8),"effect notification order/full bytes differ")
        last_call=U(raw,16);last_sequence=U(raw,24);op=U(raw,32)
        counts[op]=counts.get(op,0)+1
        require(op in(1,2,3,5,6,9,11,19)and e["operation"]==op and e["occurrence"]==counts[op],
            "effect occurrence differs")
        if case["mutation"]and(op,counts[op])==((3,1)if case["mutation"]=="rename_parent"else(6,3)):changed=True
        require(e["mutation"]==int(changed),"mutation was not applied at the exact bound operation")
        if op==6:
            st=e["fd_stat"];values=final_rows if changed else initial_rows
            matches=[v for v in values.values()if (v["dev"],v["inode"])==(st["dev"],st["inode"])]
            if matches:require(all(meta(v)==st for v in matches),"actual pre-fstat identity differs from full fixture")
            else:
                require(changed and case["mutation"]in("unlink","replace"),"fstat capability outside retained fixture")
                old=initial_rows["parent/data.bin"]
                require(all(st[k]==old[k]for k in META if k not in("links","ctime_ns"))and st["links"]==0
                    and st["ctime_ns"]>=old["ctime_ns"],"open unlinked inode identity differs")
        else:require("fd_stat"not in e,"unexpected descriptor observation")
        decoded.append(dict(e,raw_bytes=raw,ack_bytes=ack))
    require(changed==bool(case["mutation"]),"mutation notification absent")
    limit=saved["descriptor_limit"]
    if case["fd_limit"]:
        require(limit is not None and limit["before"]==limit["after"]and limit["during"][1]==limit["before"][1],
            "descriptor limit restoration differs")
        soft=limit["during"][0];free=[i for i in range(soft)if str(i)not in limit["fds"]]
        require(free==[limit["only_free_fd"]]==[soft-1],"operation was not tested with exactly one free FD")
        require(counts.get(3)==1,"one-FD domain opened extra files")
    else:require(limit is None,"undeclared resource limit")
    return decoded
def compare_view(row):
    value=row["result"]
    if not value["ok"]or not row["input"]["mutation"]:return value
    result=dict(value["value"]);q=row["input"]
    if "version"in result:
        require(result["version"]==q["initial_version"],"result version is not bound to the retained initial inode/stat")
        result["version"]="<initial-stat-version>"
    if "path"in result:
        require(result["path"]==q["request"]["path"],"result path does not preserve the exact input")
        result["path"]="<input-path>"
    return dict(ok=True,value=result,canonical=canonical(result)[:-1].decode())
def original_binding(source):
    path=source/"trusted-build/target/binary_file.py";module=ast.parse(path.read_bytes())
    fn=next(n for n in module.body if isinstance(n,ast.FunctionDef)and n.name=="main")
    selected=[n for n in ast.walk(fn)if isinstance(n,ast.If)and isinstance(n.test,ast.Compare)
        and isinstance(n.test.left,ast.Name)and n.test.left.id=="op"
        and any(isinstance(v,ast.Constant)and v.value=="private_read"for v in n.test.comparators)]
    require(len(selected)==1,"original private branch missing")
    return dict(original=pin(path),private_branch_ast_sha256=sha(ast.dump(ast.Module(body=selected[0].body,type_ignores=[]),
        include_attributes=False).encode()),private_branch_exact=True,original_function_fingerprint_unchanged=True)
