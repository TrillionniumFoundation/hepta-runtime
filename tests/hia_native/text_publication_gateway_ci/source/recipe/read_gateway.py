#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Compare complete retained gateway, file, cache, history and session observations."""
from pathlib import Path
import argparse
import ast
import gzip
import hashlib
import json
import stat
import struct
import sys
import types
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from common import canonical,decode,require,sha,pin
from buffer_store import Reader
from input_domain import declaration,rows
from helper_source import prepare
from qualification_support import native_observations,observations
Q=lambda *v:struct.pack("<"+"Q"*len(v),*v)
U=lambda raw,at:struct.unpack_from("<Q",raw,at)[0]

def retained_filesystem():
    path=Path(__file__).resolve().parents[1]/"retained/read_body.py"
    raw=path.read_bytes()
    require(sha(raw)=="27b039a9768c6b49a4f022ead65af16af1961edc961fedce2377b74b901f12d8","retained filesystem reader changed")
    parsed=ast.parse(raw);names={"fs_read","fs_projection"}
    selected=[n for n in parsed.body if isinstance(n,ast.FunctionDef) and n.name in names]
    require(len(selected)==2,"retained filesystem functions missing")
    ns=dict(Path=Path,require=require,stat=stat)
    exec(compile(ast.Module(body=selected,type_ignores=[]),str(path),"exec"),ns)
    return ns

def normalized_output(raw,row,after,content):
    require(raw[:8]==b"HRCFGM01" and len(raw)>=32 and U(raw,16)==0 and U(raw,24)==len(raw)-32,
        "complete gateway response extent/reserved fields")
    require(U(raw,8) in (0,1,2),"gateway response status")
    if row["kind"]!="call" or row.get("tool")!="text_file_write" or U(raw,8)!=0:return raw
    text=raw[32:].decode()
    value=decode(text)
    require(set(value)=={"bytes","external_writers_transactionally_excluded","mode","path","published",
        "same_path_atomic_publication","sha256","version","was_new_file"},"success field set")
    target=Path(value["path"])
    require(target.is_absolute(),"publisher target must be absolute")
    fixture=Path(row["_fixture"])
    name=target.relative_to(fixture).as_posix()
    item=next((r for r in after if r["path"]==name),None)
    require(item is not None and item["kind"]=="file","success target was not observed completely")
    data=content[name];info=item["stat"]
    version=":".join(str(x) for x in (info["dev"],info["ino"],info["size"],
        info["mtime_ns"]//1_000_000_000,info["mtime_ns"]%1_000_000_000,
        info["ctime_ns"]//1_000_000_000,info["ctime_ns"]%1_000_000_000))
    require(value["version"]==version,"all seven result version fields differ from actual file stat")
    require(value["bytes"]==len(data) and value["sha256"]==sha(data)
        and value["mode"]==row["parameters"]["mode"] and value["published"] is True
        and value["was_new_file"] is (row["parameters"]["mode"]=="create")
        and value["same_path_atomic_publication"] is True
        and value["external_writers_transactionally_excluded"] is False,"success fields differ from actual file effects")
    token='"version":"'+version+'"'
    require(text.count(token)==1,"unique exact version token")
    changed=text.replace(token,'"version":"<verified-actual-stat>"').encode()
    return raw[:24]+Q(len(changed))+changed

def read(capture):
    capture=Path(capture)
    require((capture/"DOMAIN.json").read_bytes()==canonical(declaration()),"full input domain changed")
    declared=[decode(line) for line in (capture/"cases.jsonl").read_bytes().splitlines()]
    meta=decode((capture/"CAPTURE.json").read_bytes())
    require(meta["status"]=="COMPLETE_GATEWAY_CAPTURE_ONLY","capture did not complete")
    require(declared==rows(meta["profile"],capture/"fixtures-root"),"input-only sequence differs")
    helpers=prepare(Path(__file__).resolve().parents[1]/"retained/text75_qualify.py")
    fs=retained_filesystem()
    all_rows={};readers={}
    for role in ("native","original"):
        lane=capture/role
        process=decode((lane/"PROCESS.json").read_bytes())
        require(process["exit_code"]==0 and process["timed_out"] is False and process["cleanup_error"] is None
            and process["expected_success"] is True and process["elapsed_seconds"]<180
            and process["timeout_seconds"]==180 and process["exchange_limit_seconds"]==60,"full process gate differs")
        require(process["stdin"]==pin(lane/"stdin") and process["stdout_gzip"]==pin(lane/"stdout.gz")
            and process["stderr"]==pin(lane/"stderr") and (lane/"stderr").read_bytes()==b"","complete process streams differ")
        with gzip.open(lane/"stdout.gz","rb") as stream:stdout=stream.read()
        require(process["full_stdout"]==dict(bytes=len(stdout),sha256=sha(stdout)),"full uncompressed process stdout differs")
        records=[decode(line) for line in (lane/"records.jsonl").read_bytes().splitlines()]
        report=decode((lane/"CAPTURE.json").read_bytes())
        require(report["role"]==role and report["completed"]==report["total"]==len(declared)
            and report["capture_completed"] is True,"complete capture case count differs")
        require(len(records)==len(declared),"case record omitted")
        buffers=Reader(lane/"buffers");readers[role]=buffers
        inputs=[];responses=[]
        for index,(row,record) in enumerate(zip(declared,records)):
            require(record["index"]==index and record["input"]==row and 0<=record["elapsed_ns"]<60_000_000_000,
                "ordered full case differs")
            require(record["fixture"]==str(capture/"fixtures-root"/row["fixture"]),"fixture path changed")
            inputs.append(buffers.get(record["request"]));responses.append(buffers.get(record["response"]))
            if role=="original":require(inputs[-1]==canonical(row),"actual original input differs")
        require((lane/"stdin").read_bytes()==b"".join(inputs) and stdout==b"".join(responses),"complete pipe coverage differs")
        all_rows[role]=(records,responses)
    compared=0;publisher_success=0
    for index,row in enumerate(declared):
        nr,nwire=all_rows["native"][0][index],all_rows["native"][1][index]
        rr,rwire=all_rows["original"][0][index],all_rows["original"][1][index]
        complete={}
        for role,record in (("native",nr),("original",rr)):
            before,blinks=fs["fs_read"](record["before"],readers[role])
            after,alinks=fs["fs_read"](record["after"],readers[role])
            complete[role]=(fs["fs_projection"](record["before"],before,blinks),
                fs["fs_projection"](record["after"],after,alinks),after)
            require(not any(x["path"].split("/")[-1].startswith(".hepta-text-") for x in record["after"]),
                "generated publisher temporary file remained")
        require(complete["native"][:2]==complete["original"][:2],("complete filesystem comparison",row["id"]))
        native=helpers.decode_records(nwire);expected=decode(rwire)
        require(len(native)==4 and expected["id"]==row["id"] and expected["session"]==row["session"],
            "complete response and observer records")
        primary=native[0];wanted=bytes.fromhex(expected["output_hex"]);actual=primary["output"]
        require(primary["session"]==row["session"] and primary["slot"]==(64 if row.get("tool")=="text_file_write" else 37 if row["kind"]=="call" else 32)
            and primary["code"]==expected["code"],("actual gateway slot/return",row["id"]))
        if row["kind"]=="call":
            tag=dict(row,_fixture=nr["fixture"])
            left=normalized_output(actual,tag,nr["after"],complete["native"][2])
            right=normalized_output(wanted,tag,rr["after"],complete["original"][2])
            publisher_success+=int(row.get("tool")=="text_file_write" and U(actual,8)==0)
            require(left==right,("complete gateway result",row["id"],actual[:512],wanted[:512]))
        else:require(actual==wanted,("complete direct cache response",row["id"]))
        require(expected["scope_unbound_after_call"] is True and expected["live_session_arcs"]==[1,1],
            "actual original Scope or session cache lifetime differs")
        for sid in (0,1):
            record=native[1+sid];require(record["session"]==sid,"session observer routing")
            cache,observation=helpers.canonical_snapshot(record)
            require(cache==bytes.fromhex(expected["cache_snapshots_hex"][sid]),("complete session cache",row["id"],sid))
            require(observation["session_state"]==expected["sessions"][sid],("complete session state",row["id"],sid))
            compared+=len(record["output"])+len(cache)
        shared=native[3];state=shared["output"]
        require(shared["slot"]==41 and shared["code"]==0 and state[:8]==b"HLTBSH01" and U(state,24) in (0,1,2),"shared observer framing")
        ln,hn=U(state,8),U(state,16);require(len(state)==32+ln+hn,"shared complete extent")
        locks=native_observations.locks(state[32:32+ln],1,index+1)
        history=native_observations.history(state[32+ln:],1,index+1)
        require(locks==observations.locks(bytes.fromhex(expected["lock_snapshot_hex"])),("complete locks",row["id"]))
        require(history==observations.history(bytes.fromhex(expected["history_snapshot_hex"])),("complete history",row["id"]))
        compared+=len(state)+len(actual)+len(wanted)
    retired=decode((capture/"RETIRED_FIXTURE.json").read_bytes())
    require(retired["root"]==str(capture/"fixtures-root") and retired["captured_before_retirement"] is True
        and retired["case_buffers_preserved"] is True and not (capture/"fixtures-root").exists(),
        "owned fixture retirement provenance differs")
    retained=Reader(capture/"retired-fixture-buffers")
    fs["fs_read"](retired["complete_snapshot"],retained)
    retirement=retained.finish()
    stats={role:reader.finish() for role,reader in readers.items()}
    stats["retired_fixture"]=retirement
    return dict(status="COMPLETE_SERIAL_GATEWAY_STATE_FILES_COMPARISON_PASS",profile=meta["profile"],
        cases=len(declared),publisher_successes=publisher_success,complete_compared_record_bytes=compared,
        buffers=stats,actual_sdk_context=True,actual_scope=True,actual_cache_forget=True,
        shared_history_and_locks_observed=True,source_graph_images=116,public_route=False,
        full_async=False,full_sdk=False,production_installed=False)

def main():
    p=argparse.ArgumentParser();p.add_argument("--capture",required=True,type=Path)
    a=p.parse_args();print(json.dumps(read(a.capture),sort_keys=True))
if __name__=="__main__":main()
