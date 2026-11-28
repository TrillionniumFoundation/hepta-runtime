#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Read complete public wire and owned effects; never execute either implementation."""
from pathlib import Path
import argparse
import gzip
import importlib.util
import json
import struct
import sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"recipe"));sys.path.insert(0,str(ROOT))
from common import canonical,decode,require,sha,pin
from buffer_store import Reader
from public_domain import rows,stdio_rows,declaration
from helper_source import prepare
from read_private_trace import read as read_trace
from qualification_support import native_observations,observations
spec=importlib.util.spec_from_file_location("retained_publisher_result_reader",ROOT/"retained/read_gateway.py")
old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
Q=lambda *v:struct.pack("<"+"Q"*len(v),*v)
U=lambda raw,at:struct.unpack_from("<Q",raw,at)[0]

def native_command(row):
    raw=bytes.fromhex(row["wire_hex"])
    if row["kind"]=="wire":
        require(raw.endswith(b"\n"),"public line terminator")
        raw=raw[:-1];slot=34
    else:
        require(row["kind"]=="cache","declared cache command")
        slot=32
    return b"HFSFXQ02"+Q(row["session"],slot,len(raw))+raw+b"".join(
        b"HFSFXQ02"+Q(sid,33,0) for sid in (0,1))+b"HFSFXQ02"+Q(0,41,0)

def original_command(row):
    value=dict(id=row["id"],kind=row["kind"],session=row["session"],wire_hex=row["wire_hex"])
    if row["kind"]=="wire":value["response"]=row["response"]
    return canonical(value)

def native_response(raw,row,helpers):
    if row["kind"]=="cache":
        records=helpers.decode_records(raw)
        require(len(records)==4,"complete cache/observer records")
        primary=records[0]
        require(primary["session"]==row["session"] and primary["slot"]==32 and primary["code"]==len(primary["output"]),
            "actual cache callback descriptor")
        return primary["output"],records[1:]
    require(len(raw)>=96 and raw[:8]==b"HFSJPR03","actual public carrier framing")
    require(U(raw,8)==row["session"] and U(raw,16) in (0,1,2,3) and U(raw,24)==0
        and raw[80:96]==bytes(16),"actual public carrier disposition/reserved fields")
    kind=U(raw,16)
    if kind:
        end=raw.find(b"\n",96)
        require(end>=96,"complete native public wire line")
        wire=raw[96:end+1];remaining=raw[end+1:]
    else:wire=b"";remaining=raw[96:]
    require(bool(wire)==row["response"],"public response/notification disposition")
    observers=helpers.decode_records(remaining)
    require(len(observers)==3,"complete public session/shared observer frames")
    return wire,observers

def normalized_wire(wire,row,after,content,fixture):
    if not wire:return wire,False
    require(wire.endswith(b"\n") and wire.count(b"\n")==1,"single complete SDK response line")
    result=decode(wire)
    require(isinstance(result,dict) and result.get("jsonrpc")=="2.0"
        and ("result" in result)^("error" in result),"complete JSON-RPC response")
    if row.get("tool")!="text_file_write" or "result" not in result:return wire,False
    body=result["result"]
    require(isinstance(body,dict),"typed SDK CallTool result")
    if body.get("isError",False):return wire,False
    blocks=body.get("content")
    require(isinstance(blocks,list) and len(blocks)==1 and blocks[0].get("type")=="text"
        and isinstance(blocks[0].get("text"),str),"actual publisher success content")
    text=blocks[0]["text"].encode()
    params=row["parameters"]
    require(isinstance(params,dict),"successful publisher has typed object arguments")
    tag=dict(kind="call",tool="text_file_write",parameters=params,_fixture=fixture)
    framed=b"HRCFGM01"+Q(0,0,len(text))+text
    changed=old.normalized_output(framed,tag,after,content)
    require(changed!=framed,"verified publication stat normalization did not occur")
    value=decode(text);version=value["version"]
    # The original exact reader first binds all seven stat fields to this run's file.
    # Only that unique token inside the already encoded SDK content string may differ.
    token=('\\"version\\":\\"'+version+'\\"').encode()
    require(wire.count(token)==1,"unique encoded publisher version token")
    return wire.replace(token,b'\\"version\\":\\"<verified-actual-stat>\\"'),True

def process(capture,role,declared,fixture_root,mode,dependencies):
    lane=capture/role;receipt=decode((lane/"PROCESS.json").read_bytes())
    require(receipt["exit_code"]==0 and receipt["timed_out"] is False
        and receipt["cleanup_error"] is None and receipt["expected_success"] is True
        and receipt["elapsed_seconds"]<180 and receipt["timeout_seconds"]==180
        and receipt["exchange_limit_seconds"]==60,"complete actual process/EOF gate")
    require(receipt["stdin"]==pin(lane/"stdin") and receipt["stdout_gzip"]==pin(lane/"stdout.gz")
        and receipt["stderr"]==pin(lane/"stderr") and receipt["cwd"]==str(fixture_root),
        "actual complete streams or fixture identity")
    diagnostic=(lane/"stderr").read_bytes()
    if role=="original":require(not diagnostic,"original public stderr")
    elif diagnostic:read_trace(diagnostic)
    with gzip.open(lane/"stdout.gz","rb") as stream:stdout=stream.read()
    require(receipt["full_stdout"]==dict(bytes=len(stdout),sha256=sha(stdout)),"complete inflated stdout")
    records=[decode(line) for line in (lane/"records.jsonl").read_bytes().splitlines()]
    report=decode((lane/"CAPTURE.json").read_bytes())
    require(report["role"]==role and report["mode"]==mode and report["completed"]==report["total"]==len(declared)
        and report["capture_completed"] is True and report["source_dependencies"]==dependencies,
        "whole public capture and dependency binding")
    require(report["native_binary"]==dependencies[mode+"_binary_pin"]
        and report["original_binary"]==dependencies["original_binary_pin"]
        and report["per_exchange_seconds"]==60 and report["per_process_seconds"]==180,
        "actual executable identity or limits")
    require(len(records)==len(declared),"omitted public case")
    buffers=Reader(lane/"buffers");ins=[];outs=[]
    for index,(row,record) in enumerate(zip(declared,records)):
        require(record["index"]==index and record["input"]==row and 0<=record["elapsed_ns"]<60_000_000_000
            and record["fixture"]==str(fixture_root/row["fixture"]),"ordered public row/capacity")
        incoming=buffers.get(record["request"]);outgoing=buffers.get(record["response"])
        expected=bytes.fromhex(row["wire_hex"]) if mode=="stdio" else (
            native_command(row) if role=="native" else original_command(row))
        require(incoming==expected,"complete original/native input line")
        ins.append(incoming);outs.append(outgoing)
    require((lane/"stdin").read_bytes()==b"".join(ins) and stdout==b"".join(outs),
        "complete pipe byte coverage including no-response notifications")
    return records,outs,buffers,receipt

def read(capture):
    capture=Path(capture)
    require((capture/"DOMAIN.json").read_bytes()==canonical(declaration()),"complete frozen public domain")
    meta=decode((capture/"CAPTURE.json").read_bytes())
    require(meta["status"]=="COMPLETE_PUBLIC_PUBLISHER_CAPTURE_ONLY","public capture incomplete")
    mode,profile,era=(meta[k] for k in ("mode","profile","era"))
    require(mode in ("carrier","stdio"),"declared entry kind")
    retired=decode((capture/"RETIRED_FIXTURE.json").read_bytes())
    fixture_root=Path(retired["root"])
    require(fixture_root.is_absolute() and fixture_root.name=="fixtures-root","owned fixture identity")
    declared=[decode(line) for line in (capture/"cases.jsonl").read_bytes().splitlines()]
    wanted=rows(profile,fixture_root,era) if mode=="carrier" else stdio_rows(fixture_root,era)
    require(declared==wanted and meta["cases"]==len(wanted),"complete frozen public sequence")
    deps=decode((capture/"DEPENDENCIES.json").read_bytes())
    from dependencies import verify_receipt
    verify_receipt(deps)
    configured=profile!="absent"
    if configured:
        config=decode((capture/"config.json").read_bytes())
        require(config==dict(state_dir=str(fixture_root.parent/"controller-state"),
            controller_workspace_roots=[] if profile=="denied" else [str(fixture_root)],
            hosts={"fixture":dict(ssh_target="uncontacted-gateway-reference",remote_state_dir="/unused-runtime-state",
                allow_write=True,allowed_read_path_prefixes=["/allowed"],allowed_write_path_prefixes=["/allowed"],
                protected_path_prefixes=["/allowed/protected"])}),"actual configuration bytes")
    else:require(not (capture/"config.json").exists(),"absent configuration became present")
    helpers=prepare(ROOT/"retained/text75_qualify.py")
    fs=old.retained_filesystem()
    captured={role:process(capture,role,declared,fixture_root,mode,deps) for role in ("native","original")}
    for role in ("native","original"):
        receipt=captured[role][3]
        exe=deps["original_binary"] if role=="original" else deps["filesystem_binary" if mode=="carrier" else "public_binary"]
        expected=[exe]
        if role=="original" and mode=="stdio":expected+=["--stdio"]
        if configured:expected+=(["--runtime-config",str(capture/"config.json")] if role=="native" else [str(capture/"config.json")])
        # Relocation changes only the containing evidence path, never the retained
        # actual invocation strings or the complete input fixture identity.
        original_capture=fixture_root.parent
        expected=[str(original_capture/"config.json") if x==str(capture/"config.json") else x for x in expected]
        require(receipt["command"]==expected,"actual fixed executable command")
    publisher_success=0;wire_bytes=0;observer_bytes=0;responses=0
    for index,row in enumerate(declared):
        nr,nraw=captured["native"][0][index],captured["native"][1][index]
        rr,rraw=captured["original"][0][index],captured["original"][1][index]
        complete={}
        for role,record in (("native",nr),("original",rr)):
            before,blinks=fs["fs_read"](record["before"],captured[role][2])
            after,alinks=fs["fs_read"](record["after"],captured[role][2])
            complete[role]=(fs["fs_projection"](record["before"],before,blinks),
                fs["fs_projection"](record["after"],after,alinks),after)
            require(not any(x["path"].split("/")[-1].startswith(".hepta-text-") for x in record["after"]),
                "publication staging file remained")
        require(complete["native"][:2]==complete["original"][:2],
            ("complete files, contents, metadata and link comparison",row["id"]))
        if mode=="stdio":
            nwire,rwire=nraw,rraw
            require(bool(nwire)==bool(rwire)==row["response"],"actual stdio notification response")
        else:
            nwire,observers=native_response(nraw,row,helpers)
            original=decode(rraw)
            require(set(original)=={"id","session","kind","output_hex","cache_snapshots_hex","sessions",
                "scope_unbound_after_exchange","closed_sessions","history_snapshot_hex","lock_snapshot_hex"}
                and original["id"]==row["id"] and original["session"]==row["session"]
                and original["kind"]==row["kind"],"complete SDK observer response identity")
            rwire=bytes.fromhex(original["output_hex"])
            require(original["scope_unbound_after_exchange"] is True
                and original["closed_sessions"]==[False,False],"actual Scope/connection state after exchange")
            if row["kind"]=="wire":
                require(bool(rwire)==row["response"],"actual SDK response disposition")
            for sid in (0,1):
                item=observers[sid]
                require(item["session"]==sid and item["slot"]==33,"session observer child routing")
                cache,state=helpers.canonical_snapshot(item)
                require(cache==bytes.fromhex(original["cache_snapshots_hex"][sid]),
                    ("complete actual session cache",row["id"],sid))
                require(state["session_state"]==original["sessions"][sid],
                    ("complete actual session state",row["id"],sid))
                observer_bytes+=len(item["output"])+len(cache)
            shared=observers[2];state=shared["output"]
            require(shared["slot"]==41 and shared["code"]==0 and state[:8]==b"HLTBSH01"
                and U(state,24) in (0,1,2),"shared lock/history observer framing")
            ln,hn=U(state,8),U(state,16)
            require(len(state)==32+ln+hn,"complete shared state extent")
            locks=native_observations.locks(state[32:32+ln],1,index+1)
            history=native_observations.history(state[32+ln:],1,index+1)
            require(locks==observations.locks(bytes.fromhex(original["lock_snapshot_hex"])),
                ("complete actual shared locks",row["id"]))
            require(history==observations.history(bytes.fromhex(original["history_snapshot_hex"])),
                ("complete actual shared history",row["id"]))
            observer_bytes+=len(state)
        if row["kind"]=="cache":
            require(nwire==rwire,("complete actual cache seed/get reply",row["id"]))
        else:
            left,success=normalized_wire(nwire,row,nr["after"],complete["native"][2],nr["fixture"])
            right,other=normalized_wire(rwire,row,rr["after"],complete["original"][2],rr["fixture"])
            require(success==other and left==right,("whole SDK public response",row["id"],nwire[:1024],rwire[:1024]))
            publisher_success+=int(success);responses+=int(bool(nwire))
        wire_bytes+=len(nwire)+len(rwire)
    require(retired["root"]==str(fixture_root) and retired["captured_before_retirement"] is True
        and retired["case_buffers_preserved"] is True and not (capture/"fixtures-root").exists(),
        "complete fixture retirement provenance")
    retained=Reader(capture/"retired-fixture-buffers")
    fs["fs_read"](retired["complete_snapshot"],retained)
    buffers={role:captured[role][2].finish() for role in ("native","original")}
    buffers["retired_fixture"]=retained.finish()
    return dict(status="COMPLETE_SERIAL_PUBLIC_PUBLISHER_WIRE_AND_EFFECTS_PASS",
        mode=mode,profile=profile,era=era,cases=len(declared),responses=responses,
        publisher_successes=publisher_success,complete_compared_wire_bytes=wire_bytes,
        complete_compared_observer_bytes=observer_bytes,buffers=buffers,
        actual_sdk_serve=True,actual_tool_call_context=True,actual_async_method_adapter=True,
        actual_scope_cache_history_locks_observed=mode=="carrier",actual_public_stdio=mode=="stdio",
        graph_hia_images=123,physical_images=116,public_route_domain_only=True,
        full_async=False,full_sdk=False,all_136_handlers=False,production_installed=False)

def main():
    p=argparse.ArgumentParser();p.add_argument("--capture",required=True,type=Path)
    a=p.parse_args();print(json.dumps(read(a.capture),sort_keys=True))
if __name__=="__main__":main()
