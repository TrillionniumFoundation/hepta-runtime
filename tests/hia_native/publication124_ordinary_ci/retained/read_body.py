#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Full existing body buffers/effects/filesystem/original comparison; zero execution."""
from pathlib import Path
import hashlib
import os
import stat
import struct
from common import canonical, decode, owned, pin, require, sha, source_evidence
from body_cases import cases, request, domain
from buffer_store import Reader
from private_controls import definitions
from read_build import build_evidence

MASK=(1<<64)-1
word=lambda raw,at:struct.unpack_from("<Q",raw,at)[0]

def initial(value):
    path=value["path"].encode();content=value["content"].encode();expected=value["expected_sha256"].encode()
    return b"HTPBQ001"+struct.pack("<7Q",1,0,{"create":1,"replace":2,"append":3}[value["mode"]],
        len(path),len(content),len(expected),len(path)+len(content)+len(expected))+path+content+expected

def reply(seq,code,data):
    return b"HTPBQ001"+struct.pack("<7Q",2,seq,code,0,0,0,len(data))+data

def fs_read(rows,buffers):
    require(rows and rows[0]["path"]==".","filesystem snapshot root missing")
    seen=set();content={};groups={}
    for row in rows:
        name=row["path"];require(name not in seen,"duplicate filesystem item");seen.add(name)
        require(name=="." or not Path(name).is_absolute() and ".." not in Path(name).parts,"filesystem path invalid")
        info=row["stat"];mode=info["mode"]
        require(set(info)=={"mode","dev","ino","nlink","uid","gid","size","atime_ns","mtime_ns","ctime_ns"},"stat fields omitted")
        require(all(type(x) is int for x in info.values()),"stat fields not exact integers")
        require(type(row["xattrs"]) is dict and all(type(k) is str for k in row["xattrs"]),"xattrs omitted")
        for value in row["xattrs"].values():bytes.fromhex(value)
        if row["kind"]=="file":
            require(stat.S_ISREG(mode),"regular file stat differs")
            raw=buffers.get(row["data"])
            require(len(raw)==info["size"],"complete file extent differs")
            content[name]=raw;groups.setdefault((info["dev"],info["ino"]),[]).append(name)
        elif row["kind"]=="dir":
            require(stat.S_ISDIR(mode) and row["entries"]==sorted(set(row["entries"])),"directory shape differs")
        else:
            require(row["kind"]=="symlink" and stat.S_ISLNK(mode) and type(row["target"]) is str,"symlink snapshot differs")
    for row in rows:
        if row["kind"]=="dir":
            prefix="" if row["path"]=="." else row["path"]+"/"
            actual=sorted(name[len(prefix):] for name in seen if name!="." and name.startswith(prefix) and "/" not in name[len(prefix):])
            require(actual==row["entries"],"directory complete entry set differs")
    return content,sorted(sorted(names) for names in groups.values())

def fs_projection(rows,content,groups):
    return dict(rows=[dict(path=r["path"],kind=r["kind"],
        mode=r["stat"]["mode"],uid=r["stat"]["uid"],gid=r["stat"]["gid"],
        nlink=r["stat"]["nlink"] if r["kind"]!="dir" else None,
        size=r["stat"]["size"] if r["kind"]=="file" else None,
        xattrs=r["xattrs"],entries=r.get("entries"),target=r.get("target"),
        data=content[r["path"]].hex() if r["kind"]=="file" else None) for r in rows],links=groups)

def result_projection(row,after,content):
    result=row["result"];value=row["request"]
    require(set(result)=={"id","ok","text"} and result["id"]==value["id"] and type(result["ok"]) is bool
        and type(result["text"]) is str,"complete result envelope differs")
    if not result["ok"]:
        return result
    data=decode(result["text"])
    require(set(data)=={"bytes","external_writers_transactionally_excluded","mode","path","published",
        "same_path_atomic_publication","sha256","version","was_new_file"},"complete success fields differ")
    path=Path(value["path"]).relative_to(Path(row["fixture"])).as_posix()
    actual=next(r for r in after if r["path"]==path)
    require(actual["kind"]=="file","success did not produce a regular target")
    raw=content[path];info=actual["stat"]
    version=":".join(str(x) for x in (info["dev"],info["ino"],info["size"],
        info["mtime_ns"]//1_000_000_000,info["mtime_ns"]%1_000_000_000,
        info["ctime_ns"]//1_000_000_000,info["ctime_ns"]%1_000_000_000))
    require(data["version"]==version,"returned full version differs from actual stat")
    require(data["bytes"]==len(raw) and data["sha256"]==sha(raw) and data["path"]==value["path"]
        and data["mode"]==value["mode"] and data["published"] is True
        and data["was_new_file"] is (value["mode"]=="create")
        and data["same_path_atomic_publication"] is True and data["external_writers_transactionally_excluded"] is False,
        "actual publication body result differs from observed file")
    # The only nondeterministic result field is first verified, then replaced as raw text.
    token='"version":"'+version+'"'
    require(result["text"].count(token)==1,"version wire token ambiguous")
    return dict(result,text=result["text"].replace(token,'"version":"<verified-actual-stat>"'))

def lane_rows(source,output,role):
    root=output/role;summary=decode(owned(root,"capture.json").read_bytes())
    require(summary["status"]=="COMPLETE_PRIVATE_BODY_CAPTURE" and summary["role"]==role
        and summary["source"]==source_evidence(source) and summary["original_output_read_by_native"] is False,
        "actual capture status/source differs")
    require(owned(root,"DOMAIN.json").read_bytes()==canonical(domain()),"whole input domain changed")
    declared=[decode(line) for line in owned(root,"cases.jsonl").read_bytes().splitlines()]
    require(len(declared)==len(cases())==summary["cases"],"body case omitted")
    buffers=Reader(root/"buffers")
    projected=[];wires=[]
    for case,row in zip(cases(),declared):
        require((row["id"],row["name"])==(case["id"],case["name"]),"body case order changed")
        require(row["request"]==request(case,row["fixture"]),"body input changed")
        require(type(row["elapsed_ns"]) is int and 0<=row["elapsed_ns"]<60_000_000_000,"body exchange limit changed")
        before,before_links=fs_read(row["before"],buffers);after,after_links=fs_read(row["after"],buffers)
        wire=buffers.get(row["response"]);wires.append(wire)
        require(decode(wire)==row["result"] and wire==canonical(row["result"]),"whole body wire differs")
        normalized=result_projection(row,row["after"],after)
        projected.append(dict(input=row["request"],before=fs_projection(row["before"],before,before_links),
            after=fs_projection(row["after"],after,after_links),result=normalized))
        require(not any(r["path"].split("/")[-1].startswith(".hepta-text-") for r in row["after"]),
            "generated staging name remained")
    require(owned(root,"wire.jsonl").read_bytes()==b"".join(wires),"complete output stream changed")
    if role=="original":
        process=decode(owned(root,"original-process.json").read_bytes())
        binary=owned(output,"rust-target/debug/hepta-text-publication-body-original")
        require(process["binary"]==pin(binary) and process["returncode"]==0 and process["same_outer_process_group"] is True,
            "actual original process/binary changed")
        for suffix in ("stdin","stdout","stderr"):
            require(process["streams"][suffix]==pin(owned(root,"original."+suffix)),"complete original pipe bytes changed")
        require(owned(root,"original.stdin").read_bytes()==b"".join(canonical(r["request"]) for r in declared)
            and owned(root,"original.stdout").read_bytes()==b"".join(wires)
            and owned(root,"original.stderr").read_bytes()==b"","original actual pipe sequence changed")
    return root,summary,declared,buffers,projected

def native_physical(root,summary,declared,buffers):
    effects=[decode(line) for line in owned(root,"effects.jsonl").read_bytes().splitlines()]
    require(len(effects)==summary["effects"],"OS/child action omitted")
    by_call={r["body_call"]:r for r in effects}
    require(len(by_call)==len(effects) and [r["effect"] for r in effects]==list(range(1,len(effects)+1)),
        "action duplicated/reordered")
    controls=decode(owned(root,"controls.json").read_bytes())
    require(len(controls)==len(definitions()),"private controls omitted")
    control_calls={}
    for defined,record in zip(definitions(),controls):
        require(record["definition"]==defined and record["name"]==defined["name"],"private control changed")
        require(record["call"] not in control_calls,"private control duplicate")
        control_calls[record["call"]]=defined
    rows_by_case={r["id"]:r for r in declared}
    state={};used_effects=set();seen_controls=set();completed=set();count=0
    pending_child=None
    with owned(root,"calls.jsonl").open("rb") as stream:
        for line in stream:
            row=decode(line);count+=1
            require(row["call"]==count and row["owner"] in ("body","codec"),"native call sequence changed")
            wire=buffers.get(row["input"]);before=buffers.get(row["workspace_before"])
            old=buffers.get(row["output_before"]);out=buffers.get(row["output"]);after=buffers.get(row["workspace_after"])
            require(len(before)==len(after) and len(old)==len(out) and old==b"\xa5"*len(out),"complete native buffers differ")
            addresses=row["addresses"];oa=addresses["output"];wa=addresses["workspace"]
            require(type(oa) is type(wa) is int and oa>0 and wa>0
                and (oa+len(out)+16<=wa or wa+len(after)+16<=oa),"native owned buffers overlap")
            require(type(row["elapsed_ns"]) is int and 0<=row["elapsed_ns"]<60_000_000_000,"native call elapsed bound")
            code=row["return_code"]
            if count in control_calls:
                require(pending_child is None and row["owner"]=="body" and row["case_id"]<0,"private control call identity")
                case=control_calls[count];seen_controls.add(count)
                require(wire==bytes.fromhex(case["wire"]) and len(out)==case["ocap"] and len(after)==case["wcap"]
                    and before==after==bytes(len(after)) and code==case["code"],"full private control buffers differ")
                if case["kind"] is None:
                    require(out==old,"refused call modified output")
                else:
                    require(out[:8]==b"HTPBS001" and word(out,8)==4 and out[16:32]==bytes(16) and out[40:]==bytes(24)
                        and word(out,32)>len(before),"growth private control differs")
                continue
            cid=row["case_id"]
            require(cid in rows_by_case and cid not in completed,"call belongs to omitted/completed case")
            declaration=rows_by_case[cid]
            require(declaration["chain"]["first_call"]<=count<=declaration["chain"]["last_call"],"native call outside case extent")
            if row["owner"]=="codec":
                require(pending_child is not None,"unrequested SHA child call")
                event,payload,op=pending_child
                require(event["case_id"]==cid and event["child_call"]==count and wire==payload
                    and before==bytes(1184) and len(out)==128,"actual SHA child request/buffer differs")
                require(code==event["return_code"]== (64 if op==6 else 128)
                    and out[code:]==b"\xa5"*(128-code),"SHA child complete response/tail differs")
                data=buffers.get(event["reply"])
                require(data==out[:code],"parent did not borrow actual SHA output")
                current=state[cid]
                if op==3:
                    current["hash"]=hashlib.sha256()
                elif op==4:
                    require(wire[24:152]==current["codec_state"],"SHA state continuation changed")
                    current["hash"].update(wire[152:])
                else:
                    require(wire[24:]==current["codec_state"] and data==current["hash"].hexdigest().encode(),
                        "actual HIA digest differs from complete input bytes")
                if op in (3,4):current["codec_state"]=data
                current["wire"]=reply(event["sequence"],code,data)
                pending_child=None
                continue
            require(pending_child is None,"parent resumed before actual SHA child")
            if cid not in state:
                require(count==declaration["chain"]["first_call"] and before==bytes(4096) and len(out)==64,
                    "first body call capacities/state differ")
                state[cid]=dict(wire=initial(declaration["request"]),after=before,ocap=64,wcap=4096,
                    seq=0,live=set())
            current=state[cid]
            require(wire==current["wire"] and len(before)==current["wcap"] and len(out)==current["ocap"]
                and before==current["after"]+bytes(len(before)-len(current["after"])),
                "body retained state/input/growth changed")
            require(code==64 and out[:8]==b"HTPBS001","body frame differs")
            kind,seq,op,a,b,c,size=struct.unpack_from("<7Q",out,8)
            require(size<=len(out)-64 and out[64+size:]==b"\xa5"*(len(out)-64-size),"body output suffix changed")
            current["after"]=after
            if kind in (4,5):
                require(seq==op==b==c==size==0 and a>len(before if kind==4 else out),"growth admission differs")
                current["wcap" if kind==4 else "ocap"]=a
                require(a<=(256<<20 if kind==4 else 128<<20),"growth profile overflow")
                continue
            if kind in (0,3):
                require(op==a==b==c==0 and seq==current["seq"] and not current["live"],"completion has pending resources")
                require(dict(id=cid,ok=kind==0,text=out[64:64+size].decode())==declaration["result"]
                    and count==declaration["chain"]["last_call"] and seq==declaration["chain"]["last_sequence"],
                    "complete HIA result differs from observed wire")
                completed.add(cid);del state[cid];continue
            require(kind in (1,2) and seq==current["seq"]+1 and count in by_call,"missing actual emitted action")
            current["seq"]=seq;event=by_call[count];used_effects.add(count)
            require((event["case_id"],event["kind"],event["sequence"],event["operation"],event["a"],event["b"],event["c"])
                ==(cid,kind,seq,op,a,b,c),"emitted action declaration differs")
            payload=buffers.get(event["payload"])
            require(payload==out[64:64+size],"complete HIA action span changed")
            if kind==2:
                require(op in (3,4,6) and (a,b,c)==(0,0,0) and payload[:8]==b"HRCODEC1"
                    and word(payload,8)==op and word(payload,16)==0,"SHA action header changed")
                require(len(payload)==24 if op==3 else len(payload)==152 if op==6 else 152<=len(payload)<=152+1048576,
                    "SHA complete request length changed")
                pending_child=(event,payload,op)
                continue
            require(1<=op<=18,"unknown actual OS effect")
            reply_data=buffers.get(event["reply"]);rc=event["return_code"];osrow=event["os"]
            require(type(osrow["libc_return"]) is int and type(osrow["errno"]) is int
                and rc==((-osrow["errno"] if osrow["libc_return"]<0 else osrow["libc_return"])&MASK),
                "OS errno return conversion changed")
            success=rc<(1<<63)
            if op in (2,3,4,5,6,7,8,10,11,13,14,15,16,17):
                require(a in current["live"],"OS operation borrowed an unowned fd")
            if op in (1,2,3,4) and success:
                require(rc not in current["live"],"OS fd duplicated");current["live"].add(rc)
            if op==5 and success:current["live"].remove(a)
            require(sorted(current["live"])==osrow["live_fds"],"OS fd ownership record differs")
            if op in (6,7):
                require(len(reply_data)==(144 if success else 0),"stat complete byte count differs")
            elif op in (11,12,18):
                require(len(reply_data)==(rc if success else 0),"read/random/error complete bytes differ")
                if op==11:require(not success or rc<=b,"read exceeds actual requested count")
                if op==12:require(not success or rc<=a,"random exceeds actual requested count")
                if op==18:require(reply_data==(os.strerror(a)+" (os error "+str(a)+")").encode(),"platform errno text differs")
            else:
                require(reply_data==b"","OS non-data action returned bytes")
            if op==14:require(b==len(payload) and (not success or rc<=b),"write full span/return differs")
            if op==16:require(b in (0,1) and payload[:c].endswith(b"\0") and payload[c:].endswith(b"\0"),"rename name extents differ")
            current["wire"]=reply(seq,rc,reply_data)
    require(count==summary["body_calls"] and used_effects==set(by_call) and seen_controls==set(control_calls)
        and completed==set(rows_by_case) and not state and pending_child is None,
        "incomplete native call/action/control closure")
    return dict(native_calls=count,actions=len(effects),controls=len(controls),cases=len(completed))

def compare(source,output):
    source=Path(source);output=Path(output)
    build=build_evidence(source,output)
    native=lane_rows(source,output,"native")
    original=lane_rows(source,output,"original")
    physical=native_physical(native[0],native[1],native[2],native[3])
    require(native[4]==original[4],"full original/native body result or filesystem effect differs")
    nr=native[3].finish();orr=original[3].finish()
    for lane,counter in ((native,nr),(original,orr)):
        require(counter["complete_images"]==lane[1]["complete_buffer_images"]
            and counter["logical_buffer_bytes"]==lane[1]["logical_buffer_bytes"],"complete retained buffer count differs")
    return dict(status="COMPLETE_PRIVATE_BODY_ORIGINAL_AND_FILES_PASS",cases=len(cases()),
        physical=physical,native_buffers=nr,original_buffers=orr,build=build,
        source=source_evidence(source),version_normalization="only after all seven actual stat fields are verified",
        all_other_response_and_file_bytes_equal=True)
