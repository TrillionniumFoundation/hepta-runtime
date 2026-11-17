#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Read every actual command, response, owned wait and retained filesystem byte."""
from pathlib import Path
import gzip,json,stat,struct
from common import canonical,decode,pin,require,sha
from buffer_store import Reader
from input_domain import cases,declaration
from dependency import declaration as dependency
U=lambda raw,at:struct.unpack_from("<Q",raw,at)[0]

def full_hex(value):
    require(type(value) is str and len(value)%2==0,"complete hex type/extent")
    raw=bytes.fromhex(value)
    require(raw.hex()==value,"canonical complete hex")
    return raw

def utf(raw):
    return raw.decode("utf-8",errors="strict")

def cache(raw):
    require(len(raw)>=48 and raw[:8]==b"HLCSCS01" and U(raw,8)==len(raw)
        and U(raw,16)==1 and U(raw,24) in (0,1) and U(raw,40)==len(raw)-48,"complete cache frame")
    at=48;rows=[]
    for _ in range(U(raw,32)):
        require(at+16<=len(raw),"cache entry header")
        kn,vn=U(raw,at),U(raw,at+8);at+=16
        require(kn+vn<=len(raw)-at,"cache complete spans")
        rows.append((utf(raw[at:at+kn]),utf(raw[at+kn:at+kn+vn])));at+=kn+vn
    require(at==len(raw) and [k for k,_ in rows]==sorted({k for k,_ in rows},key=lambda k:k.encode()),"cache full sorted set")
    return dict(poisoned=bool(U(raw,24)),entries=rows)

def history(raw,sequence):
    require(len(raw)>=80 and raw[:8]==b"HLTBHS01" and U(raw,8)==len(raw)
        and U(raw,16)==1 and U(raw,24)==sequence+1 and U(raw,32) in (0,1)
        and U(raw,72)==len(raw)-80,"complete history frame")
    at=80;keys=[];count=0;total=0
    for _ in range(U(raw,40)):
        require(at+16<=len(raw),"history key header")
        kn,n=U(raw,at),U(raw,at+8);at+=16
        require(kn<=len(raw)-at,"history key extent")
        key=utf(raw[at:at+kn]);at+=kn;keys.append(key)
        for _ in range(n):
            require(at+8<=len(raw),"history value header")
            vn=U(raw,at);at+=8
            require(vn<=len(raw)-at,"history complete value")
            utf(raw[at:at+vn]);at+=vn;count+=1;total+=vn
    order=[]
    for _ in range(U(raw,64)):
        require(at+8<=len(raw),"history order header")
        kn=U(raw,at);at+=8;require(kn<=len(raw)-at,"history order extent")
        order.append(utf(raw[at:at+kn]));at+=kn
    require(at==len(raw) and keys==sorted(set(keys),key=lambda k:k.encode())
        and count==U(raw,48) and total==U(raw,56),"history complete values/accounting")
    return dict(poisoned=bool(U(raw,32)),keys=keys,snapshots=count,bytes=total,order=order)

def locks(raw,sequence):
    require(len(raw)>=56 and raw[:8]==b"HLTBLK01" and U(raw,8)==len(raw)
        and U(raw,16)==1 and U(raw,24)==sequence+1 and U(raw,32) in (0,1)
        and U(raw,48)==len(raw)-56,"complete lock frame")
    at=56;rows=[]
    for _ in range(U(raw,40)):
        require(at+16<=len(raw),"lock entry header")
        kn,refs=U(raw,at),U(raw,at+8);at+=16
        require(kn<=len(raw)-at and refs>=1,"lock complete entry")
        rows.append((utf(raw[at:at+kn]),refs));at+=kn
    require(at==len(raw) and [k for k,_ in rows]==sorted({k for k,_ in rows},key=lambda k:k.encode()),"lock full sorted set")
    return dict(poisoned=bool(U(raw,32)),entries=rows)

def validate_state(value,sequence,previous_events,case):
    require(len(value["cache_snapshots_hex"])==len(value["sessions"])==2,"two actual session observations")
    caches=[cache(full_hex(raw)) for raw in value["cache_snapshots_hex"]]
    hs=history(full_hex(value["history_snapshot_hex"]),sequence)
    ls=locks(full_hex(value["lock_snapshot_hex"]),sequence)
    require(value["scope_unbound_after_exchange"] is True,"original task-local scope escaped observer")
    for session in value["sessions"]:
        require(session["root"]==case["root"] and session["effective"]==case["root"]
            and type(session["session_applied"]) is bool and type(session["poisoned"]) is bool,"actual session cwd")
    events=value["events"]
    require(events[:len(previous_events)]==previous_events,"full lifecycle event prefix changed")
    entered={};returned={};dropped={};last_time=0
    for index,event in enumerate(events):
        require(event["ordinal"]==index and type(event["thread"]) is str,"lifecycle ordinal/thread")
        elapsed=int(event["elapsed_ns"]);require(elapsed>=last_time,"lifecycle monotonic observation");last_time=elapsed
        if event["event"]=="entered":
            number=event["number"];require(type(number) is int and number>0 and number not in entered,"actual future identity")
            require(event["path"] in {str(Path(case["root"])/p) for p in ("held/a.txt","held/b.txt","free/c.txt")},"actual future path")
            entered[number]=event
        elif event["event"]=="returned":
            number=event["number"]
            require(number in entered and number not in returned and number not in dropped
                and event["path"]==entered[number]["path"] and type(event["ok"]) is bool,"actual future return order")
            returned[number]=event
        elif event["event"]=="dropped":
            number=event["number"]
            require(number in entered and number not in dropped and event["path"]==entered[number]["path"]
                and event["after_return"]==(number in returned),"actual future Drop order")
            dropped[number]=event
    return dict(caches=caches,history=hs,locks=ls,entered=entered,returned=returned,dropped=dropped),events

def wire(raw):
    if not raw:return []
    require(raw.endswith(b"\n"),"complete SDK wire termination")
    rows=[]
    for line in raw.splitlines(keepends=True):
        require(line.endswith(b"\n"),"complete SDK line")
        row=decode(line)
        require(type(row) is dict and row.get("jsonrpc")=="2.0"
            and (("result" in row)^("error" in row)),"actual SDK result/error envelope")
        rows.append(row)
    return rows

def verify_case(root,case,actual_fixture,binary,binary_path):
    root=Path(root)
    commands=decode((root/"COMMANDS.json").read_bytes())
    host=decode((root/"HOST.json").read_bytes())
    snapshots=decode((root/"FILESYSTEM.json").read_bytes())
    result=decode((root/"RESULT.json").read_bytes())
    process=decode((root/"process/PROCESS.json").read_bytes())
    require(result["status"]=="ACTUAL_ORIGINAL_LIFECYCLE_CAPTURED" and result["case"]==case["case"]
        and result["name"]==case["name"] and result["era"]==case["era"] and result["mode"]==case["mode"],"complete case identity")
    require(result["process"]==process and process["exit_code"]==0 and not process["timed_out"]
        and process["expected_success"] is True and process["cleanup_error"] is None,"actual process terminal")
    require(process["timeout_seconds"]==180 and process["exchange_limit_seconds"]==60
        and 0<=process["elapsed_seconds"]<180,"unchanged process/exchange bounds")
    require(process["cwd"]==case["root"] and process["command"][0]==binary_path and process["command"][1]=="--async-fixture"
        and process["command"][-1]==case["mode"],"actual observer command/cwd")
    declared_output=Path(process["command"][2]).parent
    require(Path(process["command"][2]).name=="config.json","actual observer config argument")
    config=dict(state_dir=str(declared_output/"controller-state"),controller_workspace_roots=[case["root"]],
        hosts={"fixture":dict(ssh_target="uncontacted-async-reference",remote_state_dir="/unused-runtime-state",
            allow_write=True,allowed_read_path_prefixes=["/allowed"],
            allowed_write_path_prefixes=["/allowed"],protected_path_prefixes=["/allowed/protected"])})
    require((root/"config.json").read_bytes()==canonical(config),"complete actual runtime configuration")
    for key,path in (("stdin","stdin"),("stdout_gzip","stdout.gz"),("stderr","stderr")):
        require(pin(root/"process"/path)==process[key],"complete process file")
    require(process["stderr"]["bytes"]==0,"actual original observer stderr")
    stdout=gzip.decompress((root/"process/stdout.gz").read_bytes())
    require(dict(bytes=len(stdout),sha256=sha(stdout))==process["full_stdout"],"complete decompressed stdout")
    require(result["commands"]==len(commands) and result["snapshots"]==len(snapshots),"complete case record counts")
    for key,path in (("commands","COMMANDS.json"),("host","HOST.json"),("filesystem","FILESYSTEM.json")):
        require(pin(root/path)==result["files"][key],"case evidence index")
    names=[e["event"] for e in host]
    require(names==["holder_locked","process_started","holder_unlocked","holder_fd_closed"],"actual holder lifecycle")
    holder=host[0]["identity"]
    require(host[0]["directory"]==str(Path(case["root"])/"held") and host[0]["flags"]==6
        and stat.S_ISDIR(holder["mode"]),"ordinary exclusive nonblocking fixture hold")
    require(host[1]["pid"]==process["pid"] and host[1]["binary"]==binary,"actual owned process/binary")
    require(host[2]["identity"]==holder and host[3]["fd"]==holder["fd"],"same holder FD released once")
    require(all(0<=e["after_commands"]<=len(commands) for e in host)
        and [e["monotonic_ns"] for e in host]==sorted(e["monotonic_ns"] for e in host),"holder event chronology")
    store=Reader(root/"buffers")
    inputs=[];outputs=[];values=[];previous=[];states=[]
    for number,row in enumerate(commands):
        require(row["number"]==number and type(row["source_step"]) is int
            and 0<=row["source_step"]<len(case["steps"]) and 0<=row["elapsed_ns"]<60_000_000_000,"actual command record")
        request=store.get(row["request"]);response=store.get(row["response"])
        q=decode(request);v=decode(response)
        require(request==canonical(q) and request.endswith(b"\n") and response.endswith(b"\n"),"whole observer lines")
        require((v["id"],v["sequence"],v["kind"],v["session"])==(number,number,q["kind"],q["session"]),"actual observer identity")
        summary,previous=validate_state(v["state"],number,previous,case)
        inputs.append(request);outputs.append(response);values.append((q,v));states.append(summary)
        if q["kind"] in ("read","drain"):wire(full_hex(v["result"]["wire_hex"]))
        if q["kind"] in ("wait_blocked","blocked_snapshot"):
            observation=v["result"]
            require(observation["pid"]==process["pid"] and observation["path"]==q["path"]
                and observation["dev"]==holder["dev"] and observation["ino"]==holder["ino"],"actual worker/holder inode match")
            matching=[]
            for task in observation["tasks"]:
                if task.get("matching_directory") is True:
                    fields=task["syscall"].split()
                    require(len(fields)>=3 and int(fields[0],0)==73 and int(fields[1],0)==task["fd"]
                        and int(fields[2],0)==2 and task["dev"]==holder["dev"] and task["ino"]==holder["ino"],"actual Linux flock wait")
                    matching.append(task["tid"])
            require(matching==observation["matching_tids"] and len(set(matching))==len(matching),"complete matching task set")
            require(host[0]["after_commands"]<=number<host[2]["after_commands"],"blocked observation outside actual hold")
            if q["kind"]=="wait_blocked":require(len(matching)>=q["count"],"original worker never reached required wait")
            if q["kind"]=="blocked_snapshot" and case["mode"]=="queued":require(not matching,"queued fixture unexpectedly started body")
        if q["kind"]=="direct_drop":
            require(v["result"].get("joined") is False and v["result"].get("cancelled") is True
                and v["result"].get("panic") is False,"actual private task abort did not drop its pending future")
        if q["kind"]=="wait_events":
            matching=[e for e in previous if e["event"]==q["event"]
                and ("after_return" not in q or e.get("after_return")==q["after_return"])]
            require(len(matching)>=q["count"] and v["result"]["count"]==len(matching),"actual lifecycle wait count")
    require(b"".join(inputs)==(root/"process/stdin").read_bytes()
        and b"".join(outputs)==stdout,"every command and complete stdout line consumed")
    require(values and values[-1][0]["kind"]=="finalize" and values[-1][1]["result"]=={"runtime_dropped":True},"actual Runtime Drop terminal")
    final=states[-1]
    require(set(final["entered"])==set(final["dropped"]),"actual original future not dropped before runtime retirement")
    event_names=[e["event"] for e in previous]
    require(event_names.count("runtime_drop_begin")==event_names.count("runtime_drop_complete")==1
        and event_names[-2:]==["runtime_drop_begin","runtime_drop_complete"],"actual runtime drain event order")

    at=0;expected_snapshots=[("initial",0)]
    public_requests=[];public_responses=[]
    for step_number,step in enumerate(case["steps"]):
        if "local" not in step:
            require(at<len(values) and commands[at]["source_step"]==step_number,"input-only step completeness")
            require(values[at][0]==dict(step,id=at),"actual command differs from frozen input")
            if step["kind"]=="send":public_requests.append(full_hex(step["wire_hex"]))
            if step["kind"] in ("read","drain"):
                public_responses.append(full_hex(values[at][1]["result"]["wire_hex"]))
            at+=1
        elif step["local"]=="read_until_id":
            found=False
            for _ in range(step["max_lines"]):
                require(at<len(values) and commands[at]["source_step"]==step_number,"barrier command completeness")
                require(values[at][0]==dict(kind="read",session=step["session"],id=at),"barrier actual read input")
                body=full_hex(values[at][1]["result"]["wire_hex"])
                public_responses.append(body);at+=1
                if decode(body).get("id")==step["request_id"]:found=True;break
            require(found,"actual SDK barrier never observed")
        elif step["local"]=="filesystem_snapshot":
            expected_snapshots.append((step["name"],at))
        elif step["local"]=="unlock":
            require(host[2]["after_commands"]==at,"actual unlock input order")
        else:raise ValueError("unadmitted frozen input step")
    require(at==len(values),"extra application commands")
    require([(s["name"],s["after_commands"]) for s in snapshots]==expected_snapshots,"stable-point filesystem snapshot domain")
    expected_futures=sum(1 for step in case["steps"] if step.get("kind")=="direct_start")
    if case["mode"]=="public":
        expected_futures=sum(1 for raw in public_requests if decode(raw).get("method")=="tools/call")
        require(event_names.count("serve_begin")==event_names.count("serve_ready")==event_names.count("serve_finished")==2,"actual two SDK session lifecycle")
    require(len(final["entered"])==expected_futures,"complete original handler invocation count")
    initial=snapshots[0]["files"]
    require([r["path"] for r in initial]==[".","free","held"]
        and all(r["kind"]=="dir" for r in initial),"owned input-only filesystem setup")
    held=next(r for r in initial if r["path"]=="held")["stat"]
    require((held["dev"],held["ino"])==(holder["dev"],holder["ino"]),"holder bound to actual initial directory")
    final_rows=None
    for snap in snapshots:
        paths=[r["path"] for r in snap["files"]]
        require(len(set(paths))==len(paths) and paths[0]==".","complete unique filesystem observation")
        for row in snap["files"]:
            p=Path(row["path"])
            require(not p.is_absolute() and ".." not in p.parts and (str(p)==row["path"] or row["path"]=="."),"filesystem observation path")
            require(set(row["stat"])=={"mode","dev","ino","nlink","uid","gid","size","atime_ns","mtime_ns","ctime_ns"},"full stat observation")
            if row["kind"]=="file":
                data=store.get(row["data"])
                require(len(data)==row["stat"]["size"] and stat.S_ISREG(row["stat"]["mode"]),"complete file bytes/type")
            elif row["kind"]=="dir":
                require(stat.S_ISDIR(row["stat"]["mode"]) and row["entries"]==sorted(set(row["entries"])),"complete directory enumeration")
            else:raise ValueError("async fixture contains an undeclared file kind")
            for name,value in row["xattrs"].items():full_hex(value)
        if snap["name"]=="after-runtime-drop":final_rows=snap["files"]
    require(final_rows is not None,"missing complete post-runtime filesystem")
    physical={p.relative_to(actual_fixture).as_posix():p for p in Path(actual_fixture).rglob("*")}
    physical["."]=Path(actual_fixture)
    require(set(physical)=={r["path"] for r in final_rows},"complete retained final filesystem set")
    files=[]
    for row in final_rows:
        p=physical[row["path"]];info=p.lstat()
        require(stat.S_IFMT(info.st_mode)==stat.S_IFMT(row["stat"]["mode"])
            and info.st_mode&0o777==row["stat"]["mode"]&0o777
            and info.st_mtime_ns==row["stat"]["mtime_ns"],"retained final filesystem type/mode/mtime")
        import os
        require({name:os.getxattr(p,name,follow_symlinks=False).hex()
            for name in sorted(os.listxattr(p,follow_symlinks=False))}==row["xattrs"],"full retained xattrs")
        if row["kind"]=="file":
            raw=store.get(row["data"]);require(p.read_bytes()==raw,"actual retained publication bytes")
            files.append(dict(path=row["path"],bytes=len(raw),sha256=sha(raw)))
        else:require(sorted(x.name for x in p.iterdir())==row["entries"],"retained directory entries")
    complete=store.finish()
    captured_images=2*len(commands)+sum(row["kind"]=="file" for snap in snapshots for row in snap["files"])
    captured_bytes=sum(row["request"]["bytes"]+row["response"]["bytes"] for row in commands)+sum(
        row["data"]["bytes"] for snap in snapshots for row in snap["files"] if row["kind"]=="file")
    require(result["complete_buffer_images"]==captured_images and result["logical_buffer_bytes"]==captured_bytes,
        "exact full captured buffer accounting")
    require(complete["complete_images"]==captured_images+len(files)
        and complete["logical_buffer_bytes"]==captured_bytes+sum(row["bytes"] for row in files),
        "every captured buffer consumed in full")
    require(set(p.name for p in root.iterdir())=={"config.json","buffers","COMMANDS.json","HOST.json","FILESYSTEM.json","process","RESULT.json"},"case evidence file set")
    require(set(p.name for p in (root/"process").iterdir())=={"stdin","stdout.gz","stderr","PROCESS.json"},"process evidence file set")
    return dict(case=case["case"],name=case["name"],era=case["era"],mode=case["mode"],
        commands=len(commands),observed_futures=len(final["entered"]),returned=len(final["returned"]),
        dropped_without_return=sum(not row["after_return"] for row in final["dropped"].values()),
        request_wire=dict(bytes=sum(map(len,public_requests)),sha256=sha(b"".join(public_requests))),
        response_wire=dict(bytes=sum(map(len,public_responses)),sha256=sha(b"".join(public_responses))),
        response_lines=sum(len(wire(raw)) for raw in public_responses),
        final_files=files,final_cache=final["caches"],history=final["history"],locks=final["locks"],
        final_events=previous,complete_buffers=complete)

def verify(output):
    output=Path(output)
    plan=decode((output/"PLAN.json").read_bytes())
    require(plan["declaration"]==declaration() and plan["binary"]==dependency()["binary"],"fixed original domain/source dependency")
    all_cases=cases(plan["fixture_root"])
    require(0<=plan["first"]<30 and 0<plan["count"]<=30-plan["first"],"complete fixed domain selection")
    expected=all_cases[plan["first"]:plan["first"]+plan["count"]]
    require(plan["cases"]==expected,"input-only complete scenario bytes")
    require(set(p.name for p in output.iterdir())=={"PLAN.json","RESULTS.json","SUMMARY.json","cases","fixtures"},"capture top-level closure")
    require(set(p.name for p in (output/"cases").iterdir())=={"%03d"%c["case"] for c in expected},"full case directory set")
    require(set(p.name for p in (output/"fixtures").iterdir())=={Path(c["root"]).name for c in expected},"full fixture directory set")
    results=decode((output/"RESULTS.json").read_bytes())
    require(results==[decode((output/"cases"/("%03d"%c["case"])/"RESULT.json").read_bytes()) for c in expected],"actual result index")
    rows=[verify_case(output/"cases"/("%03d"%c["case"]),c,output/"fixtures"/Path(c["root"]).name,plan["binary"],plan["binary_path"]) for c in expected]
    summary=decode((output/"SUMMARY.json").read_bytes())
    require(summary==dict(status="ORIGINAL_ASYNC_LIFECYCLE_CAPTURE_COMPLETE",cases=len(results),
        selected_first=plan["first"],selected_count=plan["count"],commands=sum(r["commands"] for r in results),
        full_domain=plan["first"]==0 and plan["count"]==30,native_executed=False,full_sdk=False,
        process_limit_seconds=180,exchange_limit_seconds=60),"complete capture summary")
    return dict(status="COMPLETE_ACTUAL_ORIGINAL_ASYNC_EVIDENCE_PASS",cases=len(rows),rows=rows,
        commands=sum(r["commands"] for r in rows),future_invocations=sum(r["observed_futures"] for r in rows),
        selected_first=plan["first"],selected_count=plan["count"],full_domain=plan["first"]==0 and plan["count"]==30,
        native_executed=False,rust_executed=False,native_async_qualified=False,full_sdk=False,
        physical_copy_normalization=["device","inode","uid","gid","links","ctime","atime"],
        original_observations_preserved_in_full=True)
