#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Compare every direct command, actual two-session state and full file effect."""
from pathlib import Path
import stat,struct
from common import canonical,decode,pin,require,sha
from buffer_store import Reader
from input_domain import startup
from direct_inputs import gateway,auxiliary_body
import read_controls,read_state,direct_versions
U=read_controls.U
def blocked(value,pid,path,identity,count):
    require(value["parent_pid"]==pid and value["path"]==path
        and (value["dev"],value["ino"])==(identity["dev"],identity["ino"]),"actual parent/held directory")
    matching=[]
    for row in value["children"]:
        if "fd" in row and (row["dev"],row["ino"])==(identity["dev"],identity["ino"]):
            fields=row["syscall"].split()
            require(int(fields[0],0)==73 and int(fields[1],0)==row["fd"] and int(fields[2],0)==2,
                "actual owned worker flock")
            matching.append(row["pid"])
    require(matching==value["matching_pids"] and len(set(matching))==len(matching)
        and len(matching)>=count,"whole actual matching worker list")
    return matching
def contexts(events):
    return [dict(pool=e["pool"],job=e["job"],engine=e["engine"],tag=e["tag"],stage=e["stage"],
        entered_trace=e["entered"],returned_trace=e["returned"],dropped_trace=e["dropped"]) for e in events]
def original_startup(original_root):
    root=Path(original_root).parent/"000";rows=decode((root/"COMMANDS.json").read_bytes())
    store=Reader(root/"buffers");result=[]
    for row in rows:
        q=decode(store.get(row["request"]))
        if q["kind"]=="read" and row["source_step"] in (7,10):
            value=decode(store.get(row["response"]))["result"]
            result.append((q["session"],bytes.fromhex(value["wire_hex"])))
    require([sid for sid,_ in result]==[0,1],"retained actual original legacy initialization responses")
    return result
def startup_artifacts(root):
    p=Path(root)/"controller-state"
    require(p.is_dir() and not p.is_symlink() and stat.S_IMODE(p.stat().st_mode)==0o700,"actual config startup root")
    expected={"audit":("directory",0o700),"jobs":("directory",0o700),
        "controller.lock":("file",0o600),"controller.owner.lock":("file",0o600)}
    require({x.relative_to(p).as_posix() for x in p.rglob("*")}==set(expected),"whole startup artifact set")
    for name,(kind,mode) in expected.items():
        x=p/name;s=x.lstat()
        require(not x.is_symlink() and stat.S_IMODE(s.st_mode)==mode
            and (stat.S_ISDIR(s.st_mode) if kind=="directory" else stat.S_ISREG(s.st_mode)),"startup kind/mode")
        require(not list(x.iterdir()) if kind=="directory" else s.st_nlink==1 and x.read_bytes()==b"",
            "no unadmitted startup content")
    return expected
def compare(native_root,original_root,case,expected_binary):
    d=read_controls.read(native_root,case,expected_binary);n=d["root"];o=Path(original_root)
    result=d["result"];process=d["process"];controls=d["controls"];observed=d["observations"]
    store=d["store"];get=d["get"];rows=d["commands"];host=d["host"];holder=d["holder"]
    old_rows=decode((o/"COMMANDS.json").read_bytes());old_store=Reader(o/"buffers")
    require(case["era"]=="direct" and 22<=case["case"]<30 and result["mode"]==case["mode"]
        and result["commands"]==len(rows)==len(old_rows),"whole direct input domain")
    aux=decode((n/"AUXILIARY.json").read_bytes());auxfs=decode((n/"AUXILIARY_FILESYSTEM.json").read_bytes())
    native_fs=decode((n/"FILESYSTEM.json").read_bytes());old_fs=decode((o/"FILESYSTEM.json").read_bytes())
    require(native_fs[-1]["name"]==old_fs[-1]["name"]=="after-runtime-drop","actual final file barriers")
    incoming=[read_controls.Hash(),read_controls.Hash()];outgoing=[read_controls.Hash(),read_controls.Hash()]
    expected_startup=startup("legacy");startup_rows=[a for a in aux if a["kind"]=="carrier-startup"]
    require(len(startup_rows)==len(expected_startup)==6,"two real legacy carrier startups")
    reference_startup=dict(original_startup(o));prefix=0
    for row,q in zip(startup_rows,expected_startup,strict=True):
        require(row["after_commands"]==0 and row["request"]==q and row["control_first"]==prefix
            and type(row["control_count"]) is int and row["control_count"]>=0,"actual carrier startup ranges")
        end=prefix+row["control_count"]
        require(all(v["operation"]==1 for v in observed[prefix:end]),"carrier uses real existing service pump")
        sid=q["session"]
        if q["kind"]=="send":
            raw=bytes.fromhex(q["wire_hex"]);require(row["result"]==dict(bytes=len(raw)) and end>prefix,
                "entire carrier startup write")
            incoming[sid].add(raw)
        else:
            raw=bytes.fromhex(row["result"]["wire_hex"]);require(raw==reference_startup[sid],
                "whole carrier initialization equals actual current SDK response")
            outgoing[sid].add(raw)
        prefix=end
    expected_observations=[]
    queued=[a for a in aux if a["kind"]=="real-queue-slot-occupied"]
    if case["mode"]=="queued":
        require(len(queued)==1 and len(auxfs)==2,"one actual external queue blocker")
        q=queued[0];require(q["after_commands"]==0 and q["control_first"]==prefix and q["control_count"]>=2
            and q["outside_semantic_root"] is True,"real auxiliary before unchanged direct inputs")
        end=prefix+q["control_count"];first=observed[prefix]
        expected_path=Path(process["command"][6]).parent/"auxiliary-blocker"
        payload=auxiliary_body(expected_path/"slot.txt")
        require(bytes.fromhex(q["input_hex"])==payload and first["operation"]==10 and first["session"]==0
            and first["request"][64:]==payload and U(first["request"],40)==U(first["request"],48)==0
            and q["operation"]==prefix and first["result"]==b""
            and all(v["operation"]==1 for v in observed[prefix+1:end]),"complete actual auxiliary submit")
        blocked(q["blocked"],process["pid"],str(expected_path),q["holder"],1)
        expected_observations.append(q["blocked"])
        prefix=end
    else:require(not queued and not auxfs,"no undeclared direct queue blocker")
    endings=[a for a in aux if a["kind"]=="carrier-eof"]
    require(len(endings)==2 and [a["session"] for a in endings]==[0,1]
        and len(aux)==len(startup_rows)+len(queued)+len(endings),"whole auxiliary inventory")
    stable=[];differences=[];versions=[];direct_results=[];next_control=prefix;step_index=0
    for number,(row,old) in enumerate(zip(rows,old_rows,strict=True)):
        request=get(row["request"]);q=decode(request)
        oq=decode(old_store.get(old["request"]));ov=decode(old_store.get(old["response"]))
        require(request==canonical(oq) and row["number"]==number and row["source_step"]==old["source_step"]
            and q==dict(case["steps"][row["source_step"]],id=number),"whole actual unchanged direct command")
        require(row["control_first"]==next_control and row["control_count"]>0
            and row["state_control"]==next_control+row["control_count"]-1
            and 0<=row["elapsed_ns"]<60_000_000_000,"whole contiguous actual command range")
        end=next_control+row["control_count"];turn=observed[next_control:end];view=turn[-1]
        kind=q["kind"];sid=q["session"];actual=row["result"];expected=ov["result"]
        require(view["operation"]==(5 if kind=="finalize" else 3) and view["session"]==sid,"actual complete post-command state")
        if kind=="finalize":
            require(actual=={"actual_runtime_finalized":True} and expected=={"runtime_dropped":True},
                "actual whole process runtime end")
            cursor=next_control
            for e in endings:
                require(e["after_commands"]==number and e["control_first"]==cursor and e["control_count"]>=2,
                    "actual carrier EOF range belongs only to final runtime command")
                cursor+=e["control_count"];chunk=observed[e["control_first"]:cursor];cs=e["session"]
                require(e["eof"]=={"writer_shutdown":True} and e["drain"]["terminal"]==
                    dict(actual_phase=4,actual_eof_result=0,actual_pipe_closed=1)
                    and chunk[-1]["operation"]==4 and chunk[-1]["session"]==cs
                    and all(v["operation"]==1 for v in chunk[:-1]),"real EOF and service drain before runtime")
                outgoing[cs].add(bytes.fromhex(e["drain"]["wire_hex"]))
                require(e["drain"]["wire_hex"]=="","direct futures never fabricated SDK output")
            require(cursor==end-1 and view["final"]==1 and view["phases"]==(4,4),"only final op5 after both real service drains")
        else:
            active=turn[:-1]
            require(active,"real command before snapshot")
            if kind=="cache":
                require(active[0]["operation"]==2 and active[0]["session"]==sid and len(active)==1
                    and active[0]["request"][64:]==bytes.fromhex(q["wire_hex"])
                    and actual==expected==dict(output_hex=active[0]["result"].hex()),"actual session cache seed")
            elif kind in ("direct_start","direct_unpolled_drop","direct_drop","direct_join"):
                op={"direct_start":6,"direct_drop":7,"direct_join":8,"direct_unpolled_drop":9}[kind]
                require(len(active)==1 and active[0]["operation"]==op and active[0]["session"]==sid
                    and U(active[0]["request"],40)==q["tag"] and U(active[0]["request"],48)==0
                    and active[0]["request"][64:]==(gateway(q) if op in (6,9) else b""),"complete real private direct request")
                raw=active[0]["result"]
                require(actual==dict(tag=q["tag"],actual_operation=op,frame_hex=raw.hex()),"actual complete direct response bytes")
                if op==6:
                    require(expected==dict(tag=q["tag"],spawned=True) and raw==b"","actual first future poll and retained pending")
                elif op==9:
                    require(expected==dict(tag=q["tag"],unpolled_future_dropped=True) and raw==b"","actual unpolled future input release")
                elif op==7:
                    require(expected["tag"]==q["tag"] and expected["joined"] is False and expected["cancelled"] is True
                        and expected["panic"] is False and type(expected["join_error"]) is str and raw==b"",
                        "actual future Drop has no generated handler result")
                else:
                    require(len(raw)>=32 and raw[:8]==b"HRCFGM01" and U(raw,8) in (0,1)
                        and U(raw,16)==0 and U(raw,24)==len(raw)-32,"entire real gateway handler result")
                    require(expected["tag"]==q["tag"] and expected["joined"] is True
                        and type(expected["ok"]) is bool and expected["ok"]==(U(raw,8)==0),"actual original future join")
                    wanted=bytes.fromhex(expected["output_hex"]);parameters=next(s["parameters"] for s in case["steps"]
                        if s.get("kind")=="direct_start" and s["session"]==sid and s["tag"]==q["tag"])
                    if expected["ok"]:
                        left,lp=direct_versions.body(raw[32:],parameters,case,native_fs[-1]["files"],store)
                        right,rp=direct_versions.body(wanted,parameters,case,old_fs[-1]["files"],old_store)
                        require(left==right,"whole original/native joined publication result")
                        versions.append(dict(command=number,native=lp,original=rp))
                    else:require(raw[32:]==wanted,"whole original/native direct error bytes")
                direct_results.append(dict(command=number,session=sid,tag=q["tag"],operation=op,
                    frame=dict(bytes=len(raw),sha256=sha(raw))))
            elif kind=="wait_events":
                require(all(v["operation"]==1 for v in active) and actual["event"]==expected["event"]==q["event"]
                    and actual["count"]==expected["count"] and actual["actual_contexts"]==contexts(active[-1]["events"]),
                    "actual real future events and exact original count")
            elif kind in ("wait_blocked","blocked_snapshot"):
                require(all(v["operation"]==1 for v in active),"real scheduler driven before syscall snapshot")
                found=blocked(actual,process["pid"],q["path"],holder,q.get("count",0))
                expected_observations.append(actual)
                if kind=="blocked_snapshot":require(case["mode"]=="queued" and not found,"queued handler body has not started")
            elif kind=="release_blocker":
                require(len(active)==1 and active[0]["operation"]==11 and active[0]["session"]==sid
                    and active[0]["request"][64:]==b"" and U(active[0]["request"],40)==U(active[0]["request"],48)==0
                    and actual["actual_auxiliary_body_reaped_and_released"] is True
                    and actual["holder"]==queued[0]["holder"] and expected=={"released":True},
                    "real auxiliary body completed/reaped/released after external blocker unlock")
            else:raise ValueError("unadmitted direct input kind "+kind)
        got=[s["state"] for s in view["states"]];wanted=read_state.original(ov["state"])
        require(len(got)==2,"both complete direct session states")
        settled=kind in ("cache","direct_unpolled_drop","direct_drop","direct_join","wait_events","wait_blocked",
            "blocked_snapshot","finalize")
        if settled:
            require(got==wanted,"whole direct session/cache/history/locks differs at command "+str(number)+": "+repr((got,wanted)))
            stable.append(number)
        elif got!=wanted:differences.append(number)
        next_control=end
    require(next_control==len(controls),"no unclaimed real private controls")
    require(decode((n/"process/OBSERVATIONS.json").read_bytes())==expected_observations,
        "complete actual syscall observation inventory")
    for sid in (0,1):
        require(incoming[sid].value()==d["streams"]["stdin-"+str(sid)]
            and outgoing[sid].value()==d["streams"]["stdout-"+str(sid)],"every auxiliary carrier wire byte")
    require([(r["name"],r["after_commands"]) for r in native_fs]==[(r["name"],r["after_commands"]) for r in old_fs],
        "every original direct file observation")
    ni={};oi={};nn=native_fs[0]["files"][0]["stat"];on=old_fs[0]["files"][0]["stat"];file_rows=[]
    extra_n=0;extra_b=0
    for left,right in zip(native_fs,old_fs,strict=True):
        a=read_controls.normalize_files(left["files"],store,ni,nn)
        b=read_controls.normalize_files(right["files"],old_store,oi,on)
        require(a==b,"whole direct filesystem differs: "+left["name"]);file_rows.append(a)
        for r in left["files"]:
            if r["kind"]=="file":extra_n+=1;extra_b+=r["data"]["bytes"]
    aux_rows=[]
    if case["mode"]=="queued":
        require([r["name"] for r in auxfs]==["initial","released"],"entire auxiliary filesystem lifecycle")
        identities={};initial=auxfs[0]["files"][0]["stat"]
        for snap in auxfs:
            aux_rows.append(read_controls.normalize_files(snap["files"],store,identities,initial))
            for r in snap["files"]:
                if r["kind"]=="file":extra_n+=1;extra_b+=r["data"]["bytes"]
        require([r["path"] for r in auxfs[0]["files"]]==["."] and
            [r["path"] for r in auxfs[1]["files"]]==[".","slot.txt"]
            and store.get(auxfs[1]["files"][1]["data"])==b"owned queue-slot holder\n","entire actual external auxiliary file")
        retained=n/"auxiliary-blocker"
        require(retained.is_dir() and not retained.is_symlink() and
            {p.relative_to(retained).as_posix() for p in retained.rglob("*")}=={"slot.txt"},
            "whole retained auxiliary physical tree")
        for row in auxfs[-1]["files"]:
            p=retained if row["path"]=="." else retained/row["path"];st=p.lstat()
            require(not p.is_symlink() and stat.S_IMODE(st.st_mode)==stat.S_IMODE(row["stat"]["mode"])
                and (stat.S_ISDIR(st.st_mode) if row["kind"]=="dir" else stat.S_ISREG(st.st_mode)),
                "retained auxiliary physical mode/type")
            if row["kind"]=="file":
                require(st.st_nlink==1 and p.read_bytes()==store.get(row["data"]),
                    "retained auxiliary full physical file")
    count,extent=d["counters"]()
    require(result["complete_buffer_images"]==count+extra_n and result["logical_buffer_bytes"]==extent+extra_b,
        "all actual captured complete buffers accounted")
    for name in ("COMMANDS","HOST","FILESYSTEM","AUXILIARY","AUXILIARY_FILESYSTEM"):
        require(result["files"][name]==pin(n/(name+".json")),"whole direct evidence custody")
    startup_proof=startup_artifacts(n)
    require(set(p.name for p in n.iterdir())=={"RESULT.json","COMMANDS.json","HOST.json","FILESYSTEM.json",
        "AUXILIARY.json","AUXILIARY_FILESYSTEM.json","config.json","buffers","process","controller-state"}|
        ({"auxiliary-blocker"} if case["mode"]=="queued" else set()),"complete direct capture file set")
    full=store.finish()
    return dict(status="COMPLETE_DIRECT_COMMAND_STATE_FILES_COMPARISON_PASS",case=case["case"],name=case["name"],
        commands=len(rows),private_exchanges=len(controls),actual_direct_results=direct_results,
        stable_full_state_comparisons=stable,nonbarrier_observation_differences=differences,
        version_bindings=versions,final_files=file_rows[-1],final_state=observed[-1]["states"],
        actual_auxiliary_queue_file=aux_rows,actual_configuration_startup=startup_proof,
        carrier_input=[x.value() for x in incoming],carrier_output=[x.value() for x in outgoing],
        all_native_streams=d["streams"],full_buffer_read=full,
        original_rerun=False,native_rerun=False,worker_journal_read_pending=True,full_sdk=False)
