"""Pure complete source/custody join of two unchanged partitioned verifier bodies."""
from pathlib import Path
import math,os,stat
import recovery_common as rc

def exact_int(value,minimum=0):return type(value) is int and value>=minimum

def verify(complete,output,prepared):
    identity=rc.source();parent_raw=rc.read(output/"admission/PARENT.json");parent=rc.loads(parent_raw)
    rc.check(parent["schema"]=="hepta.audit-anchor-publish.parallel-read-parent.v1" and
             parent["source_manifest_sha256"]==identity and
             all(exact_int(parent[k],2) for k in ("pid","parent_pid","pgid")) and
             parent["pid"]==parent["pgid"]!=parent["parent_pid"] and exact_int(parent["started_ns"],1) and
             exact_int(parent["deadline_ns"]) and parent["deadline_ns"]==parent["started_ns"]+180_000_000_000 and
             exact_int(parent["timeout_seconds"]) and parent["timeout_seconds"]==180 and
             exact_int(parent["native_or_rust_executions"]) and parent["native_or_rust_executions"]==0 and
             all(type(parent[k]) is str and parent[k].startswith("/") for k in ("source_root","complete_root","output_root")),
             "actual bounded two-worker parent identity")
    records=rc.loads(rc.read(output/"parts/processes.json"));rc.check(len(records)==2,"exact two pure-reader processes")
    seen=set();values=[];snapshots=[]
    for part,(names,row) in enumerate(zip(prepared["partitions"],records,strict=True)):
        folder=output/"parts"/str(part);raw=rc.read(folder/"READBACK.json");proof=rc.loads(raw);evidence=proof["evidence"]
        rc.check(row==rc.loads(rc.read(folder/"process.json")) and type(row["part"]) is int and row["part"]==part and
                 row["names"]==list(names) and row["cwd"]==parent["source_root"] and len(row["argv"])==10 and
                 type(row["argv"][0]) is str and row["argv"][0].startswith("/") and
                 row["argv"][1:]==["-I","-B",parent["source_root"]+"/read_worker.py","--complete",parent["complete_root"],
                    "--output",parent["output_root"]+"/parts/"+str(part),"--part",str(part)] and
                 row["completed"] is True and row["timed_out"] is False and exact_int(row["exit_code"]) and row["exit_code"]==0 and
                 exact_int(row["timeout_seconds"]) and row["timeout_seconds"]==180 and
                 row["source_manifest_sha256"]==identity and exact_int(row["native_or_rust_executions"]) and
                 row["native_or_rust_executions"]==0,"entire actual pure-worker command and result")
        rc.check(all(exact_int(row[k],2) for k in ("pid","parent_pid","pgid")) and
                 row["pid"] not in seen|{parent["pid"],parent["parent_pid"]} and row["parent_pid"]==parent["pid"] and
                 row["pgid"]==parent["pgid"],"two actual distinct children of the recorder-owned group")
        seen.add(row["pid"])
        rc.check(all(exact_int(row[k],1) for k in ("started_ns","finished_ns","elapsed_ns")) and
                 parent["started_ns"]<=row["started_ns"]<row["finished_ns"]<=parent["deadline_ns"] and
                 row["elapsed_ns"]==row["finished_ns"]-row["started_ns"],"complete worker elapsed inside whole 180-second limit")
        prepared["physical"].guarded_proof(proof,evidence)
        rc.check(all(type(proof[k]) is int and proof[k]==row[j] for k,j in
                     (("pid","pid"),("ppid","parent_pid"),("pgid","pgid"))),"actual child guard PID evidence")
        rc.check(evidence["status"]=="PUBLISHER_PHYSICAL_PART_READ_PASS" and
                 exact_int(evidence["part"]) and evidence["part"]==part and evidence["checked_names"]==list(names) and
                 evidence["source_manifest_sha256"]==identity and evidence["retained_source_sha256"]==prepared["old_identity"] and
                 evidence["source_transform"]==prepared["transform"] and evidence["parent_evidence"]==rc.pin(parent_raw) and
                 exact_int(evidence["native_or_rust_executions"]) and evidence["native_or_rust_executions"]==0 and
                 exact_int(evidence["reader_writes"]) and evidence["reader_writes"]==0,
                 "exact source transform and complete selected verifier body")
        summary=dict(status=evidence["status"],part=part,checked_names=list(names),proof=rc.pin(raw),
                     pid=proof["pid"],parent_pid=proof["ppid"],pgid=proof["pgid"],guard_probes=12,
                     native_or_rust_executions=0,reader_writes=0)
        for kind in ("stdout","stderr"):
            stream=rc.read(folder/kind)
            rc.check(row[kind]==rc.pin(stream) and stream==(rc.enc(summary) if kind=="stdout" else b""),
                     "complete actual pure-reader output streams")
        rc.check(set(rc.files(folder))=={"stdout","stderr","process.json","READBACK.json"},"complete per-worker proof set")
        values.append(evidence);snapshots.append(proof["before"])
    rc.check(set(rc.files(output/"parts"))=={"processes.json"}|
             {str(i)+"/"+n for i in range(2) for n in ("stdout","stderr","process.json","READBACK.json")},
             "whole exact worker evidence directory")
    rc.check(snapshots[0]==snapshots[1],"both complete unchanged physical snapshots cover identical inputs")
    for k in ("full_retained_scope","physical_process","failed_verification","source_transform","retained_source_sha256"):
        rc.check(values[0][k]==values[1][k],"complete shared qualification identical across partitions: "+k)
    selected=[n for e in values for n in e["checked_names"]]
    rc.check(len(selected)==len(prepared["all_names"])==17 and len(set(selected))==17 and set(selected)==set(prepared["all_names"]),
             "no omission or duplication of all original control rows")
    # Reopen every full physical byte once at join, in addition to both complete child snapshots.
    current=rc.files(complete)
    observed={k.split(":",1)[1]:dict(bytes=v["bytes"],sha256=v["sha256"],mode=stat.S_IMODE(v["mode"]))
              for k,v in snapshots[0].items() if k.startswith("0:") and v["sha256"] is not None}
    rc.check(observed==current,"entire 14GB retained domain agrees with both actual guarded readers")
    current_source=rc.files(rc.ROOT)
    source_observed={k.split(":",1)[1]:dict(bytes=v["bytes"],sha256=v["sha256"],mode=stat.S_IMODE(v["mode"]))
              for k,v in snapshots[0].items() if k.startswith("1:") and v["sha256"] is not None}
    rc.check(source_observed==current_source,"whole current source identical to both child guard observations")
    admission_observed={k.split(":",1)[1]:dict(bytes=v["bytes"],sha256=v["sha256"],mode=stat.S_IMODE(v["mode"]))
              for k,v in snapshots[0].items() if k.startswith("2:") and v["sha256"] is not None}
    rc.check(admission_observed==rc.files(output/"admission") and set(admission_observed)=={"PARENT.json"},
             "complete private parent record stays bound")
    rc.check(all(k.split(":",1)[0] in ("0","1","2") for k in snapshots[0]),"only complete known guard roots")
    scope=values[0]["full_retained_scope"]
    rc.check(scope["status"]=="COMPLETE_PHYSICAL_PUBLISHER_CONTROLS_PASS" and scope["admissions"]==2 and scope["refusals"]==15 and
             scope["guard_probes"]==204,"full original physical-control domain retained")
    return dict(status="PRIVATE_PUBLISH_ARCHIVE_ANCHOR_QUALIFIED",source_manifest_sha256=identity,
                retained_source_sha256=prepared["old_identity"],checked_names=list(prepared["all_names"]),
                physical=scope,physical_process=values[0]["physical_process"],preserved_failed_verification=values[0]["failed_verification"],
                source_transform=prepared["transform"],parent=parent,workers=records,
                whole_guarded_input_entries=len(snapshots[0]),complete_reader_guard_probes=24,original_physical_guard_probes=204,
                actual_input_files=len(current),actual_input_bytes=sum(r["bytes"] for r in current.values()),
                native_or_rust_executions=0,reader_writes=0,namespace_version_qualified=False,archive_store_qualified=False,
                hot_cache_qualified=False,begin_finish_caller_qualified=False,public_handler_qualified=False,whole_runtime_replaced=False)

def custody(output,result):
    rowset=rc.loads(rc.read(output/"processes/read/processes.json"));rc.check(len(rowset)==1,"one actual bounded reader parent")
    row=rowset[0];parent=result["parent"]
    rc.check(row["name"]=="publisher-parallel-read" and row["cwd"]==parent["source_root"] and len(row["argv"])==8 and
             type(row["argv"][0]) is str and row["argv"][0].startswith("/") and
             row["argv"][1:]==["-I","-B",parent["source_root"]+"/capture.py","--complete",parent["complete_root"],
                              "--output",parent["output_root"]] and
             row["stdin"] is None and type(row["exit_code"]) is int and row["exit_code"]==0 and
             row["completed"] is True and row["timed_out"] is False and
             type(row["timeout_seconds"]) is int and row["timeout_seconds"]==180 and
             type(row["elapsed_seconds"]) in (int,float) and math.isfinite(row["elapsed_seconds"]) and 0<row["elapsed_seconds"]<=180 and
             all(type(row[k]) is int and row[k]==parent[k] for k in ("pid","parent_pid","pgid")),
             "actual parent command, complete custody, and original deadline")
    for kind in ("stdout","stderr"):
        name="publisher-parallel-read."+kind;raw=rc.read(output/"processes/read"/name)
        rc.check(row[kind]==dict(file=name,**rc.pin(raw)) and raw==(rc.enc(result) if kind=="stdout" else b""),
                 "full actual bounded parent stream")
    rc.check(set(rc.files(output/"processes/read"))=={"processes.json","publisher-parallel-read.stdout","publisher-parallel-read.stderr"},
             "entire bounded parent receipt directory")
    return row
