#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Complete retained native process, lifecycle, files and original direct projection."""
from pathlib import Path
import gzip,stat,struct
from common import canonical,decode,pin,require,sha
from buffer_store import Reader
from domain import body,cases,declaration,frame,DIRECT
import read_journal
U=lambda raw,at:struct.unpack_from("<Q",raw,at)[0]
PACKAGE=Path(__file__).resolve().parents[1]
def submissions(case):
    name=case["name"];out=[]
    if name.startswith("queued") or name in ("close_queued","fifo_growth"):out.append((999,"blocker/slot.txt"))
    if name!="unpolled_drop":out.append((10,"held/a.txt"))
    if name=="two_started_drop_first":out.append((11,"held/b.txt"))
    if name in ("fifo_growth","close_queued"):
        count=33 if name=="fifo_growth" else 3
        out.extend((n,"held/q-%02d.txt"%n) for n in range(11,10+count))
    if name in ("started_drop_then_second","queued_drop_then_second","borrow_lifetime"):out.append((11,"free/c.txt"))
    return out
def original():
    rows=[decode(line) for line in (PACKAGE/"reference/ORIGINAL_OBSERVATIONS.jsonl").read_bytes().splitlines()]
    require(len(rows)==30 and [r["case"] for r in rows]==list(range(30)),"full retained original observation set")
    handoff=decode((PACKAGE/"reference/FINAL_HANDOFF.json").read_bytes())
    return {r["name"]:r for r in rows if r["era"]=="direct"}
def verify_case(root,case,fixture,binary,binary_path):
    store=Reader(root/"buffers")
    result=decode((root/"RESULT.json").read_bytes())
    commands=decode((root/"COMMANDS.json").read_bytes());host=decode((root/"HOST.json").read_bytes())
    snapshots=decode((root/"FILESYSTEM.json").read_bytes())
    require(result["case"]==case["case"] and result["name"]==case["name"] and result["observer"]==case["observer"]
        and result["commands"]==len(commands),"actual case identity")
    require(result["files"]=={n:pin(root/n) for n in ("COMMANDS.json","HOST.json","FILESYSTEM.json")},"whole case file bindings")
    process=decode((root/"process/PROCESS.json").read_bytes())
    require(process["command"]==[binary_path] and process["cwd"]==case["root"],"exact process launch")
    require(process==result["process"] and process["exit_code"]==0 and process["timed_out"] is False
        and process["expected_success"] is True and process["cleanup_error"] is None
        and process["process_group_gone"] is True and process["private_journal_fd"]==3
        and process["timeout_seconds"]==180 and process["exchange_limit_seconds"]==60
        and 0<process["elapsed_seconds"]<=180,"complete owned process terminal and unchanged budgets")
    require(process["stdin"]==pin(root/"process/stdin") and process["stdout_gzip"]==pin(root/"process/stdout.gz")
        and process["stderr"]==pin(root/"process/stderr") and process["journal"]==pin(root/"process/journal.bin")
        and (root/"process/stderr").read_bytes()==b"","whole process streams")
    stdin=[];stdout=[];jobs={};tags={};taken={};drops=set();labels=[];seen_submit=[]
    last_journal=0;reply_address=None
    for i,row in enumerate(commands):
        require(row["number"]==i and 0<=row["elapsed_ns"]<=60_000_000_000
            and 0<=row["journal_before"]<=row["journal_after"]<=process["journal"]["bytes"]
            and row["journal_before"]>=last_journal,"complete exchange ordering/budget/journal ranges")
        last_journal=row["journal_after"]
        request=store.get(row["request"]);response=store.get(row["response"]);stdin.append(request);stdout.append(response)
        require(len(request)>=72 and U(request,0)==len(request)-8 and request[8:16]==b"HPTWFQ01"
            and U(request,64)==0 and len(request)==72+U(request,40),"complete actual fixture request")
        command=U(request,16);job=U(request,24);tag=U(request,32);argument=U(request,48);flags=U(request,56)
        require((command,job,tag)==(row["command"],row["job"],row["tag"])
            and response[:8]==b"HPTWFR01" and len(response)==64+U(response,16)
            and U(response,24)==command and U(response,32)==job and U(response,48)==i+1
            and U(response,56)==0,"complete response/request identity")
        raw=U(response,8);payload=response[64:];labels.append(row["label"])
        require(0<=raw<=0xffffffff,"exact u32 native result")
        if i==0:
            require(request==frame(0,argument=case["limit"],flags=0 if case["observer"] else 1)
                and raw==0 and not payload and U(response,40)>0,"actual fixed private pool create")
            reply_address=U(response,40)
        elif command!=8 or raw!=0:require(U(response,40)==reply_address,"same actual pool throughout lifecycle")
        if command==1:
            require(job==0 and tag!=0 and argument==flags==0 and raw==320 and len(payload)==320
                and payload[:8]==b"HPTWR001" and U(payload,24)==1,"actual enqueue response")
            if tag==4444:
                require(case["name"]=="close_queued" and request==frame(1,tag=4444,payload=body(case["root"],"free/denied.txt"))
                    and U(payload,16)==1 and U(payload,32)==0,"real post-close enqueue refusal")
            else:
                expected=submissions(case)[len(seen_submit)]
                require(tag==expected[0] and request==frame(1,tag=tag,payload=body(case["root"],expected[1]))
                    and U(payload,16)==0,"input-only complete submitted job")
                issued=U(payload,32);require(issued>0 and issued not in jobs and tag not in tags,"actual job generation uniqueness")
                jobs[issued]=dict(tag=tag,input=request[72:],path=expected[1]);tags[tag]=issued;seen_submit.append(expected)
        if command in (3,4,9) and raw==320:
            require(len(payload)>=320 and payload[:8]==b"HPTWR001" and U(payload,8)==320
                and U(payload,24)=={3:7,4:8,9:12}[command],"whole actual pool result")
            if command==4 and U(payload,16)==0:
                require(job in jobs and job not in taken and job not in drops and len(payload)>=384
                    and payload[320:328]==b"HPTWB001" and U(payload,328)==64 and U(payload,336)==job
                    and U(payload,368)==jobs[job]["tag"] and U(payload,376)==0
                    and U(payload,344)==64 and U(payload,352)>0 and len(payload)==384+U(payload,360),
                    "actual full borrowed publication output")
                data=payload[384:]
                require(data[:8]==b"HTPBS001" and U(data,8) in (0,3) and not any(data[24:56])
                    and len(data)==64+U(data,56),"complete actual publication body result")
                taken[job]=data
            else:require(len(payload)==320,"pending/control cannot invent trailing bytes")
        if command==6 and raw==0:
            require(job in jobs and job not in taken,"actual Drop of an issued awaiting job");drops.add(job)
        if command not in (0,1):require(argument==flags==tag==0,"private control reserved words")
    require(seen_submit==submissions(case),"entire frozen submit domain")
    require(result["jobs"]=={str(k):v for k,v in tags.items()} and result["taken"]==sorted(jobs[j]["tag"] for j in taken)
        and result["dropped"]==sorted(jobs[j]["tag"] for j in drops),"complete actual job index")
    require(b"".join(stdin)==(root/"process/stdin").read_bytes(),"all actual stdin bytes consumed")
    with gzip.open(root/"process/stdout.gz","rb") as stream:wire=stream.read()
    require(wire==b"".join(stdout) and process["full_stdout"]==dict(bytes=len(wire),sha256=sha(wire)),"all actual stdout bytes consumed")
    require(commands[-1]["label"]=="destroy-final" and U(stdout[-1],8)==0 and U(stdout[-1],40)==0,"actual final pool destruction")
    journal=read_journal.verify(root/"process/journal.bin",case,commands,jobs,process["pid"])
    if case["observer"]:
        for job,raw in taken.items():require(jobs[job]["terminal"]==raw,"borrow bytes equal the complete actual worker terminal")
    require(set(p.name for p in (root/"process").iterdir())=={"stdin","stdout.gz","stderr","journal.bin","PROCESS.json"},"complete process file set")
    require([s["name"] for s in snapshots]==(["initial","all-bodies-reaped"] if case["name"]=="unpolled_drop"
        else ["initial","actual-first-worker-suspended","all-bodies-reaped"]),"all fixed filesystem boundaries")
    files=[]
    for number,snapshot in enumerate(snapshots):
        paths=[r["path"] for r in snapshot["files"]];require(len(paths)==len(set(paths)) and paths[0]==".","complete snapshot paths")
        for row in snapshot["files"]:
            require(row["kind"] in ("dir","file") and row["xattrs"]=={},"ordinary owned fixture inode kind/xattrs")
            if row["kind"]=="file":
                data=store.get(row["data"]);require(len(data)==row["stat"]["size"],"full file extent")
                if number==len(snapshots)-1:files.append(dict(path=row["path"],bytes=len(data),sha256=sha(data),mode=row["stat"]["mode"]))
            else:require(row["entries"]==sorted(row["entries"]),"complete directory entry ordering")
    require(not any(r["kind"]=="file" for r in snapshots[0]["files"]),"initial fixture contains no synthesized file effect")
    for row in snapshots[-1]["files"]:
        at=fixture if row["path"]=="." else fixture/row["path"];info=at.lstat()
        require(stat.S_IFMT(info.st_mode)==stat.S_IFMT(row["stat"]["mode"]) and info.st_mode==row["stat"]["mode"]
            and (row["kind"]!="file" or info.st_size==row["stat"]["size"])
            and info.st_mtime_ns==row["stat"]["mtime_ns"],"full retained mode/file-size/mtime")
        require(sorted(os_name for os_name in __import__("os").listxattr(at,follow_symlinks=False))==[],"retained xattrs")
        if row["kind"]=="file":require(at.read_bytes()==store.get(row["data"]),"retained full filesystem bytes")
        else:require(sorted(p.name for p in at.iterdir())==row["entries"],"retained complete directory entries")
    lockrows=[x for x in host if x["event"]=="holder_locked"];unlocks=[x for x in host if x["event"]=="holder_unlocked"]
    require({r["name"] for r in lockrows}=={r["name"] for r in unlocks}
        and len(lockrows)==len(unlocks) and len({r["name"] for r in lockrows})==len(lockrows),"complete owned lock lifetime")
    for lock in lockrows:
        unlock=next(r for r in unlocks if r["name"]==lock["name"])
        require(lock["identity"]==unlock["identity"] and lock["monotonic_ns"]<unlock["monotonic_ns"],"same actual held descriptor identity")
    for row in host:
        if row["event"]=="actual_flock_observation":
            v=row["observation"];lock=next(x for x in lockrows if str(Path(case["root"])/x["name"])==v["path"])
            require(v["parent"]==process["pid"] and (v["dev"],v["ino"])==(lock["identity"]["dev"],lock["identity"]["ino"]),"actual held target inode")
            matching=[]
            for x in v["rows"]:
                if x.get("matching"):
                    parts=x["syscall"].split()
                    require(int(parts[0],0)==73 and int(parts[1],0)==x["fd"] and int(parts[2],0)==2
                        and (x["dev"],x["ino"])==(v["dev"],v["ino"]),"actual blocked flock syscall and descriptor")
                    matching.append(x["pid"])
            require(matching==v["matching"],"complete actual blocked child set")
    if case["name"]!="unpolled_drop":
        matched=[r for r in host if r["event"]=="actual_flock_observation" and len(r["observation"]["matching"])>=r["required"]]
        require(matched and any(r["observation"]["path"]==str(Path(case["root"])/"held") for r in matched),"actual target blocking observed")
    destroyed=[r for r in host if r["event"]=="pool_destroyed"];require(len(destroyed)==1,"one actual destruction observation")
    final=store.get(destroyed[0]["final_state"]);require(len(final)==320 and U(final,160)==U(final,168)==0,"no live/active at actual retirement")
    paired=None
    if case["original_direct"] is not None:
        old=original()[case["original_direct"]]
        observed=[{k:r[k] for k in ("path","bytes","sha256")} for r in files if not r["path"].startswith("blocker/")]
        require(observed==old["final_files"],"complete final file bytes equal retained actual current Rust direct domain")
        require(len(jobs)-(999 in tags)==old["observed_futures"]
            and len(drops)==old["dropped_without_return"]
            and len(taken)-(999 in tags)==old["returned"],"actual submitted/Drop/returned lifecycle projection")
        paired=dict(original_case=old["case"],compared_fields=["complete final file bytes","submitted futures","Drop without return","normal returns"],
            cache_or_sdk_simulated=False,blocker_difference="native owned publication blocker; original actual Condvar blocking task")
    needed={"create","close-final","destroy-final"}
    if case["name"]=="invalid_lifecycle":needed|={"release-before-take","destroy-while-running","unknown-issued-id","duplicate-take","drop-after-take","release-valid","poll-after-retirement"}
    if case["name"]=="borrow_lifetime":needed|={"borrowed-output-before-other-job","borrowed-output-after-other-job","drop-after-take","destroy-with-borrow","release-held-borrow","duplicate-release"}
    require(needed<=set(labels),"complete original private lifecycle controls")
    bylabel={r["label"]:(store.get(r["request"]),store.get(r["response"])) for r in commands if r["label"] in needed}
    for name in ("release-before-take","unknown-issued-id","duplicate-take","drop-after-take","duplicate-release","poll-after-retirement"):
        if name in needed:require(U(bylabel[name][1],8)==0xffffffff,"actual raw lifecycle refusal")
    for name in ("destroy-while-running","destroy-with-borrow"):
        if name in needed:require(U(bylabel[name][1],8)==0xfffffffd,"actual native storage BUSY")
    if case["name"]=="borrow_lifetime":
        require(bylabel["borrowed-output-before-other-job"][1][64:]==bylabel["borrowed-output-after-other-job"][1][64:],"full borrowed output remains unchanged")
    expected_images=2*len(commands)+1+sum(r["kind"]=="file" for s in snapshots for r in s["files"])
    expected_bytes=sum(r["request"]["bytes"]+r["response"]["bytes"] for r in commands)+320+sum(
        r["data"]["bytes"] for s in snapshots for r in s["files"] if r["kind"]=="file")
    require(result["complete_buffer_images"]==expected_images and result["logical_buffer_bytes"]==expected_bytes,
        "exact complete observed-buffer accounting")
    complete=store.finish()
    require(set(p.name for p in root.iterdir())=={"buffers","COMMANDS.json","HOST.json","FILESYSTEM.json","process","RESULT.json"},"complete case evidence set")
    return dict(case=case["case"],name=case["name"],observer=case["observer"],commands=len(commands),
        jobs=len(jobs),journal=journal,files=files,paired=paired,complete_buffers=complete)
def verify(root,expected_binary):
    root=Path(root);plan=decode((root/"PLAN.json").read_bytes())
    require(plan["declaration"]==declaration() and plan["binary"]==expected_binary,"fixed source/domain/binary")
    planned=cases(plan["fixture_root"]);selection=plan["observer"]
    expected=[c for c in planned if selection=="all" or c["observer"]==(selection=="on")]
    require(selection in ("on","off","all") and plan["cases"]==expected,"full immutable input domain")
    require(set(p.name for p in root.iterdir())=={"PLAN.json","RESULTS.json","SUMMARY.json","cases","fixtures"},"complete capture root")
    require({p.name for p in (root/"cases").iterdir()}=={"%03d"%c["case"] for c in expected}
        and {p.name for p in (root/"fixtures").iterdir()}=={Path(c["root"]).name for c in expected},"complete case/fixture directory sets")
    result=[verify_case(root/"cases"/("%03d"%c["case"]),c,root/"fixtures"/Path(c["root"]).name,expected_binary,plan["binary_path"]) for c in expected]
    saved=decode((root/"RESULTS.json").read_bytes())
    require(saved==[decode((root/"cases"/("%03d"%c["case"])/"RESULT.json").read_bytes()) for c in expected],"actual case index")
    summary=dict(status="PRIVATE_NATIVE_WORKER_CAPTURE_COMPLETE",cases=len(result),commands=sum(x["commands"] for x in result),
        observer=selection,process_limit_seconds=180,exchange_limit_seconds=60,
        original_rust_executed=False,public_async_qualified=False,full_sdk=False)
    require(decode((root/"SUMMARY.json").read_bytes())==summary,"complete scope-correct summary")
    return dict(status="COMPLETE_PRIVATE_NATIVE_WORKER_READ_PASS",cases=len(result),rows=result,
        hia_or_rust_executed_by_reader=False,public_async_qualified=False,full_sdk=False)
