#!/usr/bin/env python3
"""Read complete partial captures and prove exactly which calls were never sent."""
from pathlib import Path
import gzip,hashlib,struct
from evidence_common import require,decode,pin,source_evidence
from buffer_store import Reader
import restore_original
from cases import group
U=lambda b,o:struct.unpack_from("<Q",b,o)[0]
def refs(value,reader):
    if isinstance(value,dict):
        if set(value)=={"bytes","sha256","blocks"}:reader.get(value)
        else:
            for v in value.values():refs(v,reader)
    elif isinstance(value,list):
        for v in value:refs(v,reader)
def verify(source,work,name):
    source,work=Path(source),Path(work);bound=restore_original.selection(source,name)
    archive=restore_original.verify(source,work,bound)
    root=work/"original/restored";old=root/"source";run=root/"run";data=run/"application"
    identity=source_evidence(old)
    require(identity["manifest"]["sha256"]==bound["manifest_sha256"],"whole prior frozen source")
    gate=decode((run/"GATE.json").read_bytes());processes=decode((run/"processes/processes.json").read_bytes())
    require(processes==gate["processes"]and[(x["name"],x["timeout_seconds"])for x in processes]==
        [("source-check",60),("build-fetch",60),("build-unpack",180),("build-admission",180),("capture-original",180)],
        "original lane failure preceded native lane")
    for p in processes:
        require(p["completed"]is True and p["timed_out"]is False and p["pid"]==p["pgid"]
            and p["exit_code"]==(1 if p["name"]=="capture-original"else 0),"natural terminal old processes")
        for suffix in("stdout","stderr"):
            item=p[suffix]
            require(pin(run/"processes"/item["file"])=={k:item[k]for k in("bytes","sha256")},"whole old process streams")
    require(not(data/"native").exists()and not(data/"original/CAPTURE.json").exists(),"no completed or partial native lane")
    require(pin(data/"production/file-info-at-callable.elf")==decode((old/"BUILD_REUSE.json").read_bytes())["elf"],
        "retained production is an unexecuted copied ELF")
    folder=data/"original";failure=decode((folder/"FAILURE.json").read_bytes())
    expected=group(name);completed_ids=bound["expected_completed_original_ids"]
    require(failure["status"]=="FAIL"and failure["role"]=="original"and failure["group"]==name
        and failure["completed_cases"]==len(completed_ids)
        and failure["current_input"]==next(q for q in expected if q["id"]==bound["expected_failed_id"])
        and failure["message"]=="private fixture command differs","exact original command-admission failure")
    with gzip.open(folder/"cases.jsonl.gz","rb")as f:lines=list(f)
    require(all(x.endswith(b"\n")for x in lines),"complete retained successful case lines")
    values=[decode(x)for x in lines]
    require([x["input"]["id"]for x in values]==completed_ids,"exact original completed prefix")
    stored=Reader(folder/"buffers");complete=[];all_commands={}
    for line,case in zip(lines,values):
        require(case["input"]==next(q for q in expected if q["id"]==case["input"]["id"])
            and case["whole_process_exited"]is True and case["process"]["returncode"]==0,
            "unchanged completed original input and process exit")
        refs(case,stored);where=folder/case["process_path"]
        require(decode((where/"carrier-process.json").read_bytes())==case["process"],"whole actual completed process receipt")
        complete.append(dict(id=case["input"]["id"],case_line=dict(bytes=len(line),sha256=hashlib.sha256(line).hexdigest()),
            process=pin(where/"carrier-process.json"),invocations=len(case["actual"]["chain"]["invocations"])))
    ids=[*completed_ids,bound["expected_failed_id"]]
    require({p.name for p in(folder/"carriers").iterdir()}=={str(x)for x in ids},"only completed prefix and one administrative fixture")
    for cid in ids:
        where=folder/"carriers"/str(cid)
        exchanges=[decode(x)for x in(where/"exchanges.jsonl").read_bytes().splitlines()]
        sent=(where/"carrier.stdin").read_bytes()
        with gzip.open(where/"carrier.stdout.gz","rb")as f:received=f.read()
        s=r=0;commands=[]
        for ordinal,x in enumerate(exchanges,1):
            require(x["exchange"]==ordinal and x["session"]in(0,1),"whole ordered actual exchange")
            a=stored.get(x["input"]);b=stored.get(x["output"])
            require(sent[s:s+len(a)]==a and received[r:r+len(b)]==b,"complete stdin/stdout equals every saved exchange")
            s+=len(a);r+=len(b)
            require(len(a)>=72 and U(a,0)==len(a)-8 and a[8:16]==b"HIFXFQ01"
                and U(a,16)==x["command"]and U(a,24)==x["session"]and U(a,32)==len(a)-72
                and a[40:72]==bytes(32),"complete fixed old fixture command")
            require(b[:8]==b"HIFXFR01"and U(b,16)==len(b)-64,"whole original fixture reply")
            commands.append(x["command"])
        require(s==len(sent)and r==len(received),"no unrecorded original input or output suffix")
        all_commands[str(cid)]=commands
        if cid==bound["expected_failed_id"]:
            require(commands==[8,10,14]and 1 not in commands,"failed input never sent any application command")
            receipt=decode((where/"carrier-failure-process.json").read_bytes())
            require(receipt["failed"]is True and receipt["streams"]["stdin"]==pin(where/"carrier.stdin")
                and receipt["streams"]["stderr"]==pin(where/"carrier.stderr")
                and receipt["stdout"]["raw"]==dict(bytes=len(received),sha256=hashlib.sha256(received).hexdigest()),
                "whole failed administrative fixture receipt")
            with gzip.open(where/"carrier.journal.gz","rb")as f:journal=f.read()
            require(not journal and not(where/"carrier.stderr").read_bytes(),"failed fixture executed no observed original helper")
        else:
            require(commands.count(1)==1,"completed prefix has exactly one original invocation")
            receipt=decode((where/"carrier-process.json").read_bytes())
            require(receipt["streams"]["stdin"]==pin(where/"carrier.stdin")and receipt["streams"]["stderr"]==pin(where/"carrier.stderr")
                and receipt["stdout"]["compressed"]==pin(where/"carrier.stdout.gz")
                and receipt["stdout"]["raw"]==dict(bytes=len(received),sha256=hashlib.sha256(received).hexdigest()),
                "complete successful original streams")
            with gzip.open(where/"carrier.journal.gz","rb")as f:journal=f.read()
            require(receipt["journal"]["compressed"]==pin(where/"carrier.journal.gz")
                and receipt["journal"]["raw"]==dict(bytes=len(journal),sha256=hashlib.sha256(journal).hexdigest()),
                "complete successful original journal")
    # The failed run_case never returned its partial chain. Every raw block,
    # including unreferenced administrative snapshots, remains fully preserved.
    blocks=0;logical=0
    for path in sorted((folder/"buffers").iterdir()):
        require(path.is_file()and not path.is_symlink()and path.suffix==".gz","ordinary full original block")
        with gzip.open(path,"rb")as f:raw=f.read(65537);require(not f.read(1),"no extra block suffix")
        require(0<len(raw)<=65536 and hashlib.sha256(raw).hexdigest()==path.stem,"all complete referenced or partial blocks")
        blocks+=1;logical+=len(raw)
    require(stored.used.issubset({p.stem for p in(folder/"buffers").iterdir()}),"all completed references retained")
    return dict(status="COMPLETE_INFO_PARTIAL_BOUNDARY_PASS",group=name,archive=archive,source=identity,
        retained_complete_original=complete,actual_original_invocations=len(complete),actual_native_invocations=0,
        never_executed_original_ids=[q["id"]for q in expected if q["id"]not in completed_ids],
        never_executed_native_ids=[q["id"]for q in expected],all_fixture_commands=all_commands,
        full_buffer_blocks=blocks,full_block_bytes=logical,new_application_calls=0,
        process_administration_is_not_application_execution=True,first_failure_preserved=True)
