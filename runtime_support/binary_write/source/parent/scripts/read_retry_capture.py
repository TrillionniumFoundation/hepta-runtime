"""Independent DATA admission of actual EINTR and explicit cancellation controls."""
import gzip
import hashlib
import struct
from evidence_common import decode,encoded,pin,require
from protocol import U
from read_kernel import read_trace


def read_retry(folder,binding,case,lane,store,executable):
    from read_parent_capture import all_buffers,actual_faults,filesystem,parent_kernel,same
    raw=(folder/"RETRY.json").read_bytes()
    same(pin(folder/"RETRY.json"),binding["case"],"entire fixed retry capture")
    row=decode(raw);all_buffers(row,store)
    same(row["input"],case,"full frozen retry input")
    require(row["lane"]==lane and row["elapsed_ns"]<60_000_000_000 and row["whole_process_exited"]is True
            and row["normal_application_result"]is False,"bounded explicit retry-control terminal")
    process=row["process"]
    same(process,decode((folder/"carrier-process.json").read_bytes()),"whole retry process authority")
    require(process["returncode"]==-15 and process["same_outer_process_group"]is True,"actual retry cancellation process exit")
    same(process["observer_wait"],dict(kind="SIGCHLD-pipe",parent_only=True,target_signal_replacement=False),"exact parent-only retry observer wait mechanism")
    same(process["binary"],executable if lane=="native-observed"else dict(bytes=8020928,
        sha256="e50d468e8b0adfb05733f5b87b3cff34829c4a8c1aea50c865aa8bdfe4bb150f"),"actual retry executable")
    for name in("stdin","stderr"):same(pin(folder/("carrier."+name)),process["streams"][name],"entire retry stream")
    require((folder/"carrier.stderr").read_bytes()==b"","actual cancelled application stderr")
    for name in("stdout","journal"):
        digest=hashlib.sha256();count=0
        with gzip.open(folder/("carrier."+name+".gz"),"rb")as stream:
            while part:=stream.read(1<<20):digest.update(part);count+=len(part)
        same(dict(bytes=count,sha256=digest.hexdigest()),process[name]["raw"],"all cancelled raw stream bytes")
        same(pin(folder/("carrier."+name+".gz")),process[name]["compressed"],"complete cancelled stream archive")
    exchanges=[decode(line)for line in(folder/"exchanges.jsonl").read_bytes().splitlines()]
    all_buffers(exchanges,store)
    require([item["command"]for item in exchanges]==[8,18]and [item["exchange"]for item in exchanges]==[1,2]
            and all(item["application"]is False for item in exchanges),"only two control responses completed before the retry")
    packet=store.get(row["application_input"])
    frame=b"HBWTFQ01"+struct.pack("<7Q",1,0,len(packet),0,0,0,0)+packet
    frame=struct.pack("<Q",len(frame))+frame
    require((folder/"carrier.stdin").read_bytes()==b"".join(store.get(item["input"])for item in exchanges)+frame,
            "complete actual cancelled invocation input")
    with gzip.open(folder/"carrier.stdout.gz","rb")as stream:
        require(stream.read()==b"".join(store.get(item["output"])for item in exchanges),"cancelled invocation emitted a result")
    kernel=read_trace(folder,process["kernel"],expected_returncode=-15)
    require(kernel["application_calls"]==1 and [item["signal"]for item in kernel["signals"]]==[15],
            "actual original/native entry and unchanged explicit SIGTERM")
    actual_faults(kernel,case)
    attempts=[call for call in kernel["calls"]if call["number"]==257 and call.get("exit",{}).get("result")==-4]
    require(len(attempts)==case["actual_eintr_returns_before_sigterm"]==8,"complete actual retry count")
    derived=[]
    for call in attempts:
        phase=call["phase"]
        require(phase is not None and phase["magic_hex"]==b"HBPWHK01".hex()
                and phase["words"][5]==case["retry_phase"],"actual EINTR belongs to the frozen open")
        derived.append(dict(ordinal=call["ordinal"],phase=phase,args=call["args"],result=-4))
    same(derived,row["actual_eintr"],"all actual syscall retry records")
    cancel=row["cancellation"]
    require(cancel==process["explicit_cancellation"] and cancel["signal"]==15 and cancel["after_actual_eintr_returns"]==8
            and cancel["target_pid"]==process["pid"]and cancel["result_replacements"]==cancel["memory_or_register_writes"]==0,
            "explicit stop is separate from application success")
    require(row["hooks"]["eof"]==[],"cancelled process cannot claim natural EOF witness")
    notifications=[];acks=[]
    for call in kernel["calls"]:
        if "exit"not in call:continue
        if call["number"]==1 and call["args"][0]==4:
            require(call["exit"]["result"]==64,"complete actual retry notification")
            notifications.append(call["input_spans"]["notification"]["raw"])
        elif call["number"]==0 and call["args"][0]==5:
            require(call["exit"]["result"]==8,"complete actual retry acknowledgement")
            acks.append(call["output_spans"]["ack"]["raw"])
    require(notifications==[store.get(item["raw"])for item in row["hooks"]["events"]]
            and acks==[bytes(8)]*len(notifications),"all retry observer ACKs are actual zero bytes")
    same(filesystem(row["after_exit"]),filesystem(row["setup"]),"retry/cancellation changed target filesystem")
    row["independent_parent_kernel"]=parent_kernel(kernel,lane!="native-observed")
    require((folder/"RETRY.json").read_bytes()==raw,"retry raw custody changed")
    return row
