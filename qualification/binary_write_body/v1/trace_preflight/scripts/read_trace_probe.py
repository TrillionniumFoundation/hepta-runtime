"""Pure original archive and exact kernel evidence checks for the observer probes."""
from pathlib import Path
import gzip,hashlib,struct
from evidence_common import decode,pin,require
from buffer_store import Reader
from read_kernel import read_trace
from protocol import U
def verify(source,folder,case):
    folder=Path(folder);row=decode((folder/"CAPTURE.json").read_bytes())
    require(row["status"]=="CAPTURED"and row["case"]==case and row["observer_probe_calls"]==1
        and row["target_hia_application_calls"]==row["original_write_application_calls"]==0,"complete frozen observer probe")
    receipt=row["receipt"];store=Reader(folder/"buffers")
    exchanges=[decode(x)for x in(folder/"exchanges.jsonl").read_bytes().splitlines()]
    require(receipt["returncode"]==0 and receipt["elapsed_ns"]<=60000000000
        and receipt["same_outer_process_group"]and receipt["pid"]!=receipt["parent_pgid"],"actual owned observer probe")
    stdin=b"";stdout=b""
    for index,q in enumerate(exchanges,1):
        require(q["exchange"]==index and 0<=q["elapsed_ns"]<=60000000000,"actual exchange ordering/budget")
        a=store.get(q["input"]);b=store.get(q["output"]);stdin+=a;stdout+=b
        require(a[8:16]==b"HBWTFQ01"and U(a,0)==len(a)-8 and U(a,16)==q["command"]
            and b[:8]==b"HBWTFR01"and U(b,16)==len(b)-64,"complete actual private frames")
    require((folder/"carrier.stdin").read_bytes()==stdin and gzip.open(folder/"carrier.stdout.gz","rb").read()==stdout,
        "all actual input/output stream bytes")
    require(pin(folder/"carrier.stdin")==receipt["streams"]["stdin"]and pin(folder/"carrier.stderr")==receipt["streams"]["stderr"]
        and(folder/"carrier.stderr").read_bytes()==b"" and pin(folder/"carrier.stdout.gz")==receipt["stdout"]["compressed"]
        and dict(bytes=len(stdout),sha256=hashlib.sha256(stdout).hexdigest())==receipt["stdout"]["raw"],"complete actual streams")
    journal=gzip.open(folder/"carrier.journal.gz","rb").read()
    require(pin(folder/"carrier.journal.gz")==receipt["journal"]["compressed"]
        and dict(bytes=len(journal),sha256=hashlib.sha256(journal).hexdigest())==receipt["journal"]["raw"]
        and decode(journal)==dict(actual_kernel_probe=case["kind"],bytes=len(bytes.fromhex(case["data_hex"]))),
        "complete actual probe journal")
    require(len(row["eof"])==1,"one actual EOF survivor witness")
    require(store.get(row["eof"][0]["raw"])==b"HBWTEOF1"+bytes(56)and store.get(row["eof"][0]["ack"])==bytes(8),
        "actual zero-only EOF ACK")
    buffers=store.finish();trace=read_trace(folder,receipt["kernel"])
    require(trace["application_calls"]==1,"one actual kernel probe")
    mark=next(x for x in trace["marks"]if x["application"])
    calls=[x for x in trace["calls"]if x["scope"]==mark["scope"]and"exit"in x]
    result=row["result"];fd=result["fd"]
    random=[x for x in calls if x["number"]==318 and x["args"][1]==16 and x["args"][2]==0]
    require(len(random)==1 and random[0]["exit"]["result"]==16
        and random[0]["output_spans"]["random"]["raw"].hex()==result["random_hex"],"UUID bytes came from actual kernel")
    require(result["signal_profile"]=={"13":1,"25":1},"actual CPython signal profile")
    data=bytes.fromhex(case["data_hex"]);observed=bytes.fromhex(row["file_hex"])
    require((folder/"probe.file").read_bytes()==observed and pin(folder/"probe.file")==row["file"],"actual final probe file")
    stat_calls=[x for x in calls if x["number"]in(5,262)and x["args"][0]==fd]
    require(stat_calls,"actual C/Python stat boundary is present")
    if case["kind"]in("append-fileio","fd-zero"):
        require(result["read_hex"]==data.hex()==observed.hex()and result["text_count"]==len(data),"actual FileIO/BufferedReader bytes")
        require(any(x["number"]==8 and x["args"][:3]==[fd,0,2]and x["exit"]["result"]==0 for x in calls),
            "actual FileIO append SEEK_END syscall observed")
        require(any(x["number"]==16 and x["args"][:2]==[fd,0x5401]for x in calls),"actual C-layer isatty observed")
        require(any(x["number"]==1 and x["args"][0]==fd and x["input_spans"]["write"]["raw"]==data
            and x["exit"]["result"]==len(data)for x in calls),"actual buffered text write")
        require(sum(x["exit"]["result"]==0 for x in stat_calls)>=2,"complete FileIO init/user fstat calls")
        if case["kind"]=="fd-zero":require(fd==0,"actual file descriptor zero")
    elif case["kind"]=="seccomp-eio":
        require(observed==b"" and result["error"]["errno"]==5 and any(x["exit"]["result"]==-5 for x in stat_calls),
            "real fstat errno is observed without fabricated payload")
        filters=[x for x in calls if x["number"]==317]
        require(len(filters)==1 and filters[0]["exit"]["result"]==0 and len(filters[0]["input_spans"]["seccomp-bpf"]["raw"])==56,
            "complete actual filter installation")
    else:
        require(case["kind"]=="partial-write"and result["first_write"]==23 and result["error"]["errno"]==27
            and observed==data[:23]and result["read_hex"]==observed.hex(),"real RLIMIT partial-write behavior")
        writes=[x for x in calls if x["number"]==1 and x["args"][0]==fd]
        require([x["exit"]["result"]for x in writes]==[23,-27]
            and writes[0]["input_spans"]["write"]["raw"]==data and writes[1]["input_spans"]["write"]["raw"]==data[23:],
            "complete actual partial-write kernel input/result")
        require(any(x["signal"]==25 for x in trace["signals"]),"actual SIGXFSZ forwarded unchanged")
    return dict(status="ACTUAL_KERNEL_OBSERVER_PROBE_PASS",case=case["kind"],syscalls=len(trace["calls"]),
        trace_bytes=trace["complete_bytes"],buffers=buffers,observer_probe_calls=1,
        target_hia_application_calls=0,original_write_application_calls=0)
