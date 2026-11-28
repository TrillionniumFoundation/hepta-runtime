"""Whole actual owned tracer controls; no process execution."""
from reader_common import read,loads,pin,require,integer
from read_pairs import exact,elapsed
def verify(root,row,stdout,source_sha):
    summary=loads(read(root/"CONTROLS.json"));exact(summary,loads(stdout),"whole actual trace-control stdout")
    require(summary["status"]=="OWNED_TRACER_CUSTODY_CONTROLS_PASS"and summary["source_manifest_sha256"]==source_sha
        and summary["pid"]==summary["pgid"]==row["pid"]and summary["parent_pid"]==row["parent_pid"]
        and summary["timeout_seconds"]==60 and summary["native_executions"]==summary["rust_executions"]==0,
        "complete actual fixed tracer controls and owned parent")
    elapsed(summary["elapsed_seconds"],row["elapsed_seconds"])
    names=("normal","before-ready-exit","rejected-ready","one-live-tracee","two-live-tracees","missing-executable")
    require([r["name"]for r in summary["controls"]]==list(names),"all original real tracer cleanup controls")
    for i,control in enumerate(summary["controls"]):
        folder=root/control["name"];exact(loads(read(folder/"CONTROL.json")),control,"whole physical original control receipt")
        require(control["cleanup_errors"]==[]and control["restored"]is True and type(control["prior_subreaper"])is int
            and control["prior_subreaper"]in(0,1)and control["rejected"]is(i!=0)
            and(bool(control["exception"])==(i!=0)),"actual exception, subreaper restoration and all cleanup")
        count=2 if control["name"]=="two-live-tracees"else 1
        require(len(control["processes"])==count,"every actually started tracer retained")
        for j,p in enumerate(control["processes"]):
            child=folder/("child-%d"%j);exact(loads(read(child/"PROCESS.json")),p,"whole actual probe process receipt")
            require(p["owner_pid"]==row["pid"]and p["pgid"]==row["pgid"]and integer(p["tracer_pid"],1)
                and type(p["exit_code"])is int and p["timeout_seconds"]==60,"actual owned probe/tracer process")
            for key,ident in p["streams"].items():require(pin(read(child/key))==ident,"every complete probe stream")
            ex=loads(read(child/"EXCHANGES.json"));require(len(ex)==p["exchanges"],"all complete probe exchanges")
            for at,e in enumerate(ex):
                require(e["index"]==at and pin(bytes.fromhex(e["request_hex"]))==e["request"]
                    and pin(bytes.fromhex(e["response_hex"]))==e["response"],"complete actual probe request/reply bytes")
            if i==0:require(p["exit_code"]==0 and p["success"]is True and not control["adopted_reaps"],"normal tracer/tracee closure")
            elif i==1:require(p["exit_code"]!=0 and b"exit_group(23)"in read(child/"syscalls.strace"),"actual pre-ready exit")
            elif i in(2,3,4):require(p["exit_code"]==-9,"actual killed tracer status")
            else:require(p["exit_code"]!=0,"actual absent executable refusal")
        if i in(2,3,4):
            actual={p["ready"]["pid"]for p in control["processes"]if p["ready"]is not None}
            require(actual=={r["pid"]for r in control["adopted_reaps"]}and
                all(type(r["exit_code"])is int and r["exit_code"]==-9 for r in control["adopted_reaps"]),
                "every actual adopted live tracee reaped after killed tracer")
    return dict(controls=6,complete_receipt=pin(read(root/"CONTROLS.json")),application_executions=0)
