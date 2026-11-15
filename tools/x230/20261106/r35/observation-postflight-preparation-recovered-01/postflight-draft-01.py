#!/usr/bin/env python3
"""Preserve a completed R35 ordinary OBS first snapshot; actual receipts must be sealed first."""
import base64, datetime, hashlib, json, os, stat
from pathlib import Path

ROOT = Path("/home/qian/hepta-runtime-optimization-20261106-r35")
STATIC_PINS = {'preparation.json': {'bytes': 62335,
                      'sha256': '4770faa3c73ec2e9287fd43154ad5f9b6df149d85767ddb5f18e6aeb153ea1cc'},
 'qualification-01/report.json': {'bytes': 83363,
                                  'sha256': '5369433b6eb2db62a907593f1b679f968b411d0cde96ce9eabe8e124420cf8e1'},
 'qualification-01/source-map.json': {'bytes': 24156,
                                      'sha256': '87f085a95a1c1925ecc444b46c996a0aec399c74ce7d0c32afff572e24055313'},
 'qualification-terminal-status-01.json': {'bytes': 731,
                                           'sha256': '8b171dde1644b1c9cacfc126be053484a3649031f946c648db7a69f9be404844'},
 'rust-ci-01/report.json': {'bytes': 14132,
                            'sha256': 'b619804c79479d2bb529e363d8fa48520b8ef9f351a99729ccba77d5510fec5f'},
 'rust-ci-native-01.json': {'bytes': 731,
                            'sha256': 'c19d3490b283df287ba2743d3385f26a83144505ef36ccc874e218359cc94746'},
 'rust-ci-native-read-01.json': {'bytes': 5126,
                                 'sha256': '31a962dfcbc55ce22b4bb81f5fa05aaacf018c13f17d2dc3f3b49e933d30977b'}}

def need(v,m):
    if not v: raise RuntimeError(m)

def ident(raw):
    return {"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}

def read(path,pin=None,cap=8*1024*1024):
    need(path.is_absolute() and path.resolve(strict=True)==path,"indirect input")
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(fd,"rb") as f:
        a=os.fstat(f.fileno())
        need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and 0<=a.st_size<=cap,"unsafe original")
        raw=f.read(a.st_size+1); b=os.fstat(f.fileno())
    c=path.lstat(); fields=("st_dev","st_ino","st_mode","st_uid","st_nlink","st_size","st_mtime_ns","st_ctime_ns")
    need(len(raw)==a.st_size and all(getattr(a,k)==getattr(b,k)==getattr(c,k) for k in fields),"original changed")
    if pin: need(ident(raw)=={k:pin[k] for k in ("bytes","sha256")},"original identity mismatch "+str(path))
    return raw

def create(path,raw):
    need(path.parent.resolve(strict=True)==path.parent,"indirect output")
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    with os.fdopen(fd,"wb") as f:
        f.write(raw); f.flush(); os.fsync(f.fileno())
    read(path,ident(raw))
    return {"path":str(path),**ident(raw)}

def native(term,receipt,job,state,code):
    need(term["job_id"]==receipt["job_id"]==job and term["state"]==state and term["exit_code"]==code,"original native outcome differs")
    need(all(term[k] is False for k in ("automatic_retry","cancelled","timed_out")) and all(term[k] is True for k in ("output_complete","output_durable","terminal_publication_confirmed")),"native incomplete")
    need(term["terminal_publication_protocol"]==1 and term["log_synced"]=={"stdout":True,"stderr":True} and term["log_errors"]=={"stdout":None,"stderr":None} and term["log_truncated"]=={"stdout":False,"stderr":False},"native storage differs")
    for k in ("stdout","stderr"):
        v=receipt[k]; raw=bytes.fromhex(v["bytes_hex"])
        need(v["offset"]==0 and v["eof"] is True and len(raw)==v["size"]==v["next_offset"]==term["log_bytes"][k]["stored"]==term["log_bytes"][k]["seen"] and raw==v["text"].encode(),"native stream incomplete")

FUTURE_PINS = (
    "campaign-01/report.json", "campaign-01/summary.json",
    "campaign-01/native-observation/independent-summary.json",
    "campaign-01/compiler-monitor.audit.json", "campaign-01/native-observation/report.json",
)
PAYLOAD_NAMES = ("observation-holder-native-01.json", "observation-holder-read-01.json",
                 "observation-holder-report-01.json")
LC_PATHS = ("lifecycle-inputs-01.json", "lifecycle-campaign-01", "lifecycle-abba-01",
            "lifecycle-materialization-native-01.json", "lifecycle-materialization-read-01.json")
PARENT_SHA = "3707cbc2e3307a29aa6e645afdf8f6da7a5e80d36e90a86d505bd8f18061778c"
HOLDER_SHA = "715e996217c7d33a7483354f16f2d39c9a033f51f3a20a52484495a00262dd65"
CI_JOB = "1a1af88c330-fc05-696f"
ACTUAL = None
PAYLOAD = None


def require_sealed():
    need(type(ACTUAL) is dict and ACTUAL.get("schema") == "hepta-r35-observation-postflight-actual/v1"
         and ACTUAL.get("sealed") is True and type(PAYLOAD) is list,
         "UNSEALED: original completed OBS receipts and coordinator LC state are required")
    pins = ACTUAL.get("pins")
    need(type(pins) is dict and set(pins) == set(FUTURE_PINS), "actual full OBS original pins required")
    for name, pin in pins.items():
        need(type(pin) is dict and set(pin) == {"bytes", "sha256"}
             and type(pin["bytes"]) is int and 0 < pin["bytes"] <= 8*1024*1024
             and type(pin["sha256"]) is str and len(pin["sha256"]) == 64
             and set(pin["sha256"]) <= set("0123456789abcdef"), "invalid actual original identity: " + name)
    need(type(ACTUAL.get("holder_job_id")) is str and ACTUAL["holder_job_id"], "actual holder job required")
    need(ACTUAL.get("holder_native_state") == "succeeded" and ACTUAL.get("holder_native_exit_code") == 0,
         "this first snapshot requires a fully completed ordinary observation workflow")
    need(ACTUAL.get("reported_workflow_passed") is True
         and type(ACTUAL.get("observation_gate_passed")) is bool
         and type(ACTUAL.get("performance_gates_passed")) is bool
         and type(ACTUAL.get("rejection_reasons")) is list
         and all(type(reason) is str for reason in ACTUAL["rejection_reasons"]),
         "actual complete workflow and raw gate outcomes required")
    count = ACTUAL.get("compiler_monitor_sample_count")
    need(type(count) is int and count > 0, "actual completed monitor sample count required")
    need(ACTUAL.get("lifecycle_materialization_started") is False
         and ACTUAL.get("normal_lifecycle_started") is False
         and ACTUAL.get("original_lifecycle_materializer_job_id") is None
         and ACTUAL.get("original_normal_lifecycle_job_id") is None,
         "this first snapshot is before LC launch; later LC requires its own original evidence")
    source = ACTUAL.get("lifecycle_nonlaunch_source")
    need(type(source) is str and bool(source.strip()), "coordinator nonlaunch declaration source required")
    need(len(PAYLOAD) == len(PAYLOAD_NAMES)
         and all(type(row) is dict for row in PAYLOAD)
         and {row.get("name") for row in PAYLOAD} == set(PAYLOAD_NAMES), "fixed three holder originals required")
    return {**STATIC_PINS, **pins}


def main():
    pins = require_sealed()
    os.umask(0o077)
    need(ROOT.resolve(strict=True)==ROOT and ROOT.stat().st_uid==os.geteuid() and os.geteuid()!=0,
         "fixed operator root")
    out=ROOT/"observation-postflight-01.json"
    need(not os.path.lexists(out) and all(not os.path.lexists(ROOT/name) for name in PAYLOAD_NAMES),
         "fresh native preservation required")
    decoded={}
    for row in PAYLOAD:
        need(set(row) == {"name", "bytes", "sha256", "data_base64"}
             and type(row["bytes"]) is int and 0 < row["bytes"] <= 8*1024*1024
             and type(row["data_base64"]) is str
             and len(row["data_base64"]) <= 4*((8*1024*1024+2)//3), "bounded original payload required")
        need(Path(row["name"]).name==row["name"],"unsafe payload")
        body=base64.b64decode(row["data_base64"],validate=True)
        need(ident(body)=={k:row[k] for k in ("bytes","sha256")},"payload differs")
        decoded[row["name"]]=body
    parsed={k:json.loads(v) for k,v in decoded.items()}
    native(parsed["observation-holder-native-01.json"], parsed["observation-holder-read-01.json"],
           ACTUAL["holder_job_id"], ACTUAL["holder_native_state"], ACTUAL["holder_native_exit_code"])
    holder=[json.loads(line) for line in parsed["observation-holder-read-01.json"]["stdout"]["text"].splitlines()]
    need(holder and holder[-1]["passed"] is True and holder[-1]["remote_returncode"]==0
         and holder[-1]["owned_agent_reaped"] is True,"holder ownership not closed")
    owned=parsed["observation-holder-report-01.json"]
    need(owned["schema"]=="hepta-x230-r21-held-agent-campaign/v1" and owned["passed"] is True
         and owned["remote_returncode"]==0 and owned["automatic_ssh_retries"]==0
         and owned["services_modified"] is False,"original holder result differs")
    need(owned["holder_script_sha256"]==HOLDER_SHA and owned["remote_script_sha256"]==PARENT_SHA,
         "original holder/program identity differs")
    need(owned["owned_agent_reaped"] is True and owned["owned_agent_directory_absent_after_context"] is True
         and owned["owned_agent_socket_absent_after_context"] is True,"original agent custody differs")
    documents={name:read(ROOT/name,pin) for name,pin in pins.items()}
    values={name:json.loads(raw) for name,raw in documents.items()}
    parent=values["campaign-01/report.json"]
    summary=values["campaign-01/summary.json"]
    need(parent["passed"] is ACTUAL["reported_workflow_passed"] is True and parent["finished_utc"]
         and parent["compiler_monitor"]["passed"] is True and parent["inputs_unchanged"] is True
         and parent["source_inputs_unchanged"] is True and parent["baseline_source_inputs_unchanged"] is True
         and parent["measurement_attribution_valid"] is True,"original parent did not close")
    need(parent["observation_gate_passed"] is summary["observation_gate_passed"] is ACTUAL["observation_gate_passed"]
         and summary["performance_gates_passed"] is ACTUAL["performance_gates_passed"]
         and parent["rejection_reasons"]==summary["rejection_reasons"]==ACTUAL["rejection_reasons"],
         "original raw observation gate/reasons differ from actual bound receipts")
    need(summary["correctness_verified"] is True and summary["evidence_verified"] is True
         and summary["controller_rss"]["passed"] is True,"original correctness/resource closure differs")
    need([r["name"] for r in parent["stages"]]==["native-observation","native-audit","native-boundary",
         "boundary-audit","cancel-recovery","recovery-audit","observation-summary"]
         and all(r["returncode"]==0 and r["passed"] is True and r["waited_and_reaped"] is True
         and r["owned_process_absent"] is True and r["owned_process_group_absent"] is True
         for r in parent["stages"]),"original owned stages not closed")
    audit=values["campaign-01/native-observation/independent-summary.json"]
    need(audit["verified"] is True and audit["original_sha256"]==pins["campaign-01/native-observation/report.json"]["sha256"]
         and audit["measured_calls"]==2304 and audit["warmup_calls"]==288 and audit["preflight_restart_calls"]==72
         and audit["total_calls"]==2664 and audit["failed_calls"]==0,"original full call counts differ")
    native_counts={key:audit[key] for key in ("verified", "measured_calls", "warmup_calls",
                                            "preflight_restart_calls", "total_calls", "failed_calls")}
    monitor=values["campaign-01/compiler-monitor.audit.json"]
    need(monitor["monitor_sources_unchanged"] is True and monitor["source_recheck_errors"]==[]
         and monitor["validation"]["passed"] is True and monitor["validation"]["errors"]==[],
         "original monitor validation differs")
    ledger_pin=parent["compiler_monitor"]["ledger"]
    ledger_name="campaign-01/compiler-monitor.json"
    need(ledger_pin==monitor["ledger"] and ledger_pin["path"]==str(ROOT/ledger_name),
         "original monitor ledger identities differ")
    documents[ledger_name]=read(ROOT/ledger_name,ledger_pin)
    ledger=json.loads(documents[ledger_name])
    count=ledger["sample_count"]
    need(type(count) is int and type(ledger["samples"]) is list
         and count==len(ledger["samples"])==monitor["validation"]["validated_sample_count"]
         ==ACTUAL["compiler_monitor_sample_count"],"original monitor sample count differs")
    native(values["rust-ci-native-01.json"],values["rust-ci-native-read-01.json"],CI_JOB,"succeeded",0)
    ci=values["rust-ci-01/report.json"]
    need(ci["schema"]=="hepta-r35-external-rust-ci/v1" and ci["passed"] is True
         and ci["source_inputs_unchanged"] is True and ci["owned_children_closed"] is True
         and ci["automatic_retries"]==0,"original CI closure differs")
    qualified=values["qualification-01/report.json"]
    source_map=values["qualification-01/source-map.json"]
    need(qualified["qualified"] is True and qualified["source_after"]==qualified["source_tested"]==source_map
         and len(source_map)==220,"qualified source map differs")
    current_names={"Cargo.toml","Cargo.lock","rustfmt.toml"}|{
        p.relative_to(ROOT/"source").as_posix() for sub in ("src","examples")
        for p in (ROOT/"source"/sub).rglob("*") if p.is_file()}
    need(current_names==set(source_map),"current compiler input membership differs")
    for name,digest in source_map.items():
        p=Path(name); need(not p.is_absolute() and ".." not in p.parts,"unsafe compiler path")
        need(hashlib.sha256(read(ROOT/"source"/p)).hexdigest()==digest,"current source differs "+name)
    path_presence={name:os.path.lexists(ROOT/name) for name in LC_PATHS}
    need(not any(path_presence.values()),"LC namespace exists; this pre-LC snapshot cannot claim nonlaunch")
    need((ROOT/"target-build").is_dir() and (ROOT/"target-build").resolve(strict=True)==ROOT/"target-build",
         "original cache location differs")
    originals={name:{"path":str(ROOT/name),**ident(raw)} for name,raw in documents.items()}
    for name,raw in decoded.items(): originals[name]=create(ROOT/name,raw)
    gate=summary["observation_gate_passed"]
    report={
        "schema":"hepta-r35-observation-postflight/v1",
        "captured_at_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "snapshot_scope":"first completed ordinary OBS snapshot before lifecycle launch",
        "original_observation_job_id":ACTUAL["holder_job_id"],
        "observation_workflow_closed":True, "original_owned_agent_reaped":True,
        "observation_gate_passed":gate, "performance_gates_passed":summary["performance_gates_passed"],
        "rejection_reasons":summary["rejection_reasons"], "native_audit_counts":native_counts,
        "compiler_monitor_sample_count":count,
        "lifecycle_materialization_started":False, "normal_lifecycle_started":False,
        "original_lifecycle_materializer_job_id":None, "original_normal_lifecycle_job_id":None,
        "normal_lifecycle_state":"not_started_at_capture",
        "normal_lifecycle_disposition":"awaiting_normal_lifecycle" if gate else "not_started_after_gate_rejection",
        "normal_lifecycle_path_presence":path_presence, "normal_lifecycle_paths_absent":list(LC_PATHS[:3]),
        "normal_lifecycle_final_outcome":None,
        "lifecycle_nonlaunch_source":ACTUAL["lifecycle_nonlaunch_source"],
        "lifecycle_nonlaunch_scope":"coordinator declaration plus five paths absent at capture; not inferred from OBS gate",
        "candidate_adopted":False, "candidate_adoption_evaluated":False,
        "accepted_baseline_commit":"baab4def80be7af015b2e7a594cb302f66c4130e",
        "current_source_matches_qualified_map":True, "compiler_input_count":220,
        "cache_path":str(ROOT/"target-build"), "cache_moved":False, "cache_deleted":False,
        "current_machine_idle_claimed":False, "originals":originals,
        "tests_benchmarks_or_auditors_reexecuted":False,
    }
    body=(json.dumps(report,sort_keys=True,indent=2)+"\n").encode()
    identity=create(out,body)
    print(json.dumps({"receipt":identity,**report}),flush=True)


if __name__ == "__main__":
    main()
