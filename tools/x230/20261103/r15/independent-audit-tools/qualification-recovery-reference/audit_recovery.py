#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Independently audit retained six-host cancellation and recovery evidence."""
import argparse,base64,collections,datetime,hashlib,json,math,re
from pathlib import Path
parser=argparse.ArgumentParser()
parser.add_argument("--root",default="/home/qian/hepta-runtime-optimization-20261103-r13")
parser.add_argument("--recovery",default="/home/qian/hepta-runtime-optimization-20261103-r12/r13-candidate-cancel-recovery-01")
parser.add_argument("--remote-gate",default="remote-campaigns-02/report.json")
parser.add_argument("--output",default="independent-recovery-audit.json")
args=parser.parse_args()
ROOT=Path(args.root)
BASE=Path(args.recovery)
INPUTS={}
def need(value,message):
    if not value: raise RuntimeError(message)
def sha_bytes(value): return hashlib.sha256(value).hexdigest()
def sha_file(path):
    with Path(path).open("rb") as stream: return hashlib.file_digest(stream,"sha256").hexdigest()
def finite(value,path="root"):
    if isinstance(value,float): need(math.isfinite(value),"nonfinite value: "+path)
    elif isinstance(value,dict):
        for k,v in value.items(): finite(v,path+"."+k)
    elif isinstance(value,list):
        for i,v in enumerate(value): finite(v,path+"["+str(i)+"]")
def load(path):
    path=Path(path); raw=path.read_bytes()
    INPUTS[str(path)]=sha_bytes(raw)
    value=json.loads(raw); finite(value,str(path)); return value
def canonical(value): return json.dumps(value,sort_keys=True,separators=(",",":"),allow_nan=False)
def bound(path,expected,length=None):
    path=Path(path)
    need(path.resolve().is_relative_to(BASE.resolve()),"reply outside recovery directory")
    raw=path.read_bytes()
    actual=sha_bytes(raw)
    need(actual==expected,"raw artifact hash differs: "+str(path))
    if length is not None: need(len(raw)==length,"raw artifact size differs: "+str(path))
    INPUTS[str(path)]=actual
    return raw
def positive(value,label):
    need(isinstance(value,(int,float)) and not isinstance(value,bool) and math.isfinite(value) and value>0,"invalid "+label)
def decode_reply(raw):
    reply=json.loads(raw)
    need(reply.get("jsonrpc")=="2.0" and "error" not in reply,"native JSON-RPC failed")
    result=reply["result"]
    need(result.get("isError") is False,"native tool returned error")
    texts=[x["text"] for x in result.get("content",[]) if x.get("type")=="text"]
    need(len(texts)==1,"unexpected native JSON text count")
    value=json.loads(texts[0]); finite(value,"reply"); return value
report=load(BASE/"report.json")
gate=load(ROOT/args.remote_gate)
qualification=load(ROOT/"qualification-audit-summary.json")
need(report["passed"] is True and report["phase"]=="completed","recovery incomplete")
need(gate["success"] is True and gate["recovery_report_sha256"]==INPUTS[str(BASE/"report.json")],"remote gate recovery binding differs")
candidate=qualification["release_binaries"]["hepta-runtime"]["sha256"]
need(qualification["success"] is True and gate["candidate_sha256"]==candidate,"qualification binding differs")
need(report["binary_unchanged"] is True,"recovery binary changed")
candidate_refs=[v for k,v in report.items() if "sha256" in k and isinstance(v,str)]
need(candidate in candidate_refs,"recovery candidate hash missing")
for key in ("automatic_rpc_retries","production_service_mutations","remote_cleanup_operations"):
    need(report[key]==0,key+" nonzero")
need(report["new_start_call_count"]==6 and report["same_key_lookup_call_count"]==12 and report["cancel_call_count"]==12,"recovery operation counts differ")
need(report["source_originals_unchanged"] is True and report["current_agent_unchanged"] is True,"originals or agent changed")
HOSTS={"ai395","mac","main","pocket4","rog","x230"}
need(set(report["hosts"])==HOSTS,"recovery host set differs")
native=report["native_calls"]; ssh=report["ssh_calls"]
need(len(ssh)==36,"SSH proof count differs")
native_by=collections.defaultdict(list)
native_bindings=[]
for row in native:
    need(row["host"] in HOSTS and row["okay"] is True and row["automatic_retry"] is False,"native row refused/retried")
    positive(row["elapsed_ms"],"native duration"); positive(row["started_unix"],"native timestamp")
    need(re.fullmatch("[0-9a-f]{64}",row["arguments_sha256"]) is not None,"invalid argument hash")
    raw=bound(row["reply_path"],row["response_sha256"])
    dto=decode_reply(raw)
    native_by[(row["phase"],row["tool"],row["host"])].append((row,dto))
    native_bindings.append({"sequence":row["sequence"],"phase":row["phase"],"host":row["host"],"tool":row["tool"],"path":str(Path(row["reply_path"]).relative_to(BASE)),"sha256":sha_bytes(raw)})
expected={}
for phase,tools in {
 "launch":["process_start"],
 "before_crash_running":["process_status","process_read"],
 "after_transport_running":["process_status","process_read"],
 "after_crash_running":["process_status","process_read"],
 "same_key_after_crash":["process_start"],
 "concurrent_cancel":["process_cancel"],
 "terminal":["process_status","process_read"],
 "terminal_after_restart":["process_status","process_read"],
 "same_key_after_cancel":["process_start"],
 "cancel_after_terminal":["process_cancel"]}.items():
    for tool in tools:
        for host in HOSTS: expected[(phase,tool,host)]=1
need(set(native_by)==set(expected),"native phase/tool/host matrix differs")
extra_polls=0
for key,entries in native_by.items():
    if key[0] in {"terminal","terminal_after_restart"} and key[1]=="process_status":
        need(len(entries)>=1,"missing terminal status")
        extra_polls+=len(entries)-1
    else: need(len(entries)==1,"unexpected duplicate native operation")
need(len(native)==90+extra_polls,"native total differs from matrix")
ssh_objects=collections.defaultdict(list)
ssh_bindings=[]
for row in ssh:
    need(row["host"] in HOSTS and row["okay"] is True and row["returncode"]==0 and row["automatic_retry"] is False,"SSH proof failed/retried")
    positive(row["elapsed_ms"],"SSH duration")
    need(row["mode"] in {"prepare","inspect"},"unexpected SSH mode")
    need(row["mutation_attempted"] is (row["mode"]=="prepare"),"unexpected SSH mutation flag")
    streams={}
    for name in ("stdout","stderr"):
        item=row[name]
        streams[name]=bound(item["path"],item["sha256"],item["bytes"])
    need(streams["stderr"]==b"","unexpected SSH stderr")
    proof=json.loads(streams["stdout"]); finite(proof,"SSH proof")
    need(proof["host"]==row["host"] and proof["mode"]==row["mode"],"SSH proof identity differs")
    ssh_objects[row["host"]].append((row,proof))
    ssh_bindings.append({"sequence":row["sequence"],"host":row["host"],"mode":row["mode"],"terminal":row["terminal"],"stdout_sha256":row["stdout"]["sha256"],"stderr_sha256":row["stderr"]["sha256"]})
sequences=[x["sequence"] for x in native+ssh]
need(len(set(sequences))==len(sequences),"duplicate transport sequence")
need(set(sequences)==set(range(1,len(sequences)+1)),"transport sequence gap")
decoded_artifacts=0
decoded_bytes=0
def decode_proof(proof):
    global decoded_artifacts,decoded_bytes
    files={}
    for name,item in proof["files"].items():
        if item is None:
            files[name]=None; continue
        raw=base64.b64decode(item["base64"],validate=True)
        need(len(raw)==item["bytes"] and sha_bytes(raw)==item["sha256"],"embedded SSH file length/hash differs: "+name)
        files[name]=raw; decoded_artifacts+=1; decoded_bytes+=len(raw)
    return files
INPUT=b"0123456789abcdef"*256
MARKER=b"EXECUTED\n"
host_results={}
running_phases=("before_crash_running","after_transport_running","after_crash_running")
terminal_phases=("terminal","terminal_after_restart")
for host in sorted(HOSTS):
    h=report["hosts"][host]
    job=h["job_id"]
    expected_out={"stdout":("BEGIN "+host+"\n").encode(),"stderr":("HEPTA-CANARY-STDERR "+host+"\n").encode()}
    proofs=[h["prepare"]]+[h[phase]["proof"] for phase in running_phases+terminal_phases]
    recorded=[proof for _,proof in ssh_objects[host]]
    need(collections.Counter(map(canonical,proofs))==collections.Counter(map(canonical,recorded)),"per-host SSH proof/report mismatch")
    need(len(recorded)==6,"per-host SSH probe count differs")
    need(sum(row["mode"]=="prepare" for row,_ in ssh_objects[host])==1 and sum(row["terminal"] for row,_ in ssh_objects[host])==2,"per-host SSH phase counts differ")
    launch_pair=native_by[("launch","process_start",host)][0]
    need(launch_pair[1]==h["launch"],"launch DTO/report mismatch")
    need(h["launch"]["job"]["id"]==job and h["launch"]["job"]["host"]==host and h["launch"]["reused"] is False,"new launch identity differs")
    original_job=h["launch"]["job"]
    for phase in ("same_key_after_crash","same_key_after_cancel"):
        dto=native_by[(phase,"process_start",host)][0][1]
        need(dto==h[phase] and dto["reused"] is True and dto.get("retried_launch",False) is False,"same-key lookup replayed launch")
        for key in ("id","host","idempotency_key","request_digest","remote_job_dir"):
            need(dto["job"].get(key)==original_job.get(key),"same-key immutable identity differs: "+key)
    for phase,result,confirmed in (("concurrent_cancel","stop_requested",False),("cancel_after_terminal","already_exited",False)):
        dto=native_by[(phase,"process_cancel",host)][0][1]
        expected_result="term_sent" if phase=="concurrent_cancel" and host=="mac" else result
        need(dto==h[phase] and dto["job_id"]==job and dto["result"]==expected_result and dto["termination_confirmed"] is confirmed,"cancel receipt differs: "+host+"/"+phase)
        need(dto["automatic_retry"] is False and dto["audit_recorded"] is True,"cancel audit/retry differs")
        if phase=="concurrent_cancel":
            need(dto["atomic_identity"] is (host!="mac"),"platform signal identity differs")
            positive(dto["supervisor_pid"],"supervisor pid")
    launch_nonces=set()
    request_shas=set()
    terminal_summary=[]
    for phase in running_phases+terminal_phases:
        terminal=phase in terminal_phases
        item=h[phase]
        entries=sorted(native_by[(phase,"process_status",host)],key=lambda v:v[0]["sequence"])
        status=entries[-1][1]
        need(status==item["status"] and status["job_id"]==job,"status DTO/report mismatch")
        for _,intermediate in entries[:-1]:
            need(intermediate["job_id"]==job and intermediate["state"] in {"running","activating","finalizing"},"invalid terminal polling state")
        launch_nonce=status["launch_nonce"] if terminal else item["launch_nonce"]
        launch_nonces.add(launch_nonce)
        need(status.get("automatic_retry",False) is False,"status retried")
        proof=item["proof"]
        need(proof["host"]==host and proof["mode"]=="inspect" and proof["fixture_identity"]==h["prepare"]["fixture_identity"],"proof fixture identity differs")
        files=decode_proof(proof)
        need(files["execution-marker"]==MARKER and files["stdin.bin"]==INPUT and files["release-marker"] is None,"one-execution/input/unreleased gate proof differs")
        request=json.loads(files["request.json"])
        need(request["job_id"]==job and request["launch_nonce"]==launch_nonce,"request binding differs")
        need(request["job_dir"]==original_job["remote_job_dir"],"request directory binding differs")
        request_shas.add(sha_bytes(files["request.json"]))
        read=native_by[(phase,"process_read",host)][0][1]
        need(read["job_id"]==job,"read identity differs")
        for stream,data in expected_out.items():
            part=read[stream]
            need(bytes.fromhex(part["bytes_hex"])==data and part["offset"]==0 and part["next_offset"]==part["size"]==len(data),"native exact output bytes/cursors differ")
            if terminal:
                need(files[stream+".log"]==data,"SSH output bytes differ")
                need(part["eof"] is True,"terminal output not EOF")
        if terminal:
            need(item["execution_count"]==1,"terminal execution count differs")
            need(status["state"]=="cancelled" and status["cancelled"] is True and status["timed_out"] is False,"terminal cancellation state differs")
            for key in ("output_complete","output_durable","terminal_publication_confirmed"):
                need(status[key] is True,"terminal durability flag false: "+key)
            need(status["terminal_publication_protocol"]==1,"terminal protocol differs")
            need(status["log_synced"]=={"stdout":True,"stderr":True} and status["log_truncated"]=={"stdout":False,"stderr":False} and status["log_errors"]=={"stdout":None,"stderr":None},"terminal log durability differs")
            need(status["log_bytes"]=={stream:{"seen":len(data),"stored":len(data)} for stream,data in expected_out.items()},"terminal byte counters differ")
            need(item["outputs"]=={stream:{"bytes":len(data),"sha256":sha_bytes(data)} for stream,data in expected_out.items()},"terminal output summary differs")
            exit_record=json.loads(files["exit.json"])
            witness=json.loads(files["exit.witness.json"])
            intent=json.loads(files["cancel-request.json"])
            for record in (exit_record,witness,intent):
                need(record["job_id"]==job and record["launch_nonce"]==status["launch_nonce"],"terminal file identity differs")
            for key in ("cancelled","timed_out","exit_code","log_bytes","log_errors","log_synced","log_truncated","output_complete","output_durable","terminal_publication_protocol"):
                need(exit_record[key]==status[key],"exit/status field differs: "+key)
            need(witness["exit_sha256"]==sha_bytes(files["exit.json"]) and witness["terminal_publication_protocol"]==1,"terminal witness commit differs")
            terminal_summary.append({"phase":phase,"exit_sha256":sha_bytes(files["exit.json"]),"witness_sha256":sha_bytes(files["exit.witness.json"]),"cancel_intent_sha256":sha_bytes(files["cancel-request.json"]),"stdout_sha256":sha_bytes(expected_out["stdout"]),"stderr_sha256":sha_bytes(expected_out["stderr"])})
        else:
            need(status["state"] in {"running","activating"} and not status.get("cancelled",False),"job did not survive recovery running")
            need(files["exit.json"] is None and files["exit.witness.json"] is None and files["cancel-request.json"] is None,"running phase has terminal/cancel record")
            need(item["launch_nonce"]==request["launch_nonce"],"running nonce summary differs")
    need(len(launch_nonces)==1 and len(request_shas)==1,"launch identity/request changed across recovery")
    for key in ("exit_sha256","witness_sha256","cancel_intent_sha256","stdout_sha256","stderr_sha256"):
        need(terminal_summary[0][key]==terminal_summary[1][key],"terminal bytes changed after restart: "+key)
    host_results[host]={"job_id":job,"launch_nonce":next(iter(launch_nonces)),"request_sha256":next(iter(request_shas)),"execution_marker_count":1,"same_key_reused_after_crash":True,"same_key_reused_after_cancel":True,"terminal_records":terminal_summary,"cancel_acknowledgement":h["concurrent_cancel"]["result"],"cancel_after_terminal_acknowledgement":h["cancel_after_terminal"],"signal_identity":"pidfd" if host!="mac" else "account-and-PID-start best effort"}
records=report["controller_records"]
need(records["errors"]==[] and records["exact_original_set"] is True and len(records["records"])==6,"controller original records differ")
for item in records["records"]:
    need(item["original_bytes_unchanged"] is True and sha_file(item["path"])==item["sha256"],"controller original record hash differs")
    original=report["hosts"][item["host"]]["launch"]["job"]
    need(item["job_id"]==original["id"] and item["idempotency_key"]==original["idempotency_key"] and item["remote_job_dir"]==original["remote_job_dir"],"controller record identity differs")
startup=[report[key] for key in ("first_startup","after_crash_startup","after_cancel_startup")]
identities=[(x["pid"],x["birth_ticks"]) for x in startup]
need(len(set(identities))==3,"controller generations not distinct")
need(report["intentional_crash"]["exit_code"]==-9,"controller crash was not observed SIGKILL")
for key in ("after_cancel_shutdown","shutdown"):
    need(report[key]["exit_code"]==0 and report[key]["reader_error"] is None and report[key]["observed_descendant_survivors"]==[],"normal controller shutdown not clean")
transport=report["transport_interruption"]
need(transport["attempted"] is True and transport["passed"] is True and transport["requested_host"]=="rog","transport interruption differs")
receipt=transport["signal_receipt"]
need(receipt["signal"]=="SIGKILL" and receipt["signal_sent"] is True and receipt["pidfd_terminal_observed"] is True,"owned master kill not witnessed")
need(receipt["network_or_service_changes"] is False and receipt["socket_removed_by_harness"] is False,"transport interruption changed network/service/socket")
old_master=transport["original_master"]; new_master=transport["replacement_master"]
need((old_master["pid"],old_master["birth_ticks"])!=(new_master["pid"],new_master["birth_ticks"]),"SSH master generation not replaced")
cancel_rows=[x for x in native if x["phase"]=="concurrent_cancel"]
events=[]
for row in cancel_rows:
    events.append((row["started_unix"],1))
    events.append((row["started_unix"]+row["elapsed_ms"]/1000,-1))
active=peak=0
for _,delta in sorted(events): active+=delta; peak=max(peak,active)
need(peak==6,"six successful cancellation requests did not overlap")
result={"schema":"hepta-six-host-independent-recovery-audit/v1","success":True,"audited_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"auditor_sha256":sha_file(__file__),"candidate_sha256":candidate,"qualification_audit_sha256":INPUTS[str(ROOT/"qualification-audit-summary.json")],"raw_report_sha256":INPUTS[str(BASE/"report.json")],"counts":{"hosts":6,"native_replies":len(native),"ssh_probes":len(ssh),"ssh_stdout_and_stderr_files":len(ssh)*2,"embedded_artifacts_rehashed":decoded_artifacts,"embedded_artifact_bytes_rehashed":decoded_bytes,"new_starts":6,"same_key_lookups":12,"cancel_calls":12,"extra_read_only_terminal_polls":extra_polls,"automatic_rpc_retries":0},"phase_tool_counts":dict(sorted(collections.Counter(row["phase"]+"/"+row["tool"] for row in native).items())),"successful_cancel_concurrency":{"observed_peak_overlap":peak,"start_spread_ms":(max(x["started_unix"] for x in cancel_rows)-min(x["started_unix"] for x in cancel_rows))*1000,"latencies_ms":{x["host"]:x["elapsed_ms"] for x in cancel_rows},"supports":"live six-host successful-cancel overlap; not a successful-cancel C8 throughput measurement"},"faults":{"controller_sigkill_confirmed":True,"three_controller_generations":[{"pid":p,"birth_ticks":b} for p,b in identities],"owned_rog_ssh_master_sigkill_confirmed":True,"master_generation_replaced":True,"network_and_services_unchanged":True},"hosts":host_results,"native_reply_file_bindings":native_bindings,"ssh_stream_bindings":ssh_bindings,"original_controller_record_hashes_recomputed":6,"limitations":["Fixture execution markers prove one execution for these six same-key recovery scenarios, not universal distributed exactly-once execution.","No host reboot, power loss, WAN partition, ownership transfer, or external-effect deduplication experiment is claimed.","Mac signal identity is account/PID-start best effort; Linux evidence uses pidfd.","Native response files and embedded remote files are independently hashed; argument hashes are checked for shape but full request bodies were not retained in this report."]}
for path,expected in INPUTS.items(): need(sha_file(path)==expected,"input changed during recovery audit")
result["input_sha256"]=INPUTS
out=ROOT/args.output
with out.open("x") as stream: json.dump(result,stream,indent=2,allow_nan=False); stream.write("\n")
print(json.dumps({"success":True,"path":str(out),"sha256":sha_file(out),"auditor_sha256":sha_file(__file__),"candidate_sha256":candidate,"counts":result["counts"],"successful_cancel_concurrency":result["successful_cancel_concurrency"]}),flush=True)
