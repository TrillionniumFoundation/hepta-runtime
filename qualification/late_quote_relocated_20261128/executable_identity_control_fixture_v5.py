#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Separate whole-executable identity negative control; never a new qualified binary.

Append a non-loaded marker to an owned copy of the qualified ELF. Keep all
original bytes, ELF headers, entry point and PT_LOAD segments unchanged. Kill
an original-executable same-SHA graph-only attempt after candidate publication.
Within its ORIGINAL live same-boot 60-second window, recover with the changed
whole-executable SHA. Only the original function inverse may occur; no new
phase charge or model forward is allowed. The all-path budget is <=7 forwards;
a successfully captured pre-inverse window consumes at most5. A missed window
is FAIL without retry, and its possible two original Restored forwards count.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import socket
import stat
import struct
import sys
import time
import late_quote_mcp_relocated as m

t=m.t
require,read,parse,digest=m.require,m.read,m.parse,m.digest
MAIN_SHA="9763f0c078a46c7367703bb7d072003fe2136cf6e5f59656f7733e6f90ac40e9"
CONTINUATION_SHA="a2212ee79bff7f4ea611ac9984f700dd3afc1868b51d73eff6690272b9fdb9bc"
COMPOSITE_SCHEMA="hepta.late-quote.http-continuation-qualification.v1.result"
PRIOR_RESULT_SHA="4cbf5fc0c624f944c53caf2cf12ffd0398d20f6df4e046f210d1b81404ca7713"
PRIOR_PLAN_SHA="3e145469d1da17d9f92a2d95183d8a1119a12719de2eb1d5a22ee9d38fb65fc8"
PRIOR_RESPONSE_SHA="b6549b634395e5c5bdf085d8b4cb7f9b464920665268081ff36d4914a87c0bc0"
COMPOSITE_COUNTS={"server_starts":4,"rpc_wire_calls":35,"tool_calls":27,
 "roundtrip_wire_calls":10,"roundtrip_new_intents":4,"recover_wire_calls":6,"crash_attempts":1}
SCHEMA="hepta.late-quote.whole-executable-negative-control.relocated.v1"
MARKER=b"\nHEPTA_OWNED_EXE_IDENTITY_NEGATIVE_CONTROL_V1\n"
BUDGET={
 "server_starts":2,"rpc_wire_calls":12,"tool_calls":5,"roundtrip_wire_calls":1,
 "roundtrip_new_intents":1,"recover_wire_calls":2,"crash_attempts":1,
 "complete_and_partial_forward_upper_bound":7,"pure_compiler_upper_bound":2,
 "training_steps":0,"wall_seconds":180,"server_cpu_seconds":60,
 "server_address_space_bytes":2*1024**3,"server_tokio_worker_threads":2,"automatic_retry":False,
}
t.BUDGET=BUDGET

def elf(raw):
    require(len(raw)>=64 and raw[:7]==b"\x7fELF\x02\x01\x01","ELF64 little endian required")
    header=struct.unpack_from("<16sHHIQQQIHHHHHH",raw)
    _,kind,machine,version,entry,phoff,shoff,flags,ehsize,phentsize,phnum,shentsize,shnum,shstr=header
    require(machine==62 and version==1 and kind in (2,3) and ehsize==64 and phentsize==56 and 0<phnum<=128,"bounded x86_64 ELF required")
    require(phoff+phnum*phentsize<=len(raw),"program header extent")
    loads=[]
    for i in range(phnum):
        fields=struct.unpack_from("<IIQQQQQQ",raw,phoff+i*phentsize)
        ptype,pflags,offset,vaddr,paddr,filesz,memsz,align=fields
        require(offset+filesz<=len(raw),"ELF segment extends beyond original bytes")
        if ptype==1:
            require(memsz>=filesz,"invalid load segment")
            loads.append({"index":i,"offset":offset,"file_bytes":filesz,"memory_bytes":memsz,
              "virtual_address":vaddr,"flags":pflags,"sha256":digest(raw[offset:offset+filesz])})
    require(loads,"no load segments")
    return {"entry_point":entry,"elf_header_sha256":digest(raw[:64]),
      "program_headers_sha256":digest(raw[phoff:phoff+phnum*phentsize]),"load_segments":loads}

def primary(path):
    raw=read(path,8*1024*1024,private=True);v=parse(raw)
    require(path.name=="CONTINUATION_RESULT_V1.json" and v["schema"]==COMPOSITE_SCHEMA
      and v["status"]=="PASS" and v["failure"] is None and v["cleanup_errors"]==[],
      "source-bound composite native qualification must already PASS")
    continuation=Path(__file__).resolve().with_name("late_quote_mcp_continuation.py")
    require(digest(read(continuation))==CONTINUATION_SHA==v["continuation_driver_sha256"],
      "actual reviewed continuation source differs")
    require(v["identity"]["source_commit"]==m.SOURCE_COMMIT and v["identity"]["source_tree"]==m.SOURCE_TREE
      and v["original_main_driver_sha256"]==MAIN_SHA,"composite exact native/original source identity differs")
    require(v["original_failed_main_result_sha256"]==PRIOR_RESULT_SHA
      and v["original_main_plan_sha256"]==PRIOR_PLAN_SHA
      and v["original_refusal_response_sha256"]==PRIOR_RESPONSE_SHA,"composite historical identities differ")
    require(digest(read(path.parent/"RESULT.json",4*1024*1024,private=True))==PRIOR_RESULT_SHA
      and digest(read(path.parent.parent/"plan.json",private=True))==PRIOR_PLAN_SHA
      and digest(read(path.parent/"a-first-main-019-response.json",private=True))==PRIOR_RESPONSE_SHA,
      "actual original failure/plan/refusal bytes were not preserved")
    require(v["original_failure_preserved"] is True and v["original_negative_effect_snapshot_available"] is False
      and v["new_schema_refusal_verified"] is True,"composite refusal evidence scope differs")
    require(isinstance(v["receipts"],dict) and set(v["receipts"])=={"47","83","137","crash137"},
      "composite native receipt set differs")
    require(isinstance(v["counts"],dict) and set(v["counts"])==set(COMPOSITE_COUNTS)
      and all(type(v["counts"][key]) is int and v["counts"][key]==value
              for key,value in COMPOSITE_COUNTS.items()),"composite cumulative counts differ")
    expected={"forward_source_control_flow_upper_bound":29,"pure_compiler_source_control_flow_upper_bound":8,
      "continuation_new_forward_upper_bound":7,"continuation_new_compiler_upper_bound":2,
      "prior_complete_forward_results":22,"optimizer_steps":0,"training_steps":0}
    require(all(type(v[key]) is int and v[key]==value for key,value in expected.items()),"composite scope differs")
    require(v["actual_total_forward_calls_claimed_exact"] is False
      and v["interrupted_partial_work_accounted_by_original_phase_ledgers"] is True
      and v["automatic_retry"] is False and v["production_deployment"] is False,
      "composite partial-work or execution-scope claim differs")
    return {"path":str(path),"sha256":digest(raw),"identity":v["identity"],
      "continuation_source_sha256":CONTINUATION_SHA,"original_failed_main_result_sha256":PRIOR_RESULT_SHA,
      "original_main_plan_sha256":PRIOR_PLAN_SHA,"original_refusal_response_sha256":PRIOR_RESPONSE_SHA}

def clocks(window):
    boot=Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    now=time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    wall=time.time_ns()//1000000
    stamp=window["native_boot_clock"]
    require(boot==stamp["boot_id"],"different boot cannot establish executable-specific refusal")
    elapsed=now-stamp["boottime_nanoseconds"]
    require(elapsed>=0,"kernel boottime moved backward")
    return {"boot_id":boot,"boottime_nanoseconds":now,"wall_unix_ms":wall,
      "boottime_remaining_seconds":60-elapsed/1e9,"wall_remaining_seconds":(window["expires_unix_ms"]-wall)/1000}

def live(window,minimum):
    v=clocks(window)
    require(v["boottime_remaining_seconds"]>minimum and v["wall_remaining_seconds"]>minimum,"original dual-clock window no longer establishes executable-specific refusal")
    return v

def actual_exe(server,path,sha):
    require(server.process.poll() is None,"owned process unavailable")
    proc=Path("/proc")/str(server.process.pid)/"exe"
    require(os.readlink(proc)==str(path),"actual owned executable path differs")
    fd=os.open(proc,os.O_RDONLY|os.O_CLOEXEC)
    try:
        before=os.fstat(fd);require(stat.S_ISREG(before.st_mode) and before.st_size<=512*1024**2,"bounded owned executable required")
        with os.fdopen(fd,"rb",closefd=False) as f:raw=f.read(512*1024**2+1)
        after=os.fstat(fd)
        require((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),"actual executable changed during read")
        require(digest(raw)==sha,"whole actual executable SHA differs")
        return {"owned_pid":server.process.pid,"proc_exe_path":str(proc),"resolved_executable":str(path),"bytes":len(raw),"sha256":sha}
    finally:os.close(fd)

def plan(args):
    root=Path(args.root);m.private_dir(root)
    require(digest(read(Path(m.__file__).resolve()))==MAIN_SHA,"reviewed main driver differs")
    require(digest(read(Path(t.__file__).resolve()))==m.TRANSPORT_SHA,"reviewed original transport differs")
    first=primary(Path(args.primary_result));ci=m.ci_check(Path(args.ci_receipt))
    identity=t.package_check(args.binary,args.package_manifest,m.SOURCE_COMMIT,m.SOURCE_TREE)
    require(identity==first["identity"],"original qualified binary differs from primary")
    for name in ("workspace","state","credentials","evidence","derived"):
        (root/name).mkdir(mode=0o700)
    for owner in ("a","b"):t.write_bytes_once(root/"credentials"/("operator-"+owner+".token"),secrets.token_hex(32).encode())
    source=read(args.binary,512*1024**2);loads=elf(source)
    derived=source+MARKER
    require(derived[:len(source)]==source and elf(derived)==loads and digest(derived)!=digest(source),"derived copy changes loaded program or lacks whole-SHA change")
    binary=root/"derived"/"hepta-runtime-nonloaded-marker"
    t.write_bytes_once(binary,derived,0o700)
    policy={"state_dir":str(root/"state"),"controller_workspace_roots":[str(root/"workspace")],
      "hosts":{"denied":{"ssh_target":"never-connect-executable-identity-control","remote_state_dir":str(root/"no-remote"),
      "allow_execute":False,"allow_pty":False,"allow_write":False,"allow_job_network":False}}}
    policy_sha=t.write_once(root/"policy.json",policy)
    index_raw,index=m.checked_input_index(Path(args.inputs))
    case=m.input_case(index,"137",root,"exe137")
    case_path=root/"evidence/case-exe137.json"
    case_sha=t.write_once(case_path,case)
    socks=[socket.socket() for _ in range(2)]
    try:
        for s in socks:s.bind(("127.0.0.1",0))
        ports=[s.getsockname()[1] for s in socks]
    finally:
        for s in socks:s.close()
    value={"schema":SCHEMA,"root":str(root),"binary":str(Path(args.binary)),"package_manifest":str(Path(args.package_manifest)),
      "identity":identity,"ci":ci,"primary":first,"policy_sha256":policy_sha,"ports":ports,"budget":BUDGET,
      "input_index_path":str(Path(args.inputs)),"input_index_sha256":digest(index_raw),
      "driver_sha256":digest(read(Path(__file__).resolve())),"main_driver_sha256":MAIN_SHA,
      "transport_sha256":m.TRANSPORT_SHA,"case":{"path":str(case_path),"sha256":case_sha},
      "derived_binary":{"path":str(binary),"sha256":digest(derived),"bytes":len(derived),"marker_hex":MARKER.hex(),
       "original_prefix_bytes":len(source),"original_prefix_sha256":digest(source),"load_identity":loads,
       "qualified_as_new_binary":False},"automatic_retry":False}
    target=root/"plan.json"
    print(json.dumps({"plan":str(target),"sha256":t.write_once(target,value),"model_forwards":0,"training_steps":0}))

def load_plan(path):
    raw=read(path,private=True);v=parse(raw);root=Path(v["root"]);m.private_dir(root)
    require(v["schema"]==SCHEMA and Path(path)==root/"plan.json" and v["budget"]==BUDGET,"wrong negative-control plan")
    require(v["driver_sha256"]==digest(read(Path(__file__).resolve())) and digest(read(Path(m.__file__).resolve()))==MAIN_SHA and digest(read(Path(t.__file__).resolve()))==m.TRANSPORT_SHA,"frozen source differs")
    require(t.package_check(v["binary"],v["package_manifest"],m.SOURCE_COMMIT,m.SOURCE_TREE)==v["identity"] and primary(Path(v["primary"]["path"]))==v["primary"] and m.ci_check(Path(v["ci"]["path"]))==v["ci"],"primary CI/executable evidence differs")
    index_raw,index=m.checked_input_index(Path(v["input_index_path"]))
    require(v["input_index_sha256"]==m.INPUT_INDEX_SHA==digest(index_raw),"negative-control fixed input index differs")
    for name in ("workspace","state","credentials","evidence","derived"):m.private_dir(root/name)
    require(not any((root/"state").iterdir()),"negative control state is not initially empty")
    require(len(v["ports"])==2 and len(set(v["ports"]))==2 and all(type(p) is int and 1024<=p<=65535 for p in v["ports"]),"distinct loopback ports required")
    require(digest(read(root/"policy.json",private=True))==v["policy_sha256"],"policy differs")
    pin=v["derived_binary"];source=read(v["binary"],512*1024**2);derived=read(pin["path"],512*1024**2)
    require(Path(pin["path"])==root/"derived/hepta-runtime-nonloaded-marker" and derived==source+MARKER and digest(derived)==pin["sha256"] and len(derived)==pin["bytes"] and elf(derived)==elf(source)==pin["load_identity"],"derived nonloaded marker copy differs")
    tokens={k:read(root/"credentials"/("operator-"+k+".token"),private=True).decode("ascii") for k in ("a","b")}
    require(tokens["a"]!=tokens["b"] and all(len(x)==64 and all(c in "0123456789abcdef" for c in x) for x in tokens.values()),"private credential shape")
    case_raw=read(v["case"]["path"],private=True);require(digest(case_raw)==v["case"]["sha256"],"case differs")
    case=parse(case_raw)
    m.verify_case_inputs(case,index,"137")
    require(Path(case["source_path"])==root/"workspace/exe137.safetensors" and digest(read(case["source_path"],private=True))==m.PARENT["137"],"case source differs")
    return raw,v,root,tokens,case

def run(args):
    raw,v,root,tokens,case=load_plan(Path(args.plan));rec=t.Recorder(root,v,tokens)
    servers=[];status="FAIL_OR_INCOMPLETE";failure=None;cleanup=[];evidence={}
    rec.record("run-intent.json",{"plan_sha256":digest(raw),"started_unix_ns":time.time_ns(),"budget":BUDGET,"automatic_retry":False})
    def start(label,port):
        s=t.Server(rec,label,"a",port);servers.append(s);return s
    try:
        publication=root/"state"/"weight-artifacts-v1"
        publication.mkdir(mode=0o700)
        m.private_dir(publication)
        require(not any(publication.iterdir()),"publication fixture must start empty")
        rec.record("publication-fixture.json",{"path":str(publication),"mode":"0700","entries":[],
          "stage":"after empty-state admission; before owned server or prepare",
          "model_manifest_or_journal_written":False,"model_forwards":0})
        original=start("original-before-kill",v["ports"][0]);client=m.Client(original,"main")
        evidence["original_running_executable"]=actual_exe(original,Path(v["binary"]),v["identity"]["binary_sha256"])
        sid,p,prewall=m.open_prepare(client,case,"exe137")
        start_wall=time.monotonic()
        boundary=m.crash_once(original,client,case,sid,p)
        evidence.update(session_id=sid,prepared=p,prepare_rpc_wall_seconds=prewall,interrupted_roundtrip_wall_seconds=time.monotonic()-start_wall,boundary=boundary)
        Path(case["source_path"]).unlink()
        window=boundary["original_window"]
        evidence["before_changed_start_clock"]=live(window,20)
        # This selects only our marker-derived owned copy. It does not replace
        # the original CI executable or upgrade its package qualification.
        rec.plan=dict(v,binary=v["derived_binary"]["path"])
        changed=start("changed-whole-sha",v["ports"][1]);client=m.Client(changed,"main")
        evidence["changed_running_executable"]=actual_exe(changed,Path(v["derived_binary"]["path"]),v["derived_binary"]["sha256"])
        evidence["before_first_recovery_clock"]=live(window,15)
        before=m.phases(root,p)
        require(before==boundary["phase_files"] and not before["late-restored-charge.json"]["present"],"Restored was already charged before code-identity gate")
        result=m.outer(client.call("rea_model_session_weight",m.recover_args(case,sid,p)))
        evidence["after_first_recovery_clock"]=live(window,0)
        m.inverse(root,case,p,result)
        require(result["new_complete_forward_results_this_request"]==0 and result["pure_compiler_invocations_this_request"]==0 and result["restored_evaluation"] is None and result["fresh_restored_complete_outputs_equal"] is False and result["research_roundtrip_verified"] is False,"changed executable performed or claimed new model qualification")
        require(result["errors"]==[{"stage":"original_window_restored_forward","error":"saved source or executable differs; inverse only, no new model work"}],"refusal was not uniquely caused by saved executable identity")
        require(result["original_running_executable_sha256"]==v["identity"]["binary_sha256"] and result["original_source_path_opened"] is False,"original identity/source boundary differs")
        require(m.phases(root,p)==before,"changed executable charged/replayed any phase")
        require(digest(read(m.journal(root,p)/"late-intent.json",private=True))==boundary["intent_sha256"],"original saved intent changed")
        evidence["first_recovery"]=result
        before_effects=m.effects(root)
        second=m.outer(client.call("rea_model_session_weight",m.recover_args(case,sid,p)))
        m.inverse(root,case,p,second)
        require(m.effects(root)==before_effects and m.phases(root,p)==before and second["new_complete_forward_results_this_request"]==0 and second["pure_compiler_invocations_this_request"]==0,"second inverse replayed model or state")
        evidence["second_recovery"]=second
        require(not Path(case["source_path"]).exists(),"source was recreated")
        require(rec.counts=={"server_starts":2,"rpc_wire_calls":9,"tool_calls":5,"roundtrip_wire_calls":1,"roundtrip_new_intents":1,"recover_wire_calls":2,"crash_attempts":1},"frozen negative-control operations differ")
        saved=parse(read(m.journal(root,p)/"late-intent.json",private=True))
        evidence["cost"]={"prepare_and_roundtrip_pure_compilers":2,
          "sum_native_preparation_wall_seconds":p["source_admission_and_preparation_wall_seconds"]+saved["preparation_wall_seconds"]}
        status="PASS"
    except BaseException as error:
        failure={"type":type(error).__name__,"message":str(error)}
    finally:
        for server in reversed(servers):
            try:server.stop(kill=status!="PASS")
            except BaseException as error:cleanup.append({"server":server.label,"type":type(error).__name__,"message":str(error)})
        if not cleanup and status=="PASS":
            try:rec.remaining_seconds()
            except BaseException as error:cleanup.append({"stage":"wall_budget","type":type(error).__name__,"message":str(error)})
        if cleanup:status="FAIL_OR_INCOMPLETE"
        result={"schema":SCHEMA+".result","status":status,"failure":failure,"cleanup_errors":cleanup,
          "plan_sha256":digest(raw),"identity":v["identity"],"derived_binary":v["derived_binary"],"primary":v["primary"],
          "evidence":evidence,"counts":rec.counts,"budget":BUDGET,"wall_seconds":time.monotonic()-rec.started,
          "full_and_partial_forward_source_upper_bound":7,
          "successful_captured_window_forward_upper_bound":5 if status=="PASS" else None,
          "missed_window_possible_original_restored_forwards_included":True,
          "actual_interrupted_work_exact_count_claimed":False,
          "training_steps":0,"optimizer_steps":0,"new_executable_qualified":False,"arbitrary_upgrade_compatibility_claimed":False,
          "production_deployment":False,"automatic_retry":False}
        pin=rec.record("RESULT.json",result)
        print(json.dumps({"status":status,"result":str(rec.evidence_root/"RESULT.json"),"sha256":pin,"failure":failure,"cleanup_errors":cleanup}))
    return 0 if status=="PASS" else 1

def main():
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest="action",required=True)
    q=sub.add_parser("plan")
    for name in ("root","binary","package-manifest","ci-receipt","inputs","primary-result"):q.add_argument("--"+name,required=True)
    q=sub.add_parser("run");q.add_argument("--plan",required=True)
    a=p.parse_args();return plan(a) if a.action=="plan" else run(a)
if __name__=="__main__":sys.exit(main())

