#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Reconstructed native LateQuote MCP qualification after the original workspace loss.

This is a NEW driver and protocol. It reuses the recovered, byte-identical
transport_reference.py; it does not claim the lost driver's SHA. Plan is zero
model work. Run requires exact-head and prospective-merge CI receipts and a
separately reviewed plan. All server processes are owned, loopback-only,
resource bounded. It never activates a model or retries an uncertain attempt.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import secrets
import select
import signal
import socket
import stat
import struct
import sys
import threading
import time
import transport_reference as t

TRANSPORT_SHA = "8c2eb9a1405a2c4606a03800ada15de12bc8df70ea82a312b6b3a31e45d50391"
LOST_DRIVER_SHA = "283e535c10a2065e797baf44c9232db3adac26d09fa6c47c285ce855fd1cc198"
SOURCE_COMMIT = "16dbc208a21e4aca99dd576fb731a877598219dd"
SOURCE_TREE = "64fe6409be734a82d2ee5a28f7f17db12fc6208e"
CI_RUN = 46149528261
INPUT_INDEX_SHA = "e078644b92cb22ac39c0a1d8c14e8a01e9c572f8ccee0c15eee509e9109da5bc"
PROFILE = "smallhcsn_late_quote_min_mark4_task_route_v1"
BUDGET = {
    "server_starts":4, "rpc_wire_calls":50, "tool_calls":32,
    "roundtrip_wire_calls":10, "roundtrip_new_intents":4,
    "recover_wire_calls":6, "crash_attempts":1,
    "complete_and_partial_forward_upper_bound":29,
    "pure_compiler_upper_bound":8, "training_steps":0, "wall_seconds":900,
    "server_cpu_seconds":180, "server_address_space_bytes":2*1024**3,
    "server_tokio_worker_threads":2, "automatic_retry":False,
}
# The unchanged transport reads this explicit adapter budget for its generic
# recorder/server process limits. No native evaluator or authority is replaced.
t.BUDGET = BUDGET
require, read, parse, digest = t.require, t.read, t.parse, t.digest
PARENT = {
 "47":"9d3b61f40aa45b4a1e25299b2204e4022c113a801a6b3ad15c9ba2f948bac430",
 "83":"f248653cc821a05440598200ac7af1d5e76bdbb574627bda5a914046d7a5b64e",
 "137":"fc414bf4387be537ab8f807707aba5430fbd528c89ac6a137cb858c4d8159443",
}
RAW = {"late_input":"9b7626acf2359246833a88e7fca01f65be34674f7a8d3f3276e2f6475c81dd8e",
 "retention_input":"46dd3a525b4de1645becdf1bff720d80b08e8976109e68a3423458949c2f20e0"}
EXPECT = {
 "47":{"action":"keep","candidate":PARENT["47"],"normal":25,"unconditional":24,"forwards":7},
 "83":{"action":"sign","candidate":"57d2a1b0507f0f80a0eed37402084bfbaaa4d5a086fdfba7571f5da0f71c3a02","normal":27,"unconditional":23,"forwards":8},
 "137":{"action":"keep","candidate":PARENT["137"],"normal":27,"unconditional":24,"forwards":7},
}
ROLES = ("parent","late_profile","late_input","retention_profile","retention_input")
SCHEMA = "hepta.late-quote.http-relocated-qualification.v1"

def private_dir(p):
    require(p.is_absolute() and p.resolve(strict=True)==p,"canonical directory required")
    s=p.lstat()
    require(stat.S_ISDIR(s.st_mode) and s.st_uid==os.geteuid() and stat.S_IMODE(s.st_mode)==0o700,"owned 0700 directory required")

def ci_check(path):
    raw=read(path)
    v=parse(raw)
    require(v["source_commit"]==SOURCE_COMMIT and v["source_tree"]==SOURCE_TREE and v["run_id"]==CI_RUN,"CI source identity differs")
    jobs=v["jobs"]
    require(len(jobs)==2 and {j["name"] for j in jobs}=={"Rust exact-head validation","Rust prospective-merge validation"},"two CI lanes required")
    require(all(j["status"]=="completed" and j["conclusion"]=="success" for j in jobs),"both full CI lanes must succeed before execution")
    return {"path":str(path),"sha256":digest(raw),"run_id":CI_RUN,"jobs":jobs}

def checked_input_index(path):
    raw=read(path)
    require(digest(raw)==INPUT_INDEX_SHA,"input index differs from the independently frozen protocol SHA")
    index=parse(raw)
    require(index["schema"]=="hepta.late-quote.recovered-inputs.v1" and set(index["cases"])==set(PARENT),"wrong recovered input index")
    return raw,index

def input_payloads(index,seed):
    source=index["cases"][seed];data={};pins={}
    for role in ROLES:
        pin=source[role];body=read(pin["path"],1024*1024)
        require(digest(body)==pin["sha256"] and len(body)==pin["bytes"],"recovered input identity mismatch")
        if role=="parent": require(pin["sha256"]==PARENT[seed],"wrong original parent")
        if role in RAW: require(pin["sha256"]==RAW[role],"wrong original task input")
        data[role]=body
        pins[role]={"sha256":digest(body),"bytes":len(body),"original_path":pin["path"]}
    request={"profile_json":data["late_profile"].decode("utf-8"),"raw_input_hex":data["late_input"].hex(),
       "retention_profile_json":data["retention_profile"].decode("utf-8"),
       "retention_raw_input_hex":data["retention_input"].hex(),
       "minimum_accuracy_percent":95,"maximum_update_l2_norm":1.0}
    return data,pins,request

def input_case(index,seed,root,name):
    data,pins,request=input_payloads(index,seed)
    dest=root/"workspace"/(name+".safetensors")
    t.write_bytes_once(dest,data["parent"])
    return {"seed":seed,"source_path":str(dest),"source_sha256":PARENT[seed],
       "source_bytes":len(data["parent"]),"source_reference":index["cases"][seed]["parent"],
       "input_pins":pins,"request":request,"expected":EXPECT[seed],
       "scientific_role":"previously observed engineering replay; no new holdout"}

def verify_case_inputs(case,index,seed):
    data,pins,request=input_payloads(index,seed)
    require(case["seed"]==seed and case["input_pins"]==pins and case["request"]==request,
            "sealed case data or request differs from the fixed input index")
    require(case["source_reference"]==index["cases"][seed]["parent"]
            and case["source_bytes"]==len(data["parent"])
            and case["source_sha256"]==PARENT[seed] and case["expected"]==EXPECT[seed],
            "sealed case parent or mechanism differs from the fixed input index")

def plan(args):
    root=Path(args.root)
    require(sys.platform=="linux","Linux required")
    private_dir(root)
    require(digest(read(Path(t.__file__).resolve()))==TRANSPORT_SHA,"recovered transport differs")
    identity=t.package_check(Path(args.binary),Path(args.package_manifest),SOURCE_COMMIT,SOURCE_TREE)
    require(identity["ci_run_id"]==str(CI_RUN) or identity["ci_run_id"]==CI_RUN,"package run differs")
    ci=ci_check(Path(args.ci_receipt))
    index_raw,index=checked_input_index(Path(args.inputs))
    for name in ("workspace","state","credentials","evidence"):
        (root/name).mkdir(mode=0o700)
    for owner in ("a","b"):
        t.write_bytes_once(root/"credentials"/("operator-"+owner+".token"),secrets.token_hex(32).encode())
    policy={"state_dir":str(root/"state"),"controller_workspace_roots":[str(root/"workspace")],
      "hosts":{"denied":{"ssh_target":"never-connect-late-quote-research",
       "remote_state_dir":str(root/"no-remote"),"allow_execute":False,"allow_pty":False,
       "allow_write":False,"allow_job_network":False}}}
    policy_sha=t.write_once(root/"policy.json",policy)
    cases={}
    for name,seed in (("47","47"),("83","83"),("137","137"),("crash137","137")):
        case=input_case(index,seed,root,name)
        p=root/"evidence"/("case-"+name+".json")
        cases[name]={"path":str(p),"sha256":t.write_once(p,case)}
    sockets=[socket.socket() for _ in range(4)]
    try:
        for s in sockets:s.bind(("127.0.0.1",0))
        ports=[s.getsockname()[1] for s in sockets]
    finally:
        for s in sockets:s.close()
    value={"schema":SCHEMA,"root":str(root),"binary":str(Path(args.binary)),
       "package_manifest":str(Path(args.package_manifest)),"identity":identity,"ci":ci,
       "policy_sha256":policy_sha,"cases":cases,"ports":ports,"budget":BUDGET,
       "driver_sha256":digest(read(Path(__file__).resolve())),"transport_sha256":TRANSPORT_SHA,
       "input_index_path":str(Path(args.inputs)),"input_index_sha256":digest(index_raw),"original_driver_unavailable_sha256":LOST_DRIVER_SHA,
       "reconstructed_after_workspace_loss":True,"automatic_retry":False,
       "scope":"source-bound finite task/graph research, conditional graph routing; no production or global NDU claim"}
    p=root/"plan.json"
    print(json.dumps({"plan":str(p),"sha256":t.write_once(p,value),"model_forwards":0,"optimizer_steps":0}))

def schema_error(raw,request_id):
    require(len(raw)<=t.MAX_WIRE,"schema response byte cap")
    text=raw.decode("utf-8")
    if text.lstrip().startswith("{"): records=[parse(text)]
    else:
        records=[];data=[]
        for line in text.replace("\r\n","\n").replace("\r","\n").split("\n")+[""]:
            if not line:
                if data:
                    joined="\n".join(data)
                    if joined: records.append(parse(joined))
                    data=[]
            elif line=="data" or line.startswith("data:"):
                part="" if line=="data" else line[5:]
                data.append(part[1:] if part.startswith(" ") else part)
    require(all(isinstance(v,dict) for v in records),"nonobject JSON-RPC record")
    matches=[v for v in records if type(v.get("id")) is type(request_id) and v.get("id")==request_id]
    require(len(matches)==1,"schema refusal must have one exact request identity")
    v=matches[0]
    require(v.get("jsonrpc")=="2.0" and "result" not in v and isinstance(v.get("error"),dict),"invalid error envelope")
    require(type(v["error"].get("code")) is int and v["error"]["code"]==-32602,"only InvalidParams qualifies")
    return v

class Client(t.Client):
    def call(self,tool,arguments,denied=False,invalid_schema=False):
        require(not (denied and invalid_schema),"one negative-control expectation")
        rec=self.server.recorder
        rec.reserve("tool_calls")
        kind=arguments.get("operation",{}).get("kind")
        if kind=="late_quote_roundtrip":rec.reserve("roundtrip_wire_calls")
        if kind=="late_quote_recover":rec.reserve("recover_wire_calls")
        try:
            result=self.rpc("tools/call",{"name":tool,"arguments":arguments})
        except ValueError as error:
            if not invalid_schema or str(error)!="MCP protocol error":raise
            name=f"{self.server.label}-{self.label}-{self.request_id:03d}-response.json"
            recorded=parse(read(rec.evidence_root/name,private=True))
            raw=recorded["raw_utf8"].encode("utf-8")
            require(recorded["status"]==200 and digest(raw)==recorded["raw_sha256"],"recorded HTTP refusal differs")
            value=schema_error(raw,self.request_id)
            rec.record("cross-profile-schema-refusal.json",{"response_file":name,"response_raw_sha256":digest(raw),"jsonrpc_code":value["error"]["code"],"request_id":self.request_id,"rpc_replayed":False})
            return None
        require(not invalid_schema,"cross-profile schema unexpectedly admitted")
        if denied:
            require(result.get("isError") is True,"required authenticated refusal absent")
            return None
        require(not result.get("isError",False),"required native operation refused")
        return parse("\n".join(x.get("text","") for x in result.get("content",[]) if x.get("type")=="text"))

def arguments(case,sid,op):
    return {"session_id":sid,"parent_sha256":case["source_sha256"],"profile":PROFILE,"operation":op}

def outer(v):
    require(v["schema"]=="hepta.rea.session-late-quote-research.v1" and v["fixed_scope"]==PROFILE,"wrong typed native scope")
    require(v["credential_metadata_resume"] is True and v["paths_derived_from_session"] is True,"actual credential authority absent")
    for key in ("accepted_for_activation","production_eligible","automatic_retry","background_crash_recovery","upstream_provenance_verified","global_ndu_optimality_verified"):
        require(v[key] is False,"unsupported native scope claim")
    return v["result"]

def effects(root):
    out={}
    for name in ("weight-artifacts-v1","weight-cohort-journal-v1"):
        base=root/"state"/name
        if not os.path.lexists(base):out[name]={"kind":"absent"};continue
        stack=[base]
        while stack:
            p=stack.pop();s=p.lstat()
            require(len(out)<4096 and p.resolve(strict=True)==p and not stat.S_ISLNK(s.st_mode),"effect inventory boundary")
            row={"dev":s.st_dev,"ino":s.st_ino,"mode":stat.S_IMODE(s.st_mode),"uid":s.st_uid,"links":s.st_nlink,"mtime_ns":s.st_mtime_ns,"ctime_ns":s.st_ctime_ns}
            if stat.S_ISDIR(s.st_mode):
                private_dir(p);children=sorted(p.iterdir());row.update(kind="directory",children=[c.name for c in children]);stack.extend(children)
            else:
                b=read(p,2*1024*1024,private=True);row.update(kind="file",bytes=len(b),sha256=digest(b))
            e=p.lstat()
            require((s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)==(e.st_dev,e.st_ino,e.st_mode,e.st_uid,e.st_nlink,e.st_size,e.st_mtime_ns,e.st_ctime_ns),"effect entry changed during observation")
            out[str(p.relative_to(root/"state"))]=row
    return out

def journal(root,p):
    return root/"state"/"weight-cohort-journal-v1"/p["journal_id"]

def phases(root,p):
    directory=journal(root,p)
    names=["late-"+phase+"-"+kind+".json" for phase in ("parent","candidate","restored") for kind in ("charge","result")]
    return {name:{"present":(directory/name).exists(),"sha256":digest(read(directory/name,private=True)) if (directory/name).exists() else None} for name in names}

def artifact(root,receipt,sha):
    aid=receipt["artifact_id"]
    require(aid.startswith("wc1_") and len(aid)==68,"bad artifact id")
    path=root/"state"/"weight-artifacts-v1"/aid/"model.safetensors"
    require(receipt["artifact_path"]==str(path) and receipt["sha256"]==sha,"artifact receipt differs")
    raw=read(path,131072,private=True);require(digest(raw)==sha,"actual checkpoint digest differs")
    m=parse(read(path.with_name("manifest.json"),private=True))
    require(m["artifact_id"]==aid and m["target_sha256"]==sha and m["schema"]=="hepta.weight.native-cohort.v1","actual manifest differs")
    require(m["research_binding"]==receipt["function_capsule"],"receipt capsule differs from atomically published manifest")
    require(receipt["source_modified"] is False and receipt["incumbent_pointer_modified"] is False and receipt["production_eligible"] is False,"unsupported artifact claim")
    return raw,m

def inverse(root,case,p,result):
    require(result["journal_id"]==p["journal_id"] and result["plan_sha256"]==p["plan_sha256"],"original request identity changed")
    require(result["weights_graph_route_initial_state_and_evaluator_restored"] is True,"full function inverse missing")
    actual,m=artifact(root,result["restoration"],case["source_sha256"])
    require(actual==read(case["source_reference"]["path"],131072),"inverse is not every original checkpoint byte")
    cap=m["research_binding"]
    require(cap["function"]==p["parent_function"] and cap["normal_route_function"]==p["parent_function"],"inverse lacks full original function and route")
    require(cap["role"]=="restored" and cap["route_contract"]=={"late_request_graph":"original","normal_request_graph":"original","late_request_requires_checked_task":False,"same_weight_bytes_for_both_routes":True},"inverse route contract differs")
    require(m["parent_artifact_id"]==result["candidate"]["artifact_id"],"inverse is not the selected artifact's child")
    require(m["artifact_id"]!=m["parent_artifact_id"],"same weights cannot skip graph restoration")

def open_prepare(client,case,label):
    opened=client.call("rea_model_session_open",{"path":case["source_path"],"expected_sha256":case["source_sha256"]})
    sid=opened["session_id"];root=client.server.recorder.root
    before=effects(root);start=time.monotonic()
    prepared=outer(client.call("rea_model_session_weight",arguments(case,sid,{"kind":"late_quote_prepare","request":case["request"]})))
    wall=time.monotonic()-start;after=effects(root)
    require(before==after,"pure preparation wrote model effects")
    require(prepared["model_forward_calls"]==0 and prepared["optimizer_steps"]==0 and prepared["journal_written"] is False and prepared["candidate_published"] is False and prepared["compilation_label_reads"]==0,"prepare violated zero-work scope")
    require(not journal(root,prepared).exists(),"prepare created an attempt")
    require(prepared["parent_function"]["artifact_sha256"]==case["source_sha256"],"prepared parent differs")
    require(prepared["parent_function"]["graph"]=="original" and prepared["parent_function"]["request_route"]=="original_fixed_profile","parent graph/route differs")
    require(prepared["keep_function"]["artifact_sha256"]==case["source_sha256"] and prepared["keep_function"]["graph"]=="final_tick_tied_receiver_mark","KEEP semantic identity differs")
    require(all(prepared[k]["initial_state_contract"]=="fixed_reset_step0_six_tick_v1" for k in ("parent_function","keep_function","sign_function")),"initial-state contract is not fixed reset step zero")
    require(prepared["keep_function"]["request_route"]=="checked_late_quote_min_v1" and prepared["sign_function"]["request_route"]=="checked_late_quote_min_v1","candidate route lacks checked task")
    client.server.recorder.record(label+"-prepare.json",{"session_id":sid,"result":prepared,"rpc_wall_seconds":wall,"before":before,"after":after})
    return sid,prepared,wall

def rt(case,sid,p):
    return arguments(case,sid,{"kind":"late_quote_roundtrip","request":case["request"],"expected_journal_id":p["journal_id"]})

def recover_args(case,sid,p):
    return arguments(case,sid,{"kind":"late_quote_recover","journal_id":p["journal_id"],"expected_plan_sha256":p["plan_sha256"]})

def observations(result):
    rows=[]
    for key in ("parent_evaluation","candidate_evaluation","restored_evaluation"):
        phase=result.get(key)
        if isinstance(phase,dict):rows.extend(phase["observations"])
    return rows

def verified_result(root,case,p,result,identity):
    inverse(root,case,p,result)
    e=case["expected"]
    require(result["original_running_executable_sha256"]==identity["binary_sha256"] and result["original_evaluator_source_sha256"]==p["parent_function"]["evaluator_source_sha256"],"full executable or evaluator identity differs")
    require(result["pure_compiler_invocations_this_request"]==1,"first roundtrip compiler cost differs")
    require(result["selected_action"]==e["action"] and result["research_roundtrip_verified"] is True,"task-scoped research goal failed")
    require(result["candidate_goal_met"] is True and result["fresh_restored_complete_outputs_equal"] is True,"goal or restored outputs failed")
    require(result["scoped_original_graph_retention_byte_equal"] is True and result["scoped_retention_uses_same_selected_weights"] is True and result["scoped_retention_requires_conditional_graph_routing"] is True,"conditional same-weights retention missing")
    require(result["unconditional_graph_retention_passed"] is False and result["unconditional_graph_accepted"] is False,"unconditional negative control unexpectedly differs from sealed prior observation")
    require(result["optimizer_steps"]==0 and result["global_ndu_optimality_verified"] is False and result["errors"]==[],"scope or numerical error")
    raw,manifest=artifact(root,result["candidate"],e["candidate"])
    chosen=p["keep_artifact_id"] if e["action"]=="keep" else p["sign_artifact_id"]
    require(manifest["artifact_id"]==chosen and manifest["research_binding"]["function"]==p[e["action"]+"_function"],"selection escaped prebound alternatives")
    words=manifest["request"]["members"]
    require(len(words)==1 and words[0]["tensor_name"]=="body.input_mark.weight" and [x["index"] for x in words[0]["edits"]]==[7,16,25,34],"four-word scope differs")
    rows={v["name"]:v for v in observations(result)}
    chosen_late=rows["bridge_keep"] if e["action"]=="keep" else rows["selected_late"]
    require(chosen_late["metrics"]["correct"]==80 and chosen_late["metrics"]["queries"]==80,"selected actual late-quote score differs")
    require(rows["original_late"]["metrics"]["correct"]==40 and rows["original_normal"]["metrics"]["correct"]==e["normal"] and rows["unconditional_normal"]["metrics"]["correct"]==e["unconditional"],"frozen engineering controls differ")
    require(result["new_complete_forward_results_this_request"]==e["forwards"],"full forward count differs")
    return {"source_bytes_equal_after":read(case["source_path"],private=True)==read(case["source_reference"]["path"]),"selected_correct":80,"selected_queries":80,"unconditional_accepted":False,"conditional_graph_routing_required":True}

class PublicationWatch(t.PublicationWatch):
    def next_expected(self,expected,deadline):
        while time.monotonic()<deadline:
            ready,_,_=select.select([self.fd],[],[],max(0,min(.2,deadline-time.monotonic())))
            if not ready:continue
            raw=os.read(self.fd,65536);pos=0
            while pos+16<=len(raw):
                _,mask,_,length=struct.unpack_from("iIII",raw,pos)
                name=raw[pos+16:pos+16+length].split(b"\0",1)[0].decode();pos+=16+length
                require(not(mask&0x4000),"inotify queue overflow")
                if mask&0x80 and name.startswith("wc1_"):
                    require(name==expected,"first cohort publication was not the prebound KEEP")
                    return name
        raise TimeoutError("single publication window missed; no automatic retry")

def crash_once(server,client,case,sid,p):
    rec=server.recorder;root=rec.root;store=root/"state"/"weight-artifacts-v1"
    rec.reserve("crash_attempts");rec.reserve("roundtrip_new_intents")
    watcher=PublicationWatch(store);outcome={}
    def send():
        try:outcome["response"]=client.call("rea_model_session_weight",rt(case,sid,p))
        except BaseException as e:outcome["transport_error"]={"type":type(e).__name__,"message":str(e)}
    thread=threading.Thread(target=send,daemon=True);thread.start()
    try:
        aid=watcher.next_expected(p["keep_artifact_id"],time.monotonic()+min(60,rec.remaining_seconds()))
        require(server.process.poll() is None,"owned runtime exited before boundary")
        os.killpg(server.process.pid,signal.SIGSTOP)
        t.wait_for_owned_stop(server.process,time.monotonic()+min(5,rec.remaining_seconds()))
        candidate=store/aid
        m=parse(read(candidate/"manifest.json",private=True))
        require(m["artifact_id"]==aid and m["target_sha256"]==case["source_sha256"] and read(candidate/"model.safetensors",private=True)==read(case["source_reference"]["path"]),"same-SHA crash checkpoint differs")
        cap=m["research_binding"]
        require(cap["function"]==p["keep_function"] and cap["function"]!=p["parent_function"] and cap["original_plan_sha256"]==p["plan_sha256"],"graph-only crash identity not prebound")
        saved=read(journal(root,p)/"late-intent.json",private=True)
        require(parse(saved)["plan"]["running_executable_sha256"]==rec.plan["identity"]["binary_sha256"],"crash attempt executable differs")
        decision=parse(read(journal(root,p)/"late-decision.json",private=True))
        require(decision["action"]=="keep" and decision["selected_artifact_id"]==aid,"crash selection differs")
        inverses=[]
        for path in store.glob("wc1_*/manifest.json"):
            row=parse(read(path,private=True))
            if row["parent_artifact_id"]==aid:inverses.append(row["artifact_id"])
        before=phases(root,p)
        require(not inverses and not before["late-restored-charge.json"]["present"] and not before["late-restored-result.json"]["present"],"post-publication pre-inverse window missed")
        boundary={"candidate_artifact_id":aid,"same_checkpoint_sha256":case["source_sha256"],"different_function_verified":True,
          "inverse_ids_before_kill":inverses,"intent_sha256":digest(saved),"phase_files":before,"decision":decision,
          "original_window":{k:parse(saved)[k] for k in ("created_unix_ms","expires_unix_ms","native_boot_clock")},
          "owned_pid":server.process.pid,"owned_process_group_SIGSTOP_confirmed":True,"automatic_retry":False}
        rec.record("crash-boundary.json",boundary)
        server.stop(kill=True)
        require(server.process.returncode==-signal.SIGKILL,"actual owned SIGKILL was not observed")
        thread.join(timeout=10)
        require(not thread.is_alive() and "transport_error" in outcome and "response" not in outcome,"RPC was not actually interrupted")
        rec.record("crash-transport.json",outcome)
        return boundary
    finally:
        watcher.close()
        if server.process.poll() is None:server.stop(kill=True)
        thread.join(timeout=10)

def load_plan(path):
    raw=read(path,private=True);v=parse(raw);root=Path(v["root"])
    private_dir(root)
    require(Path(path)==root/"plan.json" and v["schema"]==SCHEMA and v["budget"]==BUDGET,"wrong sealed plan")
    require(v["driver_sha256"]==digest(read(Path(__file__).resolve())) and digest(read(Path(t.__file__).resolve()))==TRANSPORT_SHA,"sealed driver or transport differs")
    require(digest(read(root/"policy.json",private=True))==v["policy_sha256"],"sealed policy differs")
    require(t.package_check(v["binary"],v["package_manifest"],SOURCE_COMMIT,SOURCE_TREE)==v["identity"],"qualified package differs")
    require(ci_check(Path(v["ci"]["path"]))==v["ci"],"CI receipt differs")
    index_raw,index=checked_input_index(Path(v["input_index_path"]))
    require(v["input_index_sha256"]==INPUT_INDEX_SHA==digest(index_raw),"sealed fixed input index identity differs")
    for name in ("workspace","state","credentials","evidence"):private_dir(root/name)
    require(not any((root/"state").iterdir()),"execution must begin with empty isolated state")
    require(len(v["ports"])==4 and len(set(v["ports"]))==4 and all(type(p) is int and 1024<=p<=65535 for p in v["ports"]),"distinct frozen loopback ports required")
    tokens={k:read(root/"credentials"/("operator-"+k+".token"),private=True).decode("ascii") for k in ("a","b")}
    require(tokens["a"]!=tokens["b"] and all(len(x)==64 and all(c in "0123456789abcdef" for c in x) for x in tokens.values()),"invalid private credentials")
    cases={}
    require(set(v["cases"])=={"47","83","137","crash137"},"case set changed")
    for name,pin in v["cases"].items():
        require(Path(pin["path"])==root/"evidence"/("case-"+name+".json"),"case path escaped")
        body=read(pin["path"],private=True);require(digest(body)==pin["sha256"],"sealed case changed")
        case=parse(body)
        verify_case_inputs(case,index,name if name in PARENT else "137")
        require(Path(case["source_path"])==root/"workspace"/(name+".safetensors") and digest(read(case["source_path"],private=True))==case["source_sha256"]==PARENT[case["seed"]],"sealed source changed")
        cases[name]=case
    return raw,v,root,tokens,cases

def run(args):
    raw,v,root,tokens,cases=load_plan(Path(args.plan))
    rec=t.Recorder(root,v,tokens);servers=[];receipts={};status="FAIL_OR_INCOMPLETE";failure=None;cleanup=[]
    rec.record("run-intent.json",{"plan_sha256":digest(raw),"started_unix_ns":time.time_ns(),"budget":BUDGET,"reconstructed_protocol":True,"automatic_retry":False})
    def start(label,owner,port):
        server=t.Server(rec,label,owner,port);servers.append(server);return server
    try:
        a=start("a-first","a",v["ports"][0]);client=Client(a,"main")
        for name in ("47","83","137"):
            case=cases[name];sid,p,prepare_wall=open_prepare(client,case,name)
            rec.reserve("roundtrip_new_intents");started=time.monotonic()
            result=outer(client.call("rea_model_session_weight",rt(case,sid,p)))
            rtwall=time.monotonic()-started
            checks=verified_result(root,case,p,result,v["identity"])
            require(checks["source_bytes_equal_after"],"source checkpoint was modified")
            repeats=[]
            for n in range(2):
                before=effects(root)
                repeat=outer(client.call("rea_model_session_weight",rt(case,sid,p)))
                after=effects(root)
                require(before==after and repeat["new_complete_forward_results_this_request"]==0 and repeat["pure_compiler_invocations_this_request"]==0 and repeat["reused_original_result"] is True,"identical roundtrip repeated model or state work")
                inverse(root,case,p,repeat);repeats.append(repeat)
            receipts[name]={"session_id":sid,"prepared":p,"roundtrip":result,"repeat_roundtrips":repeats,"checks":checks,
              "cost":{"prepare_rpc_wall_seconds":prepare_wall,"first_roundtrip_rpc_wall_seconds":rtwall,
               "pure_compiler_invocations":2,"sum_preparation_wall_seconds":p["source_admission_and_preparation_wall_seconds"]+result["original_preparation_wall_seconds"]}}
            rec.record("case-"+name+"-result.json",receipts[name])
        first=receipts["47"];case=cases["47"]
        before=effects(root)
        bad=arguments(case,first["session_id"],{"kind":"late_quote_compile","request":case["request"]});bad["parent_sha256"]="0"*64
        client.call("rea_model_session_weight",bad,denied=True)
        bad=arguments(case,first["session_id"],{"kind":"late_quote_compile","request":case["request"]})
        bad["profile"]="smallhcsn_centered_sender_drive_and_bias40_v1"
        client.call("rea_model_session_weight",bad,invalid_schema=True)
        require(effects(root)==before,"denied identity/schema changed state")
        a.stop()
        b=start("b-other-owner","b",v["ports"][1]);other=Client(b,"main")
        before=effects(root)
        other.call("rea_model_session_weight",recover_args(case,first["session_id"],first["prepared"]),denied=True)
        require(effects(root)==before,"other owner changed model state")
        b.stop()
        for name in ("47","83","137"):Path(cases[name]["source_path"]).unlink()
        cold=start("a-cold","a",v["ports"][2]);client=Client(cold,"main")
        for name in ("47","83","137"):
            case=cases[name];item=receipts[name];before=effects(root)
            result=outer(client.call("rea_model_session_weight",recover_args(case,item["session_id"],item["prepared"])))
            require(effects(root)==before and result["new_complete_forward_results_this_request"]==0 and result["pure_compiler_invocations_this_request"]==0 and result["original_source_path_opened"] is False,"cold complete recovery performed new work")
            inverse(root,case,item["prepared"],result)
            require(not Path(case["source_path"]).exists(),"recovery recreated source")
            rec.record("case-"+name+"-cold-recovery.json",result)
        case=cases["crash137"];sid,p,pwall=open_prepare(client,case,"crash137")
        boundary=crash_once(cold,client,case,sid,p)
        Path(case["source_path"]).unlink()
        last=start("a-after-kill","a",v["ports"][3]);client=Client(last,"main")
        recovered=outer(client.call("rea_model_session_weight",recover_args(case,sid,p)))
        inverse(root,case,p,recovered)
        require(recovered["original_source_path_opened"] is False and recovered["parent_or_candidate_forward_replayed"] is False and recovered["selection_replayed_on_recovery"] is False and recovered["pure_compiler_invocations_this_request"]==0,"crash recovery replayed original work")
        require(recovered["new_complete_forward_results_this_request"]==2 and recovered["fresh_restored_complete_outputs_equal"] is True,"original-window fresh inverse forwards absent")
        require(digest(read(journal(root,p)/"late-intent.json",private=True))==boundary["intent_sha256"],"recovery changed original immutable intent")
        after=phases(root,p)
        for name,pin in boundary["phase_files"].items():
            if not name.startswith("late-restored-"):require(after[name]==pin,"recovery replayed/replaced Parent or Candidate phase")
        before=effects(root)
        second=outer(client.call("rea_model_session_weight",recover_args(case,sid,p)))
        require(effects(root)==before and second["new_complete_forward_results_this_request"]==0 and second["pure_compiler_invocations_this_request"]==0,"second crash recovery repeated work")
        inverse(root,case,p,second)
        require(not Path(case["source_path"]).exists(),"crash source reappeared")
        receipts["crash137"]={"session_id":sid,"prepared":p,"prepare_rpc_wall_seconds":pwall,"boundary":boundary,"first_recovery":recovered,"second_recovery":second}
        require(rec.counts["server_starts"]==4 and rec.counts["roundtrip_new_intents"]==4 and rec.counts["roundtrip_wire_calls"]==10 and rec.counts["crash_attempts"]==1,"frozen primary operation omitted")
        require(rec.counts["recover_wire_calls"]==6,"expected five valid and one foreign-owner refused recovery")
        status="PASS"
    except BaseException as error:
        failure={"type":type(error).__name__,"message":str(error)}
    finally:
        for server in reversed(servers):
            try:server.stop(kill=status!="PASS")
            except BaseException as error:cleanup.append({"server":server.label,"type":type(error).__name__,"message":str(error)})
        if not cleanup and status=="PASS":
            try:rec.remaining_seconds()
            except BaseException as error:cleanup.append({"stage":"final_wall_budget","type":type(error).__name__,"message":str(error)})
        if cleanup:status="FAIL_OR_INCOMPLETE"
        rows=[]
        for name,item in receipts.items():
            result=item.get("roundtrip") or item.get("first_recovery")
            if result:rows.extend(observations(result))
        seen=sum(len(observations(item["roundtrip"])) for name,item in receipts.items() if "roundtrip" in item)
        crash=receipts.get("crash137",{}).get("first_recovery")
        if crash:seen+=crash["attempt_ledger"]["completed_forward_calls_with_durable_results"]
        result={"schema":SCHEMA+".result","status":status,"failure":failure,"cleanup_errors":cleanup,
          "plan_sha256":digest(raw),"identity":v["identity"],"counts":rec.counts,"budget":BUDGET,"receipts":receipts,
          "complete_forward_results_observed":seen,"actual_total_forward_calls_claimed_exact":False,
          "interrupted_partial_work_accounted_by_original_phase_ledgers":True,"forward_source_control_flow_upper_bound":29,
          "pure_compiler_source_control_flow_upper_bound":8,"optimizer_steps":0,"training_steps":0,
          "wall_seconds":time.monotonic()-rec.started,"production_deployment":False,"automatic_retry":False,
          "historical_driver_sha256":LOST_DRIVER_SHA,"reconstructed_driver_sha256":v["driver_sha256"],
          "original_transport_sha256":TRANSPORT_SHA,"scope":"engineering replay on previously observed batches; conditional two-graph routing with identical selected weights"}
        pin=rec.record("RESULT.json",result)
        print(json.dumps({"status":status,"result":str(rec.evidence_root/"RESULT.json"),"sha256":pin,"failure":failure,"cleanup_errors":cleanup}))
    return 0 if status=="PASS" else 1

def main():
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest="action",required=True)
    q=sub.add_parser("plan")
    for name in ("root","binary","package-manifest","ci-receipt","inputs"):q.add_argument("--"+name,required=True)
    q=sub.add_parser("run");q.add_argument("--plan",required=True)
    args=p.parse_args()
    return plan(args) if args.action=="plan" else run(args)
if __name__=="__main__":sys.exit(main())

