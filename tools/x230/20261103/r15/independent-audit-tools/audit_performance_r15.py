#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""R15 independent raw performance audit, adapted from the audited R14 recomputation.
Default invocation only describes policy. --audit is a one-shot terminal-gated
read/recompute operation; it never launches a workload or imports an analyzer.
"""
import argparse, collections, datetime, hashlib, json, math, os, re, statistics, sys, traceback
from pathlib import Path
ROOT=Path("/home/qian/hepta-runtime-optimization-20261103-r15")
R14=Path("/home/qian/hepta-runtime-optimization-20261103-r14")
R11="660d64674fe3422006c0c2a82bc31f3f36edf19baf6613df7cdce51e8f3f8e4c"
CANDIDATE="51480b3cf630a95419d3afeb571eec17c90cffa5944101920d05333673de031d"
CONFIG_QUAL_SHA="bce0c05b8f13e6858ecd14d024364450cc08fd90f8adabb55d5c1323c0944a89"
REUSED_R14_AUDITOR_SHA="fd9caa8a161790efc00f92441c9562067ba1de73db9a79eedcee940f51891eb3"
INPUTS={}
RETAINED_BINDINGS={}
RAW_REPORTS=(
 "cancel-r14-r15-01/report.json","cancel-r11-r15-01/report.json",
 "native-r14-r15-01/report.json","native-r11-r15-01/report.json")


def need(value,message):
    if not value: raise RuntimeError(message)
def digest(data): return hashlib.sha256(data).hexdigest()
def sha(path):
    with Path(path).open("rb") as stream: return hashlib.file_digest(stream,"sha256").hexdigest()
def finite(value,path="root"):
    if isinstance(value,float): need(math.isfinite(value),"nonfinite value: "+path)
    elif isinstance(value,dict):
        for key,child in value.items(): finite(child,path+"."+key)
    elif isinstance(value,list):
        for i,child in enumerate(value): finite(child,path+"["+str(i)+"]")
def load(path):
    path=Path(path)
    raw=path.read_bytes()
    actual=digest(raw)
    if str(path) in RETAINED_BINDINGS:
        expected=RETAINED_BINDINGS[str(path)]
        need(actual==expected["sha256"] and len(raw)==expected["bytes"],"retained artifact binding differs: "+str(path))
    INPUTS[str(path)]=actual
    value=json.loads(raw)
    finite(value,str(path))
    return value
def equal_number(a,b):
    return isinstance(a,(int,float)) and not isinstance(a,bool) and math.isfinite(a) and math.isclose(a,b,rel_tol=1e-9,abs_tol=1e-10)
def positive(value,message): need(isinstance(value,(int,float)) and not isinstance(value,bool) and math.isfinite(value) and value>0,message)
def percentile(values,p):
    need(bool(values),"empty percentile")
    return sorted(values)[max(0,math.ceil(len(values)*p)-1)]
def percent(before,after):
    positive(before,"zero percent denominator")
    return (after/before-1)*100
def canonical(value):
    return (json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode()
def within(base,name):
    path=Path(name)
    if not path.is_absolute(): path=base/path
    need(path.resolve().is_relative_to(base.resolve()),"artifact outside campaign directory")
    return path
def file_bound(base,name,expected):
    path=within(base,name)
    actual=sha(path)
    need(actual==expected,"artifact SHA differs: "+str(path))
    return path
def comparison(a,b,keys):
    return {key:{"baseline":a[key],"candidate":b[key],"change_percent":percent(a[key],b[key])} for key in keys}



EXPECTED_ALLOCATOR = {"MALLOC_ARENA_MAX": "1"}
RUN_SCHEMA = "hepta-x230-child-allocator-run/v1"
LIVE_SCHEMA = "hepta-x230-child-allocator-observation/v1"
HOSTS = {"ai395", "mac", "main", "pocket4", "rog", "x230"}
TOOLS = {"process_status", "process_read"}
SEEN_CONTROLLERS = {}
TOOL_BINDINGS = {}
def register_controller(startup, origin):
    pid, birth = startup["pid"], startup["birth_ticks"]
    need(type(pid) is int and pid > 0 and type(birth) is int and birth > 0, "invalid controller identity")
    identity = (pid, birth)
    need(identity not in SEEN_CONTROLLERS, "controller generation reused across performance campaigns")
    SEEN_CONTROLLERS[identity] = origin

def allocator_observation(startup, expected, agent_required, origin):
    register_controller(startup, origin)
    value = startup["allocator_environment"]
    need(value["schema"] == LIVE_SCHEMA and value["status"] == "verified", "no live controller environment evidence")
    need(value["pid"] == startup["pid"] and value["birth_ticks"] == startup["birth_ticks"], "live environment PID/start mismatch")
    need(value["phase"] == "after-native-initialize", "live environment phase differs")
    need(value["requested"] == value["observed"] == expected, "wrong effective allocator arm")
    need(value["environment_sha256"] == digest(canonical(expected)), "observed environment fingerprint mismatch")
    need(value["source"] == "same-PID/start-ticks /proc/PID/environ" and value["full_environment_retained"] is False, "environment observation provenance differs")
    need(value["ssh_auth_sock_present"] is agent_required and value["held_ssh_agent_preserved"] is agent_required, "held SSH agent evidence differs")
    return {"pid":startup["pid"], "birth_ticks":startup["birth_ticks"], "phase":value["phase"],
            "observed":value["observed"], "environment_sha256":value["environment_sha256"],
            "held_agent_required":agent_required, "source":value["source"]}

def allocator_report(report, binaries, kind, directory):
    meta = report["allocator_configuration"]
    need(meta["schema"] == RUN_SCHEMA and meta["platform"] == "linux" and meta["libc"] == "glibc 2.39", "allocator platform/schema differs")
    need(meta["helper_sha256"] == TOOL_BINDINGS["allocator_environment.py"]["sha256"], "allocator helper binding differs")
    need(meta["parent_environment_modified"] is False and meta["allocator_keys_cleared"] == ["MALLOC_*", "GLIBC_TUNABLES"], "allocator isolation policy differs")
    need(meta["comparison_identity"] == "binary_sha256+allocator_environment", "configuration identity scheme differs")
    need(set(meta["variants"]) == {"A","B"} and meta["same_binary_sha256"] is (binaries["A"] == binaries["B"]), "allocator variant identity differs")
    for arm in "AB":
        item = meta["variants"][arm]
        expected = {} if arm == "A" else EXPECTED_ALLOCATOR
        need(item["environment"] == expected and item["binary_sha256"] == binaries[arm], "allocator binary/environment binding differs")
        need(item["environment_sha256"] == digest(canonical(expected)), "allocator environment hash differs")
        need(item["configuration_fingerprint"] == digest(canonical({"binary_sha256":binaries[arm],"allocator_environment":expected})), "allocator configuration fingerprint differs")
    need(meta["variants"]["A"]["configuration_fingerprint"] != meta["variants"]["B"]["configuration_fingerprint"], "A/B identity collapsed")
    observations = []
    for i, row in enumerate(report["rounds"]):
        arm = row["arm"] if kind == "cancel" else row["version"]
        expected = {} if arm == "A" else EXPECTED_ALLOCATOR
        for key in (("startup",) if kind == "cancel" else ("startup","restart_startup")):
            proof = allocator_observation(row[key],expected,kind == "native",directory+":"+str(i)+":"+key)
            observations.append({"round":i,"arm":arm,"startup_key":key,**proof})
    need(len(observations) == (16 if kind == "cancel" else 8), "controller environment count differs")
    return {"verified":True, "metadata":meta, "live_observation_count":len(observations), "observations":observations,
            "scope":"Validate retained actual /proc observations and their identity/arm bindings from hash-bound launcher code; no postmortem live process reread is claimed."}

def measured_stats(values):
    need(values and all(isinstance(v,(int,float)) and not isinstance(v,bool) and math.isfinite(v) and v >= 0 for v in values), "invalid latency samples")
    return {"count":len(values),"minimum_ms":min(values),"maximum_ms":max(values),
            "p50_ms":percentile(values,.5),"p95_ms":percentile(values,.95),"p99_ms":percentile(values,.99)}

def check_distribution(recorded, values, native=False):
    actual = measured_stats(values)
    mapping = {"p50_ms":"p50_ms","p95_ms":"p95_ms","p99_ms":"p99_ms","max_ms":"maximum_ms"} if native else {
        "count":"count","minimum_ms":"minimum_ms","maximum_ms":"maximum_ms","p50_ms":"p50_ms","p95_ms":"p95_ms"}
    for old,key in mapping.items():
        need(equal_number(recorded[old],actual[key]), "stored latency statistic differs: "+old)
    return actual

def negative_results(campaigns):
    rows=[]
    for campaign,value in campaigns.items():
        for cell in value["cells"]:
            for metric,change in cell["comparison"].items():
                direction = "lower_is_worse" if metric in ("mixed_rpc_per_second","calls_per_second") else "higher_is_worse"
                delta=change["change_percent"]
                if (delta < 0 and direction=="lower_is_worse") or (delta > 0 and direction=="higher_is_worse"):
                    rows.append({"campaign":campaign, **{k:cell[k] for k in ("workers","receipt_bytes","concurrency") if k in cell},
                                 "metric":metric,"baseline":change["baseline"],"candidate":change["candidate"],
                                 "change_percent":delta,"direction":direction,"statistical_significance_claimed":False})
        for scope in ("whole_controller_memory_comparison","restart_controller_memory_comparison"):
            for metric,change in value.get(scope,{}).items():
                if change["change_percent"] > 0:
                    rows.append({"campaign":campaign,"memory_scope":scope,"metric":metric,**change,
                                 "direction":"higher_is_worse","statistical_significance_claimed":False})
    return rows

def flat_campaign(value):
    result = {k:v for k,v in value.items() if k not in ("cells","allocator_environment_verification")}
    proof=value["allocator_environment_verification"]
    result["allocator_environment_verification"] = {"verified":True,"live_observation_count":proof["live_observation_count"],
        "same_binary_sha256":proof["metadata"]["same_binary_sha256"],
        "variants":proof["metadata"]["variants"]}
    result["cells"]=[]
    for cell in value["cells"]:
        result["cells"].append({**{k:v for k,v in cell.items() if k not in ("arms","comparison")},
            "A":cell["arms"]["A"],"B":cell["arms"]["B"],
            "change_percent":{k:v["change_percent"] for k,v in cell["comparison"].items()}})
    return result



LOCAL_FINAL_SHA="b65a3d425edd91620f859ee8e14a4556b40651f4d94a022c088f7707e8a180e8"
FIXED_INPUTS={
 "baseline-binding.json":"d701ad5c2d101ed389614083b386324c092182dcf19cb4f4bf0777e232d3c37a",
 "configuration/configuration-ready.json":"fb4a2e8eab0bfafb0c272c4c3e259cd1d68dffbaa479796854a73a1100fcc947",
 "independent-audit-tools/tooling-install-01.json":"34f0d32bcdf5057ec1cf8148a51dd13773f1235841074e0f2b8914bdfb8e461d",
 "independent-audit-tools/local-orchestrator-ready-01.json":"f321182f6bd94b948b22948e524b5eaa0c42d08436e49ed9bf778f8a27196960",
 "independent-audit-tools/remote-orchestrator-ready-01.json":"181c6385afeb9b253435dd15cb90c7804928512ad1e361fcfed1c644efaa2d20"}
def remember_file(path,expected=None,expected_bytes=None):
    path=Path(path)
    need(path.is_file() and not path.is_symlink(),"bound artifact is not a direct regular file: "+str(path))
    actual=sha(path)
    if expected is not None: need(actual==expected,"bound file SHA differs: "+str(path))
    if expected_bytes is not None: need(path.stat().st_size==expected_bytes,"bound file length differs: "+str(path))
    INPUTS[str(path)]=actual
    return actual

def bound_json(path,expected):
    value=load(path)
    need(INPUTS[str(Path(path))]==expected,"bound JSON SHA differs: "+str(path))
    return value

def stopped_driver(info):
    need(isinstance(info,dict) and type(info["pid"]) is int and type(info["start_ticks"]) is int,"missing driver generation")
    try:
        data=Path("/proc")/str(info["pid"])/"stat"
        fields=data.read_text().rsplit(") ",1)[1].split()
    except FileNotFoundError:
        return {"pid":info["pid"],"start_ticks":info["start_ticks"],"original_generation_running":False,"observation":"absent"}
    running=int(fields[19])==info["start_ticks"] and fields[0] not in {"Z","X"}
    need(not running,"campaign driver is still running; no audit/wait/retry is allowed")
    return {"pid":info["pid"],"start_ticks":info["start_ticks"],"original_generation_running":False,
            "observation":"exited-or-different-generation"}

def add_retained(item):
    path=within(ROOT,item["path"])
    key=str(path)
    entry={"path":key,"sha256":item["sha256"],"bytes":item["bytes"]}
    need(re.fullmatch("[0-9a-f]{64}",entry["sha256"]) is not None and type(entry["bytes"]) is int and entry["bytes"]>=0,"bad retained binding")
    if key in RETAINED_BINDINGS: need(RETAINED_BINDINGS[key]==entry,"conflicting retained artifact binding")
    RETAINED_BINDINGS[key]=entry
    return entry

def gates(expected_remote_sha):
    # Only metadata is read until all three completed gates and driver exits pass.
    config=bound_json(ROOT/"configuration-qualification-01/report.json",CONFIG_QUAL_SHA)
    local=bound_json(ROOT/"local-campaigns-01/report.json",LOCAL_FINAL_SHA)
    remote=bound_json(ROOT/"remote-campaigns-01/report.json",expected_remote_sha)
    need(config.get("success") is True and config.get("finished_utc"),"configuration qualification is incomplete")
    retired={}
    for label,report in (("local",local),("remote",remote)):
        need(report.get("success") is True and report.get("state")=="completed" and report.get("finished_utc")
             and not report.get("error") and report.get("automatic_retries")==0,"campaign incomplete/failed/retried: "+label)
        need(report.get("compilation_started") is False and report.get("rust_source_modified") is False,"unexpected compilation/source change")
        need(report["configuration_qualification"]["sha256"]==CONFIG_QUAL_SHA,"configuration gate binding differs")
        need(report["candidate_allocator_environment"]==EXPECTED_ALLOCATOR,"pipeline candidate allocator differs")
        retired[label]=stopped_driver(report["driver_process"])
    need(remote["local_gate"]["sha256"]==LOCAL_FINAL_SHA and remote["expected_local_report_sha256"]==LOCAL_FINAL_SHA,"remote/local terminal hash differs")
    need(local["remote_operations"]==0 and local["production_service_changes"] is False and remote["production_service_mutations"]==0,"pipeline scope differs")
    need(config["runtime_sha256"]==CANDIDATE and config["allocator_environment"]==EXPECTED_ALLOCATOR,"qualified binary/configuration differs")
    need(config["source_files"]==219 and config["source_tested_after_current_frozen_equal"] is True
         and config["source"]==str(R14/"source") and config["qualification_reused"]==str(R14/"qualification-01/report.json"),"qualified source binding differs")
    need(config["tests"]=={"passed":1637,"failed":0,"ignored":33,"selected":1670,"retries":0},"configuration qualification counts differ")
    need(config["compiler_invocations"]==0 and config["automatic_retries"]==0 and config["rust_source_modified"] is False,"configuration qualification scope differs")
    need(config["allocator_observation_counts"]=={"verified":1647,"unavailable_process_exited":0},"qualified environment observation counts differ")
    fixed={name:bound_json(ROOT/name,digest_) for name,digest_ in FIXED_INPUTS.items()}
    baseline=fixed["baseline-binding.json"]
    ready=fixed["configuration/configuration-ready.json"]
    install=fixed["independent-audit-tools/tooling-install-01.json"]
    lready=fixed["independent-audit-tools/local-orchestrator-ready-01.json"]
    rready=fixed["independent-audit-tools/remote-orchestrator-ready-01.json"]
    need(ready["success"] is True and ready["selected_arena_max"]=="1","configuration ready differs")
    need(config["configuration_ready_sha256"]==FIXED_INPUTS["configuration/configuration-ready.json"]
         and config["tooling_install_sha256"]==FIXED_INPUTS["independent-audit-tools/tooling-install-01.json"],"configuration provenance differs")
    for item in ready["files"].values(): remember_file(item["path"],item["sha256"],item["bytes"])
    need(install["success"] is True and install["rust_sources_modified"] is False and install["compilation_started"] is False,"tool installation differs")
    for item in install["files"]:
        name=Path(item["path"]).name
        need(name not in TOOL_BINDINGS,"duplicate tool file")
        remember_file(item["path"],item["sha256"],item["bytes"])
        TOOL_BINDINGS[name]=item
    for label,report,ready_meta,ready_key in (
        ("local",local,lready,"local_orchestrator_ready_sha256"),
        ("remote",remote,rready,"remote_orchestrator_ready_sha256")):
        need(ready_meta["success"] is True and len(ready_meta["stage_plan"])==6,"orchestrator ready differs")
        needed=FIXED_INPUTS["independent-audit-tools/"+label+"-orchestrator-ready-01.json"]
        need(report[ready_key]==needed,"orchestrator ready report binding differs")
        files={Path(item["path"]).name:item for item in ready_meta["files"]}
        driver=files["run_"+label+"_campaigns.py"]
        need(report["driver_sha256"]==driver["sha256"],"orchestrator driver SHA differs")
        for item in files.values(): remember_file(item["path"],item["sha256"],item["bytes"])
        need(len(report["stages"])==6,"orchestrator stage count differs")
        for actual,planned in zip(report["stages"],ready_meta["stage_plan"]):
            need(actual["name"]==planned["name"] and actual["command"]==planned["command"]
                 and actual["timeout_seconds"]==planned["timeout_seconds"],"executed stage differs from frozen plan")
            need(actual["returncode"]==0 and actual["automatic_retries"]==0
                 and actual.get("finished_utc") and not actual.get("error"),"stage failed/incomplete/retried")
            need(actual["driver_environment"]["allocator_entries"]=={},"dirty driver allocator environment")
            for field in ("stdout","stderr"):
                item=actual[field]
                path=within(ROOT,item["path"])
                remember_file(path,item["sha256"],item["bytes"])
        for item in report["retained_result_files"]: add_retained(item)
    expected_retained=set()
    for key in ("r14","r11"):
        local_dir=ROOT/("cancel-"+key+"-r15-01")
        expected_retained.update(str(local_dir/name) for name in ("report.json","independent-summary.json","independent-summary.md"))
        native_dir=ROOT/("native-"+key+"-r15-01")
        expected_retained.update(str(native_dir/name) for name in ("report.json","independent-summary.json"))
    expected_retained.update(str(ROOT/"cancel-recovery-01"/name) for name in ("report.json","independent-summary.json"))
    need(set(RETAINED_BINDINGS)==expected_retained,"retained result matrix differs")
    for key in ("r14","r11"):
        for report,section,dirname in ((local,"campaign_results","cancel-"+key+"-r15-01"),(remote,"native_results","native-"+key+"-r15-01")):
            item=report[section][key]["raw"]
            need(item["path"]==str(ROOT/dirname/"report.json"),"pipeline raw output path differs")
            need({k:item[k] for k in ("path","sha256","bytes")}==RETAINED_BINDINGS[item["path"]],"pipeline raw hash receipt differs")
    # Bind auxiliary results by hash only. Their metrics are never consumed.
    raw_set={str(ROOT/name) for name in RAW_REPORTS}
    for path,item in RETAINED_BINDINGS.items():
        if path not in raw_set: remember_file(path,item["sha256"],item["bytes"])
    for item in (config["summary"],config["audit"]):
        remember_file(item["path"],item["sha256"],item["bytes"])
    need(baseline["release_binaries"]["hepta-runtime"]["sha256"]==CANDIDATE,"R14 baseline runtime differs")
    for name,item in config["release_binaries"].items():
        need(name in baseline["release_binaries"] and item["path"]==baseline["release_binaries"][name]["path"]
             and item["sha256"]==baseline["release_binaries"][name]["sha256"],"qualified release binding differs")
    need(config["r14_qualification_sha256"]==baseline["qualification_sha256"],"R14 qualification reference differs")
    # Only the two runtime executables are hashed here; retained libtests belong
    # to the separate independent qualification audit, not a repeated 538 MiB read.
    remember_file(R14/"qualification-01/hepta-runtime",CANDIDATE)
    remember_file(Path("/home/qian/hepta-runtime-optimization-20261103-r11/qualification-01/hepta-runtime"),R11)
    return {"configuration_qualification_sha256":CONFIG_QUAL_SHA,"local_report_sha256":LOCAL_FINAL_SHA,
        "remote_report_sha256":expected_remote_sha,"original_drivers_retired":retired,
        "qualified_tests":config["tests"],"qualified_allocator_observation_counts":config["allocator_observation_counts"],
        "qualification_audit_scope":"Uses the frozen configuration-qualification receipt; the separate independent qualification audit owns complete libtest revalidation.",
        "local_stage_names":[s["name"] for s in local["stages"]],"remote_stage_names":[s["name"] for s in remote["stages"]],
        "retained_raw_report_bindings":{name:RETAINED_BINDINGS[str(ROOT/name)] for name in RAW_REPORTS},
        "monitor_scope":local["monitor_scope"]}


def cancellation(directory,baseline):
    base=ROOT/directory
    r=load(base/"report.json")
    need(r["schema"]=="hepta-x230-cancel-responsiveness/v1","cancel schema differs")
    need(r["harness_sha256"]==TOOL_BINDINGS["run_cancel_responsiveness.py"]["sha256"],"cancel harness SHA differs")
    environment_proof=allocator_report(r,{"A":baseline,"B":CANDIDATE},"cancel",directory)
    need(r["okay"] and r["automatic_retries"]==0 and r["binaries_unchanged"],"cancel campaign failed/retried")
    need(r["binary_sha256"]=={"A":baseline,"B":CANDIDATE},"cancel binary binding differs")
    need(r["order"]=="ABBA" and r["concurrency"]==8 and r["waves"]==24 and r["payload"]=="escaped","cancel plan differs")
    need(len(r["rounds"])==16,"cancel round count differs")
    groups=collections.defaultdict(list)
    matrix=set()
    identities=set()
    reply_count=0
    for sample in r["rounds"]:
        key=(sample["workers"],sample["receipt_bytes"],sample["position"])
        need(key not in matrix and sample["arm"]=="ABBA"[sample["position"]],"cancel ABBA matrix differs")
        matrix.add(key)
        identity=(sample["startup"]["pid"],sample["startup"]["birth_ticks"])
        need(identity not in identities,"controller generation reused")
        identities.add(identity)
        need(all(sample[k] is True for k in ("okay","no_cancel_intent","no_ssh_dispatch","receipt_unchanged")),"cancel guard assertion failed")
        need(sample["shutdown"]["exit_code"]==0 and sample["shutdown"]["reader_error"] is None and sample["shutdown"]["unmatched"]==0 and sample["shutdown"]["method"]=="stdin_eof","cancel shutdown mismatch")
        positive(sample["wall_seconds"],"invalid cancel wall")
        positive(sample["controller_cpu_seconds"],"invalid cancel CPU")
        for label,count in (("measured",216),("warmup",18)):
            rows=sample[label]
            need(len(rows)==count,"cancel measured/warmup count differs")
            need(len({v["rpc_id"] for v in rows})==count,"duplicate cancel RPC id")
            expected_counts={"process_cancel":192,"host_list":24} if label=="measured" else {"process_cancel":16,"host_list":2}
            need(dict(collections.Counter(v["params"]["name"] for v in rows))==expected_counts,"cancel method mix differs")
            for row in rows:
                positive(row["elapsed_ms"],"invalid cancel latency")
                need(row["method"]=="tools/call" and row["expected_result"] is True,"cancel row not accepted")
                response=row["response"]
                need(response.get("jsonrpc")=="2.0" and response.get("id")==row["rpc_id"] and "error" not in response,"cancel JSON-RPC reply differs")
                need(digest(canonical(response))==row["response_sha256"],"cancel raw reply hash differs")
                result=response["result"]
                text=[part["text"] for part in result.get("content",[]) if part.get("type")=="text"]
                need(bool(text),"cancel reply missing text")
                if row["params"]["name"]=="process_cancel":
                    need(row["params"]["arguments"]=={"grace_seconds":0,"host":"other","job_id":"cancel-responsiveness"},"cancel arguments differ")
                    need(result.get("isError") is True and text==["job `cancel-responsiveness` belongs to host `owner`, not `other`"],"wrong-host refusal differs")
                else:
                    need(row["params"]["arguments"]=={} and result.get("isError") is False,"host_list refused")
                    dto=json.loads(text[0])
                    need({v["name"] for v in dto["hosts"]}=={"owner","other"} and len(dto["hosts"])==2,"host_list result differs")
                reply_count+=1
        need(len({v["rpc_id"] for v in sample["measured"]+sample["warmup"]})==234,"warmup and measurement ids overlap")
        for wave in range(24):
            rows=[v for v in sample["measured"] if v["wave"]==wave]
            need(len(rows)==9 and collections.Counter(v["params"]["name"] for v in rows)=={"process_cancel":8,"host_list":1},"wave mix differs")
        for tool in ("process_cancel","host_list"):
            values=[v["elapsed_ms"] for v in sample["measured"] if v["params"]["name"]==tool]
            check_distribution(sample[tool],values)
        groups[(sample["workers"],sample["receipt_bytes"],sample["arm"])].append(sample)
    need(matrix=={(workers,size,p) for workers in (1,2) for size in (1024,4194272) for p in range(4)},"cancel matrix incomplete")
    need(reply_count==3744,"cancel RPC total differs")
    cells=[]
    for workers in (1,2):
        for size in (1024,4194272):
            arms={}
            hashes=set()
            for arm in "AB":
                samples=groups[(workers,size,arm)]
                need(len(samples)==2,"cancel arm count differs")
                rows=[v for s in samples for v in s["measured"]]
                calls=len(rows)
                cpu=sum(s["controller_cpu_seconds"] for s in samples)
                wall=sum(s["wall_seconds"] for s in samples)
                lat={name:[v["elapsed_ms"] for v in rows if v["params"]["name"]==name] for name in ("process_cancel","host_list")}
                hwm=[s["memory_after"]["kib"]["VmHWM"] for s in samples]
                rss=[s["memory_after"]["kib"]["VmRSS"] for s in samples]
                need(calls==432 and len(lat["process_cancel"])==384 and len(lat["host_list"])==48,"cancel denominator differs")
                rss_before=[s["memory_before"]["kib"]["VmRSS"] for s in samples]
                hwm_before=[s["memory_before"]["kib"]["VmHWM"] for s in samples]
                for v in hwm+rss+rss_before+hwm_before: positive(v,"invalid cancel memory")
                hashes.update(s["receipt_sha256"] for s in samples)
                arm_value={"mixed_calls":calls,"cancel_calls":384,"host_list_calls":48,
                    "cpu_seconds":cpu,"wall_seconds":wall,"cpu_ms_per_mixed_rpc":cpu*1000/calls,"mixed_rpc_per_second":calls/wall,
                    "vmhwm_kib_samples":hwm,"vmhwm_kib_median":statistics.median(hwm),
                    "vmrss_after_kib_samples":rss,"vmrss_after_kib_median":statistics.median(rss),
                    "vmrss_before_kib_samples":rss_before,"vmrss_before_kib_median":statistics.median(rss_before),
                    "vmhwm_before_kib_samples":hwm_before,"vmhwm_before_kib_median":statistics.median(hwm_before),
                    "process_samples":[]}
                for name,values in lat.items():
                    prefix="cancel" if name=="process_cancel" else "host_list"
                    calculated=measured_stats(values)
                    for stat in ("p50_ms","p95_ms","p99_ms","minimum_ms","maximum_ms"):
                        arm_value[prefix+"_"+stat]=calculated[stat]
                for sample in samples:
                    count=len(sample["measured"])
                    arm_value["process_samples"].append({
                        "position":sample["position"],"pid":sample["startup"]["pid"],"birth_ticks":sample["startup"]["birth_ticks"],
                        "measured_mixed_calls":count,"cpu_seconds":sample["controller_cpu_seconds"],"wall_seconds":sample["wall_seconds"],
                        "cpu_ms_per_mixed_rpc":sample["controller_cpu_seconds"]*1000/count,
                        "mixed_rpc_per_second":count/sample["wall_seconds"],
                        "host_list":measured_stats([v["elapsed_ms"] for v in sample["measured"] if v["params"]["name"]=="host_list"]),
                        "process_cancel":measured_stats([v["elapsed_ms"] for v in sample["measured"] if v["params"]["name"]=="process_cancel"]),
                        "memory_before":sample["memory_before"],"memory_after":sample["memory_after"],
                        "environment_sha256":sample["startup"]["allocator_environment"]["environment_sha256"]})
                arms[arm]=arm_value
            need(len(hashes)==1,"A/B receipt bytes differ")
            cells.append({"workers":workers,"receipt_bytes":size,"receipt_sha256":next(iter(hashes)),"arms":arms,"comparison":comparison(arms["A"],arms["B"],["cpu_ms_per_mixed_rpc","mixed_rpc_per_second","host_list_p50_ms","host_list_p95_ms","host_list_p99_ms","host_list_maximum_ms","cancel_p50_ms","cancel_p95_ms","cancel_p99_ms","cancel_maximum_ms","vmhwm_kib_median","vmrss_after_kib_median","vmrss_before_kib_median"])})
    return {"allocator_environment_verification":environment_proof,"report_sha256":INPUTS[str(base/"report.json")],"baseline_sha256":baseline,"candidate_sha256":CANDIDATE,"child_processes":16,"measured_calls":3456,"warmup_calls_excluded":288,"all_reply_hashes_and_semantics_verified":reply_count,"automatic_retries":0,"cells":cells,"scope":"Expected wrong-host refusals plus host_list; CPU denominator is mixed RPCs. VmHWM is sampled after measurement, since exec, including warmup; not per-request allocation. VmRSS before/after are point samples, not idle or peak RSS.",
        "percentile_scope":"Pooled measured per-call nearest-rank. Per-arm host_list N=48 makes p99 the maximum; cancel N=384 gives p99 rank381. No population tail stability or statistical significance is claimed.",
        "clock_scope":"Recorded elapsed and CPU/wall deltas are finite and aggregated; original clock endpoints were not retained and cannot be independently recreated."}


def native(directory,baseline):
    base=ROOT/directory
    r=load(base/"report.json")
    need(r["schema"]=="hepta-x230-readonly-observation-abba/v1","native schema differs")
    environment_proof=allocator_report(r,{"A":baseline,"B":CANDIDATE},"native",directory)
    measure=r["r12_measurement"]
    need(measure["scripts_unchanged"] is True and measure["wrapper_sha256"]==TOOL_BINDINGS["run_native_observation.py"]["sha256"] and measure["helper_sha256"]==TOOL_BINDINGS["x230_observation_benchmark.py"]["sha256"],"native harness binding differs")
    need(measure["balanced_warmup_calls_per_cell"]==24 and measure["warmup_included_in_performance_denominator"] is False and measure["sampled_tree_cpu_used_for_performance"] is False,"native measurement scope differs")
    need(r["passed"] and r["automatic_rpc_retries"]==0 and r["binary_hashes_unchanged"],"native campaign failed/retried")
    need(r["binary_sha256"]=={"A":baseline,"B":CANDIDATE},"native binary binding differs")
    need(r["order"]=="ABBA" and r["concurrency"]==[1,4,8] and r["calls_per_cell"]==96 and r["tokio_workers"]==2,"native plan differs")
    need(r["remote_mutation_tool_calls"]==0 and r["effect_starts"]==0 and r["source_originals_unchanged"],"native read-only invariants differ")
    originals={v["host"]:v for v in r["six_originals"]}
    need(len(r["six_originals"])==6 and set(originals)==HOSTS,"native six-host set differs")
    groups=collections.defaultdict(list)
    resources={"A":[],"B":[]}
    restart_resources={"A":[],"B":[]}
    all_rows=[]
    measured=warmup=checks=0
    measured_mix=warmup_mix=None
    metric_errors=[]
    def row_check(row):
        need(row.get("okay") is True and row.get("isError") is False and row.get("automatic_retry") is False,"native row unsuccessful or retried")
        need(row["host"] in originals and row["job_id"]==originals[row["host"]]["job_id"],"native original identity differs")
        need(row["tool"] in ("process_status","process_read","process_wait"),"unexpected native tool")
        positive(row["elapsed_ms"],"invalid native latency")
        for key in ("dto_sha256","response_sha256"): need(re.fullmatch("[0-9a-f]{64}",row[key]) is not None,"invalid native digest")
        if "stdout_bytes" in row:
            original=originals[row["host"]]
            need(row["stdout_bytes"]==original["stdout_bytes"] and row["stdout_sha256"]==original["stdout_sha256"],"complete original output binding differs")
            need(row["stderr_bytes"]==0 and row["stderr_sha256"]==digest(b""),"original stderr differs")
    need(len(r["rounds"])==4,"native round count differs")
    for index,round_ in enumerate(r["rounds"]):
        need(round_["index"]==index and round_["version"]=="ABBA"[index] and round_["passed"],"native ABBA order differs")
        need([cell["concurrency"] for cell in round_["cells"]]==[1,4,8],"native concurrency matrix differs")
        initial=round_["initial_complete_outputs"]
        restart=round_["restart_checks"]
        need(len(initial)==6 and len(restart)==12,"native verification call count differs")
        need(collections.Counter((v["host"],v["tool"]) for v in initial)=={(h,"process_read"):1 for h in HOSTS},"native preflight mix differs")
        need(collections.Counter((v["host"],v["tool"]) for v in restart)=={(h,t):1 for h in HOSTS for t in TOOLS},"native restart mix differs")
        for row in initial+restart: row_check(row)
        checks+=len(initial)+len(restart)
        all_rows.extend(initial+restart)
        for cell in round_["cells"]:
            for label,batch,expected in (("measured",cell,96),("warmup",cell["warmup"],24)):
                rows=batch["rows"]
                need(batch["calls"]==batch["successes"]==len(rows)==expected and batch["no_success_filtering"] is True,"native call count differs")
                need(batch["concurrency"]==cell["concurrency"],"native warmup C differs")
                positive(batch["seconds"],"invalid native duration")
                positive(batch["controller_cpu_seconds"],"invalid native CPU")
                need(batch["sampled_tree_cpu_seconds_delta_is_performance_numerator"] is False,"wrong native CPU numerator")
                need("same-PID/start-ticks" in batch["controller_cpu_source"],"native CPU identity scope differs")
                need(equal_number(batch["completion_rps"],expected/batch["seconds"]) and equal_number(batch["successful_rps"],expected/batch["seconds"]),"native cell rate differs")
                need(equal_number(batch["controller_cpu_ms_per_call"],batch["controller_cpu_seconds"]*1000/expected),"native cell CPU rate differs")
                check_distribution(batch,[v["elapsed_ms"] for v in rows],native=True)
                for row in rows: row_check(row)
                mix=collections.Counter((v["host"],v["tool"]) for v in rows)
                need(mix=={(h,t):expected//12 for h in HOSTS for t in TOOLS},"native balanced host/tool mix differs")
                if label=="measured":
                    measured+=len(rows)
                    if measured_mix is None: measured_mix=mix
                    need(mix==measured_mix,"native measured host/tool mix differs")
                else:
                    warmup+=len(rows)
                    if warmup_mix is None: warmup_mix=mix
                    need(mix==warmup_mix,"native warmup host/tool mix differs")
                all_rows.extend(rows)
            groups[(round_["version"],cell["concurrency"])].append(cell)
        for name in ("shutdown","restart_shutdown"):
            shutdown=round_[name]
            need(shutdown["exit_code"]==0 and shutdown["reader_error"] is None and shutdown["unmatched_responses"]==0 and shutdown["observed_descendant_survivors"]==[] and shutdown["shutdown_method"]=="stdin_eof","native shutdown not clean")
            usage=shutdown["resources"]
            if usage["error_counts"]: metric_errors.append({"round":index,"phase":name,"error_counts":usage["error_counts"],"errors":usage["errors"]})
            need(usage["sampled_tree_cpu_is_partial_lifetime_accumulation"] is True and usage["tree_samples_are_not_simultaneous_or_complete"] is True and usage["zero_without_metric_samples_is_unavailable"] is True,"native resource scope differs")
            if name=="restart_shutdown":
                rhwm=usage["peaks"].get("controller_hwm_kib") if usage["metric_samples"].get("controller_hwm_kib",0)>0 else None
                rrss=usage["peaks"].get("controller_rss_kib") if usage["metric_samples"].get("controller_rss_kib",0)>0 else None
                positive(rhwm,"unavailable native restart HWM")
                positive(rrss,"unavailable native restart RSS")
                restart_resources[round_["version"]].append({"round":index,"controller_vmhwm_kib":rhwm,"sampled_controller_rss_peak_kib":rrss,
                    "metric_samples":usage["metric_samples"],"errors":usage["error_counts"],"all_peaks":usage["peaks"]})
        usage=round_["shutdown"]["resources"]
        hwm=usage["peaks"].get("controller_hwm_kib") if usage["metric_samples"].get("controller_hwm_kib",0)>0 else None
        rss=usage["peaks"].get("controller_rss_kib") if usage["metric_samples"].get("controller_rss_kib",0)>0 else None
        resources[round_["version"]].append({"round":index,"controller_vmhwm_kib":hwm,"sampled_controller_rss_peak_kib":rss,"metric_samples":usage["metric_samples"],"errors":usage["error_counts"],"all_peaks":usage["peaks"]})
    need((measured,warmup,checks)==(1152,288,72) and len(all_rows)==1512,"native total call counts differ")
    cells=[]
    for concurrency in (1,4,8):
        arms={}
        for arm in "AB":
            samples=groups[(arm,concurrency)]
            need(len(samples)==2,"native arm sample count differs")
            rows=[v for s in samples for v in s["rows"]]
            calls=len(rows)
            cpu=sum(s["controller_cpu_seconds"] for s in samples)
            wall=sum(s["seconds"] for s in samples)
            need(calls==192,"native pooled denominator differs")
            values=[v["elapsed_ms"] for v in rows]
            rates=[s["calls"]/s["seconds"] for s in samples]
            arms[arm]={"calls":calls,"cpu_seconds":cpu,"wall_seconds":wall,"cpu_ms_per_call":cpu*1000/calls,"calls_per_second":calls/wall,
                "p50_ms":percentile(values,.5),"p95_ms":percentile(values,.95),"p99_ms":percentile(values,.99),"max_ms":max(values),
                "per_process_wall_seconds":[s["seconds"] for s in samples],"per_process_cpu_seconds":[s["controller_cpu_seconds"] for s in samples],
                "per_process_calls_per_second":rates,
                "per_process_cpu_ms_per_call":[s["controller_cpu_seconds"]*1000/s["calls"] for s in samples],
                "per_process_p95_ms":[percentile([v["elapsed_ms"] for v in x["rows"]],.95) for x in samples],
                "per_process_p99_ms":[percentile([v["elapsed_ms"] for v in x["rows"]],.99) for x in samples],
                "round_rate_max_min_spread_percent":100*(max(rates)/min(rates)-1)}
        cells.append({"concurrency":concurrency,"arms":arms,"comparison":comparison(arms["A"],arms["B"],["cpu_ms_per_call","calls_per_second","p50_ms","p95_ms","p99_ms","max_ms"])})
    for arm,samples in resources.items():
        for s in samples:
            positive(s["controller_vmhwm_kib"],"unavailable native HWM")
            positive(s["sampled_controller_rss_peak_kib"],"unavailable native RSS")
    memory={arm:{"samples":samples,"controller_vmhwm_kib_median":statistics.median(s["controller_vmhwm_kib"] for s in samples),"sampled_rss_peak_kib_median":statistics.median(s["sampled_controller_rss_peak_kib"] for s in samples)} for arm,samples in resources.items()}
    restart_memory={arm:{"samples":samples,"controller_vmhwm_kib_median":statistics.median(s["controller_vmhwm_kib"] for s in samples),
        "sampled_rss_peak_kib_median":statistics.median(s["sampled_controller_rss_peak_kib"] for s in samples)} for arm,samples in restart_resources.items()}
    return {"allocator_environment_verification":environment_proof,"report_sha256":INPUTS[str(base/"report.json")],"baseline_sha256":baseline,"candidate_sha256":CANDIDATE,"measured_calls":1152,"warmup_calls_excluded":288,"verification_calls_excluded":72,"total_native_calls":1512,"automatic_retries":0,"cells":cells,"whole_controller_memory":memory,"restart_controller_memory":restart_memory,
    "whole_controller_memory_comparison":comparison(memory["A"],memory["B"],["controller_vmhwm_kib_median","sampled_rss_peak_kib_median"]),
    "restart_controller_memory_comparison":comparison(restart_memory["A"],restart_memory["B"],["controller_vmhwm_kib_median","sampled_rss_peak_kib_median"]),
    "resource_metric_errors_preserved":metric_errors,
    "native_transport_envelopes_independently_rehashed":0,
    "hash_only_native_rows_validated":len(all_rows),
    "native_response_proof_scope":"Rows carry reply/DTO hashes and successful validation flags, not JSON-RPC bodies. This audit validates their format, identity/matrix, complete-output bindings, and recomputes metrics; it does not claim independently recomputed native transport-envelope hashes.",
    "memory_scope":"Main controller across initial checks, all C levels and warmup; sampled kernel VmHWM and sampled VmRSS peaks are not per-C or per-call allocations. FD permission errors remain visible and do not invalidate separately available CPU/RSS."}



def write_json_new(path,value):
    finite(value)
    raw=(json.dumps(value,indent=2,sort_keys=True,allow_nan=False)+"\n").encode()
    with Path(path).open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    need(Path(path).read_bytes()==raw,"output readback differs")
    return {"path":str(path),"sha256":digest(raw),"bytes":len(raw)}

def perform(expected_remote_sha):
    gate_proof=gates(expected_remote_sha)
    campaigns={
        "cancel_r14_r15":cancellation("cancel-r14-r15-01",CANDIDATE),
        "cancel_r11_r15":cancellation("cancel-r11-r15-01",R11),
        "native_r14_r15":native("native-r14-r15-01",CANDIDATE),
        "native_r11_r15":native("native-r11-r15-01",R11)}
    need(len(SEEN_CONTROLLERS)==48,"expected 48 unique live controller generations across four campaigns")
    need(sum(campaigns[k]["all_reply_hashes_and_semantics_verified"] for k in ("cancel_r14_r15","cancel_r11_r15"))==7488,"cancel reply proof total differs")
    need(sum(campaigns[k]["total_native_calls"] for k in ("native_r14_r15","native_r11_r15"))==3024,"native call total differs")
    negatives=negative_results(campaigns)
    method={"cpu_and_rate":"Sum measured CPU or call numerators and divide by all measured calls or summed wall durations; no median-rate substitution.",
        "percentiles":"Nearest-rank ceil(p*N) on pooled raw measured latencies within one arm/case/tool. Never average per-process percentiles.",
        "memory":"Keep both fresh-process values and their arithmetic median; preserve first-controller versus restarted-controller scope.",
        "all_raw_floats_finite":True,"existing_analysis_summaries_used_for_metrics":False,
        "cross_campaign_pooling":False,"independent_clock_endpoint_recreation_claimed":False,
        "negative_direction_is_not_statistical_significance":True}
    at=datetime.datetime.now(datetime.timezone.utc).isoformat()
    script_sha=sha(__file__)
    result={"schema":"hepta-x230-r15-independent-performance-audit/v1","success":True,"audited_utc":at,
        "auditor_sha256":script_sha,"reused_r14_auditor_sha256":REUSED_R14_AUDITOR_SHA,
        "candidate_sha256":CANDIDATE,"candidate_allocator_environment":EXPECTED_ALLOCATOR,
        "projection_repeated":False,"gate_proof":gate_proof,"method":method,
        "comparison_scope":{"r14_r15":"Same qualified executable, clean-default versus arena1; finite controlled configuration comparison.",
                            "r11_r15":"R11 clean-default versus R14+arena1; combined source plus execution-profile result."},
        "campaigns":campaigns,"negative_directional_results":negatives,
        "proof_totals":{"unique_live_controller_generations":48,"cancel_full_response_hashes_and_semantics":7488,
                        "native_hash_only_calls":3024,"native_full_transport_envelopes_rehashed":0},
        "qualification_scope":"Configuration qualification gate is hash-bound here. A separate independent qualification audit owns complete test identity and libtest verification.",
        "limitations":["Two fresh processes per arm/case do not establish statistical significance.",
          "Native observation stores hashes/validated DTO properties without complete transport bodies; no envelope rehash is claimed.",
          "Host-list p99 has only 48 pooled samples per arm/case and is their maximum.",
          "Native p99 has 192 pooled samples per arm/C and is rank191.",
          "Whole-child HWM includes initialization and warmup; sampled native memory spans all C levels and is not per-C allocation.",
          "Native tree RSS/FD sums are nonsimultaneous; sampled tree CPU is partial and is not the performance numerator.",
          "Recorded CPU/wall and latency deltas are checked and aggregated, not reconstructed from absent original clock endpoints.",
          "No absolute optimum or causal lock-level contention claim follows from these finite results.",
          "All negative directional cases and resource metric errors remain in the evidence."]}
    # Recheck every input, including both small qualified runtime artifacts.
    # Retained libtest binaries are deliberately not reread by this auditor.
    for path,expected in list(INPUTS.items()):
        need(sha(path)==expected,"input changed during independent audit: "+path)
    need(sha(__file__)==script_sha,"performance auditor changed during execution")
    result["input_sha256"]=dict(INPUTS)
    data={"schema":"hepta-x230-r15-performance-report-data/v1","success":True,"generated_utc":at,
        "auditor_sha256":script_sha,"candidate_sha256":CANDIDATE,"candidate_allocator_environment":EXPECTED_ALLOCATOR,
        "gate_proof":gate_proof,"method":method,"comparison_scope":result["comparison_scope"],
        "proof_totals":result["proof_totals"],"negative_directional_results":negatives,
        "limitations":result["limitations"],**{name:flat_campaign(value) for name,value in campaigns.items()}}
    # The audit success file is written last and binds the complete report data.
    data_receipt=write_json_new(ROOT/"performance-report-data.json",data)
    result["performance_report_data"]=data_receipt
    audit_receipt=write_json_new(ROOT/"independent-performance-audit.json",result)
    return {"success":True,"audit":audit_receipt,"report_data":data_receipt,
            "proof_totals":result["proof_totals"],"negative_directional_result_count":len(negatives)}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit",action="store_true",help="One-shot audit only after root confirms every campaign has completed.")
    parser.add_argument("--expected-remote-report-sha256",default="")
    parser.add_argument("--attempt-name",default="performance-attempt-01")
    args=parser.parse_args()
    if not args.audit:
        print(json.dumps({"operation":"describe-only","workloads_started":0,"new_compilation":False,
            "raw_reports":[str(ROOT/name) for name in RAW_REPORTS],
            "required_completed_gates":["configuration-qualification-01","local-campaigns-01","remote-campaigns-01"],
            "required_option":"--audit --expected-remote-report-sha256 <completed remote report SHA>",
            "outputs":["independent-performance-audit.json","performance-report-data.json"],
            "no_waits_or_retries":True}))
        return 0
    need(re.fullmatch("[0-9a-f]{64}",args.expected_remote_report_sha256) is not None,"explicit completed remote report SHA required")
    need(re.fullmatch("performance-attempt-[0-9]{2}",args.attempt_name) is not None,"invalid attempt directory name")
    for name in ("independent-performance-audit.json","performance-report-data.json"):
        need(not (ROOT/name).exists(),"existing final audit/data must never be overwritten")
    attempt=ROOT/"independent-audit-tools"/args.attempt_name
    attempt.mkdir(mode=0o700,exist_ok=False)
    status={"schema":"hepta-r15-performance-audit-attempt/v1","success":False,"started_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "auditor_sha256":sha(__file__),"expected_remote_report_sha256":args.expected_remote_report_sha256,
            "automatic_retries":0,"workloads_started":0,"compilation_started":False}
    try:
        result=perform(args.expected_remote_report_sha256)
        status.update(result)
    except BaseException as error:
        status["error"]={"type":type(error).__name__,"reason":str(error),"traceback":traceback.format_exc()}
        print(json.dumps({"success":False,"error":status["error"]}),file=sys.stderr,flush=True)
        return_code=1
    else:
        print(json.dumps(result,allow_nan=False),flush=True)
        return_code=0
    finally:
        status["finished_utc"]=datetime.datetime.now(datetime.timezone.utc).isoformat()
        status["observed_input_sha256"]=dict(INPUTS)
        write_json_new(attempt/"execution.json",status)
    return return_code

if __name__=="__main__":
    raise SystemExit(main())
