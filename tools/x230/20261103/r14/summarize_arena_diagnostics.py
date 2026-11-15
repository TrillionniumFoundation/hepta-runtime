#!/usr/bin/env python3
"""Summarize immutable R14 allocator probes; no workload or compilation."""
import datetime, hashlib, json, math, statistics
from pathlib import Path
R = Path("/home/qian/hepta-runtime-optimization-20261103-r14")
INPUTS = [
 ("01","1395c0e75c4c53e10386d7865e3e2f45c7f44bab184d7dffeb9e461dfb600937",["default","arena2","arena2","default"]),
 ("02","20a37ece2406a3aaeb0819bb4ecd2c0d4cdb2fcdafc785a4687077ebbe184889",["arena1","arena4","arena4","arena1"])]
def sha(b): return hashlib.sha256(b).hexdigest()
def main():
 out=R/"diagnostic-summary.json"
 if out.exists(): raise FileExistsError("never overwrite an existing summary")
 rows=[]; inputs=[]; replies_checked=0; smaps_checked=0
 for number,digest,order in INPUTS:
  p=R/("thread-arena-diagnostic-"+number)/"report.json"; b=p.read_bytes()
  assert sha(b)==digest
  d=json.loads(b)
  assert d["success"] is True and d["finished_utc"] and d["order"]==order
  assert d["automatic_retries"]==0 and d["compile_or_source_changes"] is False
  assert d["qualified_runtime"]["sha256"]=="51480b3cf630a95419d3afeb571eec17c90cffa5944101920d05333673de031d"
  assert (d["workers"],d["concurrency"],d["warmup_waves"],d["load_waves"],d["idle_seconds"],d["clock_ticks_per_second"])==(2,8,2,24,12,100)
  assert len(d["cases"])==4
  inputs.append({"path":str(p),"bytes":len(b),"sha256":digest,"script_sha256":d["diagnostic_script_sha256"]})
  for i,c in enumerate(d["cases"]):
   assert c["position"]==i and c["arm"]==order[i]
   assert all(c[k] is True for k in ("success","receipt_unchanged","no_operation_cancel_intent","no_ssh_dispatch"))
   assert c["shutdown"]=={"exit_code":0,"method":"stdin_eof","reader_error":None,"unmatched":0}
   assert len(c["warmup_replies"])==18 and len(c["load_replies"])==216
   replies=c["warmup_replies"]+c["load_replies"]
   assert sorted(x["rpc_id"] for x in replies)==list(range(2,236))
   counts={"process_cancel":0,"host_list":0}
   for reply in replies:
    encoded=(json.dumps(reply["response"],sort_keys=True,separators=(",",":"))+"\n").encode()
    assert sha(encoded)==reply["response_sha256"]
    assert reply["expected_result"] is True and math.isfinite(reply["elapsed_ms"]) and reply["elapsed_ms"]>=0
    name=reply["params"]["name"]; counts[name]+=1; result=reply["response"]["result"]
    assert result["isError"] is (name=="process_cancel")
    if name=="process_cancel":
     expected="job "+chr(96)+"cancel-responsiveness"+chr(96)+" belongs to host "+chr(96)+"owner"+chr(96)+", not "+chr(96)+"other"+chr(96)
     assert result["content"]==[{"text":expected,"type":"text"}]
    else:
     hosts=json.loads(result["content"][0]["text"])["hosts"]
     assert {h["name"] for h in hosts}=={"owner","other"}
     assert all(h["allow_execute"] is False and h["allow_write"] is False and h["allow_pty"] is False for h in hosts)
    replies_checked+=1
   assert counts=={"process_cancel":208,"host_list":26}
   samples=c["snapshots"]
   phases=["ready"]+["warmup"]*2+["before_load"]+["load"]*24+["after_load"]+["idle_"+str(j)+"s" for j in range(1,13)]
   assert [s["phase"] for s in samples]==phases
   assert all(a["monotonic"]<b["monotonic"] and a["process_cpu_ticks"]<=b["process_cpu_ticks"] for a,b in zip(samples,samples[1:]))
   ready,loaded,idle=samples[0],samples[28],samples[-1]
   cpu=(loaded["process_cpu_ticks"]-ready["process_cpu_ticks"])/100
   assert math.isfinite(cpu) and cpu>0 and cpu==c["summary"]["process_cpu_ready_to_load_seconds"]
   for phase,sample in (("ready",ready),("after_load",loaded),("after_idle",idle)):
    assert sample["memory_kib"]==c["summary"][phase+"_memory_kib"]
   shapes=[]
   for mem in c["memory_details"]:
    path=Path(mem["raw"]); assert path.is_relative_to(p.parent) and not path.is_symlink()
    assert sha(path.read_bytes())==mem["sha256"]
    shapes.append({"phase":mem["phase"],"path":str(path),"sha256":mem["sha256"],
     "heap_rss_kib_reported":mem["heap_rss_kib"],
     "anonymous_writable_rss_kib_reported":mem["anonymous_writable_rss_kib"],
     "reservation_pair_count_reported":len(mem["reservation_like_64m_pairs"]),
     "reservation_pair_rss_kib_reported":sum(m["rss_kib"] for m in mem["reservation_like_64m_pairs"])})
    smaps_checked+=1
   assert [m["phase"] for m in shapes]==["ready","after_load","after_idle"]
   env={k:v for k,v in c["child_env"].items() if k.startswith("MALLOC_") or k=="GLIBC_TUNABLES"}
   assert env==({} if c["arm"]=="default" else {"MALLOC_ARENA_MAX":c["arm"][5:]})
   rows.append({"diagnostic":number,"position":i,"arm":c["arm"],"spawn_allocator_environment":env,
    "cpu_ready_through_warmup_and_load_seconds":cpu,"cpu_ms_per_mixed_rpc_including_warmup":cpu*1000/234,
    "rpc_count_including_warmup":counts,"after_load_rss_kib":loaded["memory_kib"]["VmRSS"],
    "after_idle_rss_kib":idle["memory_kib"]["VmRSS"],"whole_child_hwm_kib":idle["memory_kib"]["VmHWM"],
    "threads_ready_peak_loaded_idle":[ready["threads"],max(s["threads"] for s in samples),loaded["threads"],idle["threads"]],
    "smaps":shapes})
 assert replies_checked==1872 and smaps_checked==24
 fields=("cpu_ready_through_warmup_and_load_seconds","cpu_ms_per_mixed_rpc_including_warmup","after_load_rss_kib","after_idle_rss_kib","whole_child_hwm_kib")
 means={}
 for arm in ("default","arena1","arena2","arena4"):
  group=[r for r in rows if r["arm"]==arm]; assert len(group)==2
  means[arm]={"processes":2,**{k:statistics.mean(r[k] for r in group) for k in fields}}
 data={"schema":"hepta-r14-allocator-diagnostic-summary/v1","success":True,
  "created_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"analysis_script_sha256":sha(Path(__file__).read_bytes()),
  "inputs":inputs,"reply_hashes_and_results_verified":replies_checked,"smaps_hashes_verified":smaps_checked,
  "rows":rows,"descriptive_process_means":means,"selected_formal_candidate":{"MALLOC_ARENA_MAX":"1"},
  "recommendation":"Evaluate arena1 formally: lowest observed HWM, idle RSS comparable to arena2, no clear diagnostic CPU disadvantage.",
  "cpu_denominator":"Ready-to-after-load CPU includes 2 warmup plus 24 load waves: 208 cancellation refusals and 26 host_list calls. CPU/234 is mixed RPC cost, not isolated cancel CPU.",
  "memory_scope":"VmHWM is whole child since exec; VmRSS point samples after load/12s idle. smaps raw hashes verified; mapping-shape summaries retained from probe and are heuristic, not direct arena enumeration.",
  "limitations":["Two fresh processes per setting across two ordered diagnostics, with background archive/audit I/O; not a throughput benchmark.",
   "Cross-campaign CPU means are descriptive only, without strong causal attribution.",
   "One arena may cause allocator contention under other workloads; formal native C8, environment-bound ABBA, and recovery remain required.",
   "All settings still reach 19 or 20 observed threads and 10 after idle: limiting arenas does not cap threads.",
   "R14 formal throughput regressions remain valid; these diagnostics do not supersede them.",
   "No source edits, new compilation, or production configuration changes."]}
 encoded=(json.dumps(data,indent=2,sort_keys=True)+"\n").encode()
 with out.open("xb") as stream: stream.write(encoded)
 print(json.dumps({"path":str(out),"sha256":sha(encoded),"bytes":len(encoded),"means":means,"verified_replies":replies_checked,"verified_smaps":smaps_checked}))
if __name__=="__main__": main()
