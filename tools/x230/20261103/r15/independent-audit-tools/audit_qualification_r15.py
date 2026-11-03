#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Independently audit reused R14 artifacts and all R15 arena1 isolated tests; never execute Rust."""
import collections,importlib.util,json
from pathlib import Path
import r15_configuration_recovery_common as c
ROOT,QUAL,SOURCE=c.ROOT,c.QUAL,c.SOURCE
REFERENCE=ROOT/"independent-audit-tools/qualification-recovery-reference"
STRICT_SHA="736b2dcc85fbd5214b855813b6c1f0ceed3dedc1cc0957e709a9ee6cb0110c40"

def rows(path):
 c.bind(path)
 result=[json.loads(line) for line in Path(path).read_text().splitlines() if line]
 c.finite(result);return result

def main():
 configuration,local,remote=c.all_measurements_finished()
 baseline=c.load(ROOT/"baseline-binding.json")
 q=c.load(QUAL/"report.json",baseline["qualification_sha256"])
 frozen=c.load(c.R14/"implementation-ready.json",baseline["implementation_ready_sha256"])
 prior_audit=c.load(c.R14/"qualification-audit-summary.json",baseline["qualification_audit_sha256"])
 c.need(q.get("qualified") is True and q.get("finished_utc") and not q.get("error") and q["automatic_test_retries"]==0 and q["service_changes"] is False,"R14 qualification not valid")
 c.need([r["name"] for r in q["stages"]]==["format","fmt-check","harness-tests","clippy","test-build","isolated-tests","audit-isolated-tests","release"] and all(r["returncode"]==0 for r in q["stages"]),"R14 required qualification stages differ")
 current=c.source_map()
 c.need(len(current)==219 and current==q["source_tested"]==q["source_after"]==frozen["source_after"],"219 frozen/tested/post/current source map differs")
 c.need(current["src/mcp/runtime/jobs.rs"]=="694a4e4dcbc2be499879abd837f0b5e399f9cad95caab34716907de15cbbe82f","frozen pool implementation differs")
 manifest=c.load(QUAL/"source-map.json",prior_audit["source_map_sha256"])
 c.need(manifest==current,"R14 retained source manifest differs")
 c.bind(QUAL/"retained-artifacts.jsonl",baseline["retained_artifacts_sha256"])
 release={}
 c.need(set(q["binaries"])=={"hepta-runtime","hepta-runtime-jobctl","native_process_driver"},"release binary set differs")
 for name,item in q["binaries"].items():
  c.need(item["path"]==str(QUAL/name) and baseline["release_binaries"][name]=={"path":item["path"],"sha256":item["sha256"]},"release artifact qualification binding differs")
  actual=c.bind(item["path"],item["sha256"])
  release[name]={"path":item["path"],"sha256":actual,"size":Path(item["path"]).stat().st_size}
 c.need(release["hepta-runtime"]["sha256"]==c.RUNTIME_SHA,"runtime is not qualified R14")
 evidence=c.CONFIG_QUAL/"isolated-tests"
 summary=c.load(evidence/"summary.json",configuration["summary"]["sha256"])
 prior_summary=c.load(QUAL/"isolated-tests/summary.json",prior_audit["isolated_summary_sha256"])
 c.need(summary["binaries"]==prior_summary["binaries"] and summary["artifacts_sha256"]==prior_summary["artifacts_sha256"]==baseline["retained_artifacts_sha256"] and summary["source_manifest_sha256"]==prior_summary["source_manifest_sha256"]==prior_audit["source_map_sha256"],"R15 executable/source inventory differs from R14")
 c.selected_configuration(summary["allocator_configuration"],None)
 strict_path=REFERENCE/"audit_isolated_tests.py"
 c.bind(strict_path,STRICT_SHA)
 spec=importlib.util.spec_from_file_location("r14_independent_isolated_oracle",strict_path)
 strict=importlib.util.module_from_spec(spec);spec.loader.exec_module(strict)
 detail={"schema":"hepta-r15-retained-isolated-independent-detail/v1","success":False,"started_utc":c.now(),"errors":[],"binaries":[],"commands":[],"strict_auditor_sha256":STRICT_SHA}
 detail_path=ROOT/"independent-audit-tools/isolated-independent-detail-01.json"
 try:
  strict.audit(evidence,"",detail)
  c.need(not detail["errors"],"independent exact-case/stdout audit failed")
  detail["success"]=True
 except BaseException as error:
  detail["error"]={"type":type(error).__name__,"reason":str(error)}
  raise
 finally:
  detail["finished_utc"]=c.now();c.write_json(detail_path,detail)
 c.bind(detail_path)
 new_rows=rows(evidence/"tests.jsonl")
 prior_rows=rows(QUAL/"isolated-tests/tests.jsonl")
 c.need(c.INPUTS[str(QUAL/"isolated-tests/tests.jsonl")]==prior_audit["raw_tests_jsonl_sha256"],"R14 raw test source changed")
 inventory={item["path"]:item for item in summary["binaries"]}
 def identities(values):
  result={}
  for row in values:
   key=(row["binary"],row["name"])
   c.need(key not in result,"duplicate test identity")
   result[key]=row["status"]
  return result
 c.need(identities(new_rows)==identities(prior_rows),"R15 changed R14 raw test identities or statuses")
 counts=dict(collections.Counter(row["status"] for row in new_rows))
 expected={"passed":1637,"failed":0,"ignored":33,"selected":1670,"retries":0}
 observed={"passed":counts.get("passed",0),"failed":counts.get("failed",0),"ignored":counts.get("ignored",0),"selected":len(new_rows),"retries":summary["retries"]}
 c.need(observed==expected and {k:summary[k] for k in expected}==expected and {k:detail[k] for k in expected if k!="retries"}=={k:v for k,v in expected.items() if k!="retries"},"independent complete test counts differ")
 commands=rows(evidence/"commands.jsonl")
 command_by_stdout={row["stdout_gzip"]:row for row in commands}
 c.need(len(command_by_stdout)==len(commands)==1637+2*len(inventory),"exact commands/enumeration count differs")
 environment_counts=dict(collections.Counter(c.command_environment(row) for row in commands))
 environment_counts={key:environment_counts.get(key,0) for key in ("verified","unavailable_process_exited")}
 c.need(environment_counts==summary["allocator_observation_counts"]==configuration["allocator_observation_counts"] and environment_counts["verified"]>0,"actual environment proof counts differ")
 for row in new_rows:
  if row["status"]=="ignored":
   c.need(row["executed"] is False and row["attempt"]==0,"ignored test executed")
   continue
  c.need(row["attempt"]==1 and row["executed"] is True and row["binary_sha256"]==inventory[row["binary"]]["sha256"],"test execution/binary binding differs")
  command=command_by_stdout[row["stdout_gzip"]]
  for field in ("allocator_environment","allocator_environment_sha256","allocator_observation"):
   c.need(row[field]==command[field],"test row/command allocator proof differs")
 retained=[]
 for item in summary["binaries"]:
  c.need(Path(item["path"]).parent==QUAL/"test-binaries","test binary is not retained R14 copy")
  retained.append({"path":item["path"],"sha256":c.bind(item["path"],item["sha256"]),"size":Path(item["path"]).stat().st_size,
   "target":item["target"],"derived_binary_configuration_fingerprint":c.json_digest({"binary_sha256":item["sha256"],"allocator_environment":c.CANDIDATE_ENV})})
 libs=[r for r in retained if r["target"]["name"]=="hepta_runtime" and r["target"]["kind"]==["lib"]]
 c.need(len(libs)==1 and libs[0]["sha256"]==prior_audit["retained_libtest"]["sha256"],"retained main libtest binding differs")
 required=prior_audit["tests"]["required_pool_tests_passed"]
 for name in required:c.need(any(row["name"]==name and row["status"]=="passed" for row in new_rows),"pool continuation test missing")
 c.need(c.source_map()==current,"R14 source changed during independent audit")
 c.inputs_unchanged()
 result={"schema":"hepta-x230-r15-independent-configuration-qualification-audit/v1","success":True,"audited_utc":c.now(),
  "auditor_sha256":c.sha_file(__file__),"common_auditor_sha256":c.sha_file(Path(c.__file__).resolve()),"strict_isolated_auditor_sha256":STRICT_SHA,
  "reused_r14_qualification_auditor_sha256":"6b36650fa00d64385a7623c503e29f0ce8453938899f0d1b9e4930c0c1771af0",
  "qualification_report_sha256":c.INPUTS[str(c.CONFIG_QUAL/"report.json")],"reused_r14_qualification_report_sha256":baseline["qualification_sha256"],
  "isolated_summary_sha256":c.INPUTS[str(evidence/"summary.json")],"raw_tests_jsonl_sha256":c.INPUTS[str(evidence/"tests.jsonl")],
  "raw_commands_jsonl_sha256":c.INPUTS[str(evidence/"commands.jsonl")],"source_map_sha256":prior_audit["source_map_sha256"],
  "source_input_count":219,"source_tested_after_current_equal":True,"source_matches_frozen_implementation":True,
  "rust_source_modified":False,"compiler_invocations":0,"jobs_rs_sha256":current["src/mcp/runtime/jobs.rs"],
  "tests":{**observed,"raw_status_counts":counts,"unique_test_identities":len(new_rows),"executed_binary_bindings_matched":True,
   "r14_identity_and_status_inventory_unchanged":True,"strict_stdout_and_inventory_audit_passed":True,
   "required_pool_tests_passed":required},
  "allocator_environment":c.CANDIDATE_ENV,"allocator_configuration":summary["allocator_configuration"],
  "allocator_observation_counts":environment_counts,"configuration_ready_sha256":c.PINS["configuration/configuration-ready.json"],
  "release_binaries":release,"retained_test_binaries":retained,
  "retained_libtest":{k:libs[0][k] for k in ("path","sha256","size")},
  "strict_independent_detail":{"path":str(detail_path),"sha256":c.INPUTS[str(detail_path)]},
  "input_sha256":dict(c.INPUTS),
  "limitations":["Multi-binary isolated top-level configuration has binary_sha256=null; executable SHA is independently checked per inventory and exact test command.",
   "Unavailable short-child snapshots, if any, are reported separately and never counted as live /proc proof or retried.",
   "R14 build qualification is reused. R15 directly executes retained artifacts; no new compilation is performed."],
  "scope":"All formal pipelines completed before hashing. 219 frozen source files, three release artifacts, five retained test executables, all exact-case compressed logs and explicit/live allocator evidence independently rechecked."}
 out=ROOT/"qualification-audit-summary.json";c.write_json(out,result)
 print(json.dumps({"success":True,"path":str(out),"sha256":c.sha_file(out),"runtime_sha256":c.RUNTIME_SHA,
                   "tests":observed,"allocator_observation_counts":environment_counts}),flush=True)

if __name__=="__main__":main()
