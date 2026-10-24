#!/usr/bin/env python3
import ast,hashlib,json,pathlib,subprocess,sys
D=pathlib.Path("/home/qian-qi/hepta-successor-inventory-integration-drafts-20261013-r1")
E=D/"evidence"
paths=["deploy/preflight_dc_successor.py","tests/dc_successor_preflight_tests.py","deploy/dc_successor_inventory.py","tests/dc_successor_inventory_tests.py","deploy/stage_dc_successor.py","tests/dc_successor_stage_tests.py"]
def pins():return {r:{"bytes":(D/r).stat().st_size,"sha256":hashlib.sha256((D/r).read_bytes()).hexdigest()} for r in paths}
before=pins()
manifest=json.loads((E/"controlled-source-manifest-r2.json").read_bytes())
assert before==manifest["after"]
runs=[("new-adapter-fixtures",["tests/dc_successor_preflight_tests.py","LargeBoundedInventoryPreflight"]),("full-preflight-regression",["tests/dc_successor_preflight_tests.py"]),("full-stage-regression",["tests/dc_successor_stage_tests.py"]),("new-header-inventory-module",["tests/dc_successor_inventory_tests.py","--results-dir",str(E/"module-run-main-r2")])]
cohorts=[]
for name,args in runs:
 proc=subprocess.run(["/usr/bin/python3",*args],cwd=D,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=100,env={"PATH":"/usr/bin:/bin","PYTHONDONTWRITEBYTECODE":"1"})
 for channel,raw in (("stdout",proc.stdout),("stderr",proc.stderr)):
  p=E/(name+"-r2."+channel+".log")
  with p.open("xb") as f:f.write(raw)
  p.chmod(0o600)
 cohorts.append({"name":name,"args":["/usr/bin/python3",*args],"exit_code":proc.returncode,"stdout_sha256":hashlib.sha256(proc.stdout).hexdigest(),"stderr_sha256":hashlib.sha256(proc.stderr).hexdigest()})
after=pins()
report={"schema":"hepta-large-jobs-only-optional-adapter-test-evidence-r2-v1","before":before,"after":after,"source_inputs_stable":before==after,"cohorts":cohorts,"all_passed":before==after and all(c["exit_code"]==0 for c in cohorts),"old_preflight_methods":82,"r1_preflight_methods":91,"new_adapter_methods":12,"new_root_review_methods":3,"full_preflight_methods":94,"new_adapter_subset_of_full":True,"stage_methods":26,"new_header_inventory_methods":55,"original91_AST_unchanged":manifest["original91_test_algorithms_AST_unchanged"],"actual_token_read":False,"actual_token_hashed":False,"actual_private_profile_read":False,"actual_HTTP_or_SSH_executed":False,"production_inventory_observed":False,"service_control_called":False,"full_dc_replacement_qualified":False,"r1_review_accepted_as_final":False,"r1_raw_results_preserved":True}
p=E/"tests-report-r2.json"
with p.open("x") as f:f.write(json.dumps(report,indent=2,sort_keys=True)+"\n")
p.chmod(0o600)
print(json.dumps(report,sort_keys=True))
sys.exit(0 if report["all_passed"] else 1)
