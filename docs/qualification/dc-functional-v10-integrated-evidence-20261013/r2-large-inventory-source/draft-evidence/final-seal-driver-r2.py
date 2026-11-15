#!/usr/bin/env python3
import ast,difflib,hashlib,json,os,pathlib,stat
D=pathlib.Path("/home/qian-qi/hepta-successor-inventory-integration-drafts-20261013-r1")
E=D/"evidence"
M=pathlib.Path("/home/qian-qi/hepta-successor-inventory-drafts-20261013-r1")
R=pathlib.Path("/home/qian-qi/hepta-runtime-dc-functional-20261013")
def sha(raw):return hashlib.sha256(raw).hexdigest()
def create(rel,raw):
 p=E/rel;p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
 with p.open("xb") as f:f.write(raw)
 p.chmod(0o600)
report_raw=(E/"tests-report-r2.json").read_bytes()
assert sha(report_raw)=="014e9918e0887a92c35240020ba04e6bafb895812076d9414b01c216152d1669"
report=json.loads(report_raw)
assert report["all_passed"] and report["source_inputs_stable"]
for r,pin in report["after"].items():assert sha((D/r).read_bytes())==pin["sha256"]
peer_raw=(E/"independent-review-r2-final.json").read_bytes()
assert sha(peer_raw)=="04f76774e766ac157b442c69e572c41a21586c400af2e59821b30e67ff0c55c9"
peer=json.loads(peer_raw);assert peer["outcome"]["blocking_findings"]==0 and peer["outcome"]["unresolved_findings"]==0
assert peer["scope"]["adapter_source_sha256"]==report["after"]["deploy/preflight_dc_successor.py"]["sha256"]
assert peer["scope"]["adapter_tests_sha256"]==report["after"]["tests/dc_successor_preflight_tests.py"]["sha256"]
assert peer["supersession"]["R1_accepted_as_final"] is False
assert sha((M/"manifest.json").read_bytes())=="c7472894422e0532b43e5a0614083ddc328969e5feb89053c38ed632169ff70e"
assert sha((M/"required-pin-r3/README.md").read_bytes())=="0a4e471498fc029ef999c2ecb028e26f92283bd2859105c065d2ebf9adceef17"
history=["manifest.json","required-pin-r3/README.md","required-pin-r3/deploy/dc_successor_inventory.py","required-pin-r3/tests/dc_successor_inventory_tests.py","results/review-0c262c-rejection.json","results/source-0c262c-baseline.py","results/tests-df169a-baseline.py","results/source-9e0234-baseline.py","results/source-f6e699-baseline.py","results/tests-8579bf-baseline.py","results/source-eda528-baseline.py","results/tests-f60a83-baseline.py","results/source-5acd24-baseline.py","results/tests-c6b5c6-baseline.py","results/source-9d519c-failed-run009.py","results/tests-7903f3-failed-run009.py"]
for run in ["results/run-001","results/run-002","results/run-main-003","results/run-004","results/run-005","results/run-009","required-pin-r2/results/run-main-007","required-pin-r3/results/run-local-010","required-pin-r3/results/run-main-011"]:
 for name in ["raw_unittest.txt","summary.json"]:history.append(run+"/"+name)
history_pins={}
for rel in history:
 p=M/rel;info=p.lstat()
 assert stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and info.st_nlink==1
 raw=p.read_bytes();history_pins[rel]={"bytes":len(raw),"sha256":sha(raw)}
 create("module-draft-history/"+rel,raw)
 assert sha(p.read_bytes())==history_pins[rel]["sha256"]
for path,pin in [("/home/qian-qi/hepta-large-inventory-adapter-draft-20261013-r1.py","d63780f8edd8288c72f26675fd26347e5178ac0b83110014dcd80262bad8d625"),("/home/qian-qi/hepta-large-inventory-adapter-root-review-fix-20261013-r2.py","165b3c9d87696b1e7850e26067777ecf0f75a53fc5949ed0c0608d207ccf1bb3"),("/home/qian-qi/hepta-large-inventory-adapter-test-20261013-r2.py","e1901a2f9b5499aabb218da347d5817d09e999aae8613616732bfc7194b27483")]:
 raw=pathlib.Path(path).read_bytes();assert sha(raw)==pin
 create("creation-drivers/"+pathlib.Path(path).name,raw)
def methods(raw):
 return {c.name+"."+n.name:ast.dump(n,include_attributes=False) for c in ast.parse(raw).body if isinstance(c,ast.ClassDef) for n in c.body if isinstance(n,ast.FunctionDef) and n.name.startswith("test_")}
old82=methods((E/"before-dc_successor_preflight_tests.py").read_bytes())
old91=methods((E/"r1-before-root-review-dc_successor_preflight_tests.py").read_bytes())
new94=methods((D/"tests/dc_successor_preflight_tests.py").read_bytes())
assert len(old82)==82 and len(old91)==91 and len(new94)==94
assert all(new94[k]==v for k,v in old82.items()) and all(new94[k]==v for k,v in old91.items())
old_source=(E/"before-preflight_dc_successor.py").read_bytes()
old_funcs={n.name:ast.dump(n,include_attributes=False) for n in ast.parse(old_source).body if isinstance(n,ast.FunctionDef)}
new_funcs={n.name:ast.dump(n,include_attributes=False) for n in ast.parse((D/"deploy/preflight_dc_successor.py").read_bytes()).body if isinstance(n,ast.FunctionDef)}
preserved=["inventory_observation","sanitized_inventory","read_private_token","refuse_token_source","read_private_profile_artifact","validate_private_profile_review","inventory_holds"]
assert all(old_funcs[n]==new_funcs[n] for n in preserved)
for rel,baseline in [("deploy/preflight_dc_successor.py","before-preflight_dc_successor.py"),("tests/dc_successor_preflight_tests.py","before-dc_successor_preflight_tests.py")]:
 old=(E/baseline).read_text();new=(D/rel).read_text()
 create("baseline977-to-final-r2-"+pathlib.Path(rel).name+".diff","".join(difflib.unified_diff(old.splitlines(True),new.splitlines(True),fromfile="977/"+rel,tofile="draft-R2/"+rel)).encode())
for rel in ["deploy/dc_successor_inventory.py","tests/dc_successor_inventory_tests.py"]:
 old=(M/"required-pin-r3"/rel).read_bytes();new=(D/rel).read_bytes()
 assert ast.dump(ast.parse(old),include_attributes=False)==ast.dump(ast.parse(new),include_attributes=False)
 create("module-header-only-"+pathlib.Path(rel).name+".diff","".join(difflib.unified_diff(old.decode().splitlines(True),new.decode().splitlines(True),fromfile="9d-38cd/"+rel,tofile="a198-3e043/"+rel)).encode())
active_baseline={}
for rel in ["deploy/preflight_dc_successor.py","tests/dc_successor_preflight_tests.py","deploy/stage_dc_successor.py","tests/dc_successor_stage_tests.py","deploy/mcp_tool_contract.py"]:
 active_baseline[rel]={"bytes":(R/rel).stat().st_size,"sha256":sha((R/rel).read_bytes())}
assert active_baseline["deploy/preflight_dc_successor.py"]["sha256"]=="e3bf754dbcf58219994af79f935f9166d9ff39534ae8b55b4d6593446c843fec"
assert active_baseline["tests/dc_successor_preflight_tests.py"]["sha256"]=="35ca6e4d3993d834ce84899a929e7605ccbaed02d8769b076d94629ce4fdfdde"
source_map={"deploy/preflight_dc_successor.py":report["after"]["deploy/preflight_dc_successor.py"],"tests/dc_successor_preflight_tests.py":report["after"]["tests/dc_successor_preflight_tests.py"],"deploy/dc_successor_inventory.py":report["after"]["deploy/dc_successor_inventory.py"],"tests/dc_successor_inventory_tests.py":report["after"]["tests/dc_successor_inventory_tests.py"]}
summary={"schema":"hepta-large-jobs-only-adapter-final-reviewable-source-v1","source_map":source_map,"active_code_baseline_still_observed":active_baseline,"active_files_modified_by_this_subagent":False,"old82_test_algorithms_AST_unchanged":True,"r1_all91_test_algorithms_AST_unchanged":True,"unchanged_existing_source_function_AST":preserved,"new_module_copyright_header_only_full_AST_equal":True,"fresh_main_execution":{"job_id":"1a137aa727a-b2f-b20","authoritative_state":"succeeded","exit_code":0,"cohorts":{"adapter_subset":12,"full_preflight":94,"stage":26,"inventory_module":55},"source_inputs_before_after_equal":True,"report_sha256":sha(report_raw),"all_cohort_exit_codes":0},"independent_R2_peer":{"sha256":sha(peer_raw),"status":peer["outcome"]["status"],"blocking_findings":0,"unresolved_findings":0,"R1_acceptance_withdrawn":True},"module_root_review":{"provenance":"root collaboration message; root independently read final9d full module and file_info before/after","reviewed_original_source_sha256":"9d519c400e3ecea186e0151a33ea631dc3388c38979dcf6f14faee461ac9a22f","reported_P0_P1_findings":0,"header_adjusted_source_AST_unchanged":True,"borrowed_actual_qualification":False},"history_pins":history_pins,"scope":{"default":"legacy unchanged","named_mode":"large-bounded","proof_scope":"jobs-only bounded offline fixtures","PTY_stream_dispatch_freeze_complete":False,"production_inventory_qualified":False,"full_DC_replacement_qualified":False,"actual_token_read_or_hash":False,"actual_private_profile_registry_read":False,"actual_HTTP_SSH":False,"service_control":False,"cutover_authorized":False,"commit_or_push_by_subagent":False},"preserved_incidents":["module0c rejected High despite passing36 offline tests","module run009 raw fixture failure and exact inputs retained","adapterR1fc7b High token alias before hashing + Medium RPC clipping rejection retained","R1 adapter independent acceptance withdrawn; R2 acceptance freshly derived","large module write errors and unknown staging remnants retained in original module manifest"],"remaining":{"production_endpoint_status_budget":"root coordinated future collection; no actual proof borrowed","PTY_stream_dispatch_freeze":"unobserved incomplete HOLD","private_profile_administrator_review":"independent required HOLD","recovery_rollback_business":"independent required HOLD"}}
create("final-reviewable-source-manifest.json",(json.dumps(summary,indent=2,sort_keys=True)+"\n").encode())
index={"schema":"hepta-large-jobs-only-adapter-evidence-index-v1","artifact_root":str(E),"files":{},"full_DC_replacement_qualified":False,"actual_private_values_published":False}
for p in sorted(E.rglob("*")):
 if p.is_file() and "__pycache__" not in p.parts and p.suffix!=".pyc":
  raw=p.read_bytes();index["files"][str(p.relative_to(E))]={"bytes":len(raw),"sha256":sha(raw)}
create("artifact-index.json",(json.dumps(index,indent=2,sort_keys=True)+"\n").encode())
print(json.dumps({"source_map":source_map,"final_manifest_sha256":sha((E/"final-reviewable-source-manifest.json").read_bytes()),"artifact_index_sha256":sha((E/"artifact-index.json").read_bytes()),"artifact_files":len(index["files"]),"actual_private_access":False,"production_qualification":False},sort_keys=True))
