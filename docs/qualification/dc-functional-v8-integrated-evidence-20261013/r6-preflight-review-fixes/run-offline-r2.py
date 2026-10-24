#!/usr/bin/env python3
import ast,hashlib,importlib.util,json,pathlib,subprocess,sys,time
root=pathlib.Path("/home/qian-qi/hepta-runtime-dc-functional-20261013")
out=root/"docs/qualification/dc-functional-v8-integrated-evidence-20261013/r6-preflight-review-fixes/r2-rechecked"
files=("deploy/preflight_dc_successor.py","tests/dc_successor_preflight_tests.py","deploy/stage_dc_successor.py","tests/dc_successor_stage_tests.py")
before={rel:hashlib.sha256((root/rel).read_bytes()).hexdigest() for rel in files}
for rel in files:ast.parse((root/rel).read_bytes(),filename=rel)
checks=[]
for name,path,expected in (("stage-25-tests","tests/dc_successor_stage_tests.py",25),("preflight-46-tests","tests/dc_successor_preflight_tests.py",46)):
    started=time.monotonic()
    with (out/(name+".log")).open("xb") as log:
        run=subprocess.run([sys.executable,path],cwd=root,env={**__import__("os").environ,"PYTHONDONTWRITEBYTECODE":"1"},stdout=log,stderr=subprocess.STDOUT,timeout=90)
    (out/(name+".exit")).write_text(str(run.returncode)+"\n")
    text=(out/(name+".log")).read_text()
    checks.append({"name":name,"exit_code":run.returncode,"expected_tests":expected,"observed_expected_summary":("Ran "+str(expected)+" tests") in text,"seconds":round(time.monotonic()-started,3),"log_sha256":hashlib.sha256((out/(name+".log")).read_bytes()).hexdigest()})
    if run.returncode:break
negative = """
import importlib.util,pathlib,sys,unittest
root=pathlib.Path("/home/qian-qi/hepta-runtime-dc-functional-20261013")
out=root/"docs/qualification/dc-functional-v8-integrated-evidence-20261013/r6-preflight-review-fixes/r2-rechecked"
sys.path.insert(0,str(root/"deploy"))
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
oldS=load("old_review_stage",out.parent/"previous-source/deploy/stage_dc_successor.py")
oldP=load("old_review_preflight",out.parent/"previous-source/deploy/preflight_dc_successor.py")
oldP.S=oldS
stage=load("stage_review_tests",root/"tests/dc_successor_stage_tests.py");stage.S=oldS
preflight=load("preflight_review_tests",root/"tests/dc_successor_preflight_tests.py");preflight.S=oldS;preflight.P=oldP
suite=unittest.TestSuite([
 stage.SuccessorStage("test_replaced_stage_directory_is_never_removed_during_failure_cleanup"),
 preflight.SuccessorPreflight("test_replaced_publication_directory_is_never_removed_during_failure_cleanup"),
 preflight.SuccessorPreflight("test_missing_durable_registry_never_becomes_complete_empty_inventory"),
])
result=unittest.TextTestRunner(verbosity=2).run(suite)
if result.testsRun != 3 or len(result.failures) < 3 or result.errors:
 raise SystemExit("Old sources did not reproduce the three expected regression failures")
print("EXPECTED_OLD_SOURCE_FAILURES_CONFIRMED_3")
"""
with (out/"negative-old-source-regressions.log").open("xb") as log:
    negative_run=subprocess.run([sys.executable,"-c",negative],cwd=root,env={**__import__("os").environ,"PYTHONDONTWRITEBYTECODE":"1"},stdout=log,stderr=subprocess.STDOUT,timeout=90)
(out/"negative-old-source-regressions.exit").write_text(str(negative_run.returncode)+"\n")
after={rel:hashlib.sha256((root/rel).read_bytes()).hexdigest() for rel in files}
receipt={"schema":"hepta-stage-preflight-independent-review-regressions-v1","reviewed_source_sha256":after,"source_stable_during_offline_tests":before==after,"offline_checks":checks,"negative_old_source_regressions":{"exit_code":negative_run.returncode,"three_expected_failures_only":negative_run.returncode==0,"log_sha256":hashlib.sha256((out/"negative-old-source-regressions.log").read_bytes()).hexdigest()},"all_checks_pass":len(checks)==2 and all(x["exit_code"]==0 and x["observed_expected_summary"] for x in checks) and negative_run.returncode==0 and before==after,"only_owned_temporary_fixture_files_changed":True,"live_preflight_run":False,"private_production_backup_created":False,"services_restarted":False,"app_refreshed":False,"full_dc_replacement_qualified":False}
with (out/"receipt.json").open("x") as f:json.dump(receipt,f,sort_keys=True,indent=2);f.write("\n")
print(json.dumps(receipt,sort_keys=True))
raise SystemExit(0 if receipt["all_checks_pass"] else 1)
