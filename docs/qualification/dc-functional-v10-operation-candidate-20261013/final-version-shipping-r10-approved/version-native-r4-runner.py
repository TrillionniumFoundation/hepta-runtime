import pathlib,json,hashlib,subprocess,datetime,sys,importlib.util,os
R=pathlib.Path("/home/qian-qi/hepta-runtime-operation-v10-20261013")
D=R/"docs/qualification/dc-functional-v10-operation-candidate-20261013/versioned-regression-r4-native"
D.mkdir(mode=0o700,exist_ok=False)
def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
sys.path.insert(0,str(R/"deploy"))
assert sha(R/"deploy/stage_dc_successor.py")=="80fb34a7d55157032a5a8da007d31f289eb2862746ea16747de7b3cb305f0582"
spec=importlib.util.spec_from_file_location("v10_version_stage",R/"deploy/stage_dc_successor.py");stage=importlib.util.module_from_spec(spec);spec.loader.exec_module(stage)
before=stage.source_identity(R);assert before["source_code_fingerprint"]=="498cca6da8c442c70534b0a35807c94d7b5f7fbef4b2b4d8f15fa9c22484e33c"
manifest_path=R/"docs/qualification/dc-functional-v10-operation-candidate-20261013/versioned-regression-package/manifest.json"
assert sha(manifest_path)=="48125a5832a18508bc78ce4a7e0ec6ff9cdfdbab35159278154cdd4b730fae6f"
package=json.loads(manifest_path.read_bytes())
for name,meta in package["copy_whitelist"].items():assert sha(R/name)==meta["sha256"]
oldmap={record["original_path"]:record["original_sha256"] for record in package["copies"]};oldmap["tests/dc_successor_contract.py"]="0b039e2d667314fec32bde7827fd0f9ad01d35b8d3199e73a1e036c7b1eb3dde"
for name,pin in oldmap.items():assert sha(R/name)==pin
B=R/"target/debug/hepta-runtime";BS="40c6f3299e8ea72e37b149673245ad77ee20ab9e5886e949ce4f0d025268c4ce";assert sha(B)==BS
C=R/"deploy/contracts/hepta-runtime-full-operator-v10.json";CS="12994454084369fb31e44f0e1ceb7a7f2ace5bbed33057789399cf895e70d553";assert sha(C)==CS
FPS=before["source_code_fingerprint"]; HTTP="8b7ee206ccfc7978ac4abdf3eac3ddb8f7e7c36d053f601b5cfcb66f52fb8dba";TOOL="e2b29f987d3aaa863d7bf6879d0d6a835a807c133c5c355b6a4e69bce9c3e216";LOADER=package["new_loader_sha256"];FACADE="b35313888a70a90dc72be44dc45d3f20be45337d7c2353556a382564299d649a"
common=["--binary",str(B),"--contract",str(C),"--expected-binary-sha256",BS,"--expected-source-fingerprint",FPS]
helper=["--expected-http-helper-sha256",HTTP,"--expected-contract-helper-sha256",TOOL,"--expected-approval-loader-sha256",LOADER]
commands=[
("catalog","dc_functional_v10_catalog_acceptance.py",common+helper+["--expected-facade-sha256",FACADE,"--out",str(D/"catalog.json")]),
("request-results","dc_functional_v10_request_results_acceptance.py",common+helper+["--out",str(D/"request-results.json")]),
("request-async","dc_functional_v10_request_async_acceptance.py",common+["--expected-contract-sha256",CS,"--out",str(D/"request-async.json")]),
("legacy-native","dc_functional_v10_legacy_native_acceptance.py",["--binary",str(B),"--out",str(D/"legacy-native.json"),"--verify-contract",str(R/"deploy/contracts/hepta-runtime-full-operator-v4.json"),"--allow-v4-directory-move","--successor-contract",str(C)]),
("legacy-directory","dc_functional_v10_legacy_directory_move_acceptance.py",["--binary",str(B),"--out",str(D/"legacy-directory.json"),"--successor-contract",str(C)]),
("legacy-root-guard","dc_functional_v10_legacy_workspace_root_guard_acceptance.py",["--binary",str(B),"--out",str(D/"legacy-root-guard.json"),"--successor-contract",str(C)]),
("legacy-concurrency","dc_functional_v10_legacy_concurrent_text_acceptance.py",["--binary",str(B),"--contract",str(C),"--waves","3","--contenders","6","--out",str(D/"legacy-concurrency.json")]),
("operation","dc_functional_v10_operation_acceptance.py",common+["--expected-contract-sha256",CS,"--expected-head","50372629e0522d19b5bc4c1a800bfc311e4597f9","--previous-contract",str(R/"deploy/contracts/hepta-runtime-full-operator-v9.json"),"--expected-previous-contract-sha256","3eb628812d0c70b9af8393ecf9d0ce47f69b1438a134148f75ae2dd3132e6761","--out",str(D/"operation.json")])
]
report={"schema":"hepta-v10-versioned-native-regression-suite-v1","recorded_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"base_HEAD":"50372629e0522d19b5bc4c1a800bfc311e4597f9","source_before":before,"binary_sha256":BS,"contract_sha256":CS,"package_manifest_sha256":sha(manifest_path),"commands":[],"old_sources_unchanged":False,"complete":False,"full_dc_replacement_qualified":False,"actual_six_host_qualified":False}
def save():
 p=D/"receipt.json";p.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n");p.chmod(0o600)
save()
try:
 for name,file,args in commands:
  assert sha(B)==BS and sha(C)==CS
  now=stage.source_identity(R);assert now["source_files"]==before["source_files"]
  for path,meta in package["copy_whitelist"].items():assert sha(R/path)==meta["sha256"]
  out,err=D/(name+".stdout.log"),D/(name+".stderr.log")
  print("RUN",name,flush=True)
  with out.open("xb") as o,err.open("xb") as e:
   p=subprocess.run([sys.executable,"-B",str(R/"tests"/file),*args],cwd=R,stdout=o,stderr=e,timeout=300)
  out.chmod(0o600);err.chmod(0o600)
  report["commands"].append({"name":name,"script":file,"exit_code":p.returncode,"stdout":{"sha256":sha(out),"bytes":out.stat().st_size},"stderr":{"sha256":sha(err),"bytes":err.stat().st_size},"output_receipt_sha256":sha(D/(name+".json")) if (D/(name+".json")).exists() else None})
  save();print("EXIT",name,p.returncode,flush=True)
  if p.returncode:raise RuntimeError("versioned native stage failed: "+name)
 report["complete"]=True
finally:
 after=stage.source_identity(R);report["source_after"]=after;report["source_stable"]=before["source_files"]==after["source_files"]
 report["old_sources_unchanged"]=all(sha(R/name)==pin for name,pin in oldmap.items())
 report["binary_stable"]=sha(B)==BS;report["new_helpers_stable"]=all(sha(R/name)==meta["sha256"] for name,meta in package["copy_whitelist"].items())
 report["complete"]=bool(report["complete"] and report["source_stable"] and report["old_sources_unchanged"] and report["binary_stable"] and report["new_helpers_stable"]);save()
print("ALL_PASS_V10_NAMED_NATIVE_REGRESSION",flush=True)
