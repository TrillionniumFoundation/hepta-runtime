#!/usr/bin/env python3
import pathlib,hashlib,json,subprocess,os
R=pathlib.Path("/home/qian-qi/hepta-runtime-dc-functional-20261013")
HEAD="97764573fafe03d2167ee7c36a52efe57107d7aa"
C=pathlib.Path("/home/qian-qi/hepta-successor-preflight-checker-9776457-20261013-r4")
O=pathlib.Path("/home/qian-qi/hepta-runtime-successor-v9-preflight-5037262-20261013-r4")
B=pathlib.Path("/home/qian-qi/hepta-runtime-successor-v9-private-rollback-5037262-20261013-r4")
Q=R/"docs/qualification/dc-functional-v9-integrated-evidence-20261013/r32-private-profile-production-proof"
pins={"deploy/preflight_dc_successor.py":"e3bf754dbcf58219994af79f935f9166d9ff39534ae8b55b4d6593446c843fec","deploy/stage_dc_successor.py":"80fb34a7d55157032a5a8da007d31f289eb2862746ea16747de7b3cb305f0582","deploy/mcp_tool_contract.py":"e2b29f987d3aaa863d7bf6879d0d6a835a807c133c5c355b6a4e69bce9c3e216","deploy/contracts/hepta-runtime-full-operator-v4.json":"d36610d575146805f4c02d89210abd360b4d42acc8736d1966f20d0d724704b1"}
assert subprocess.check_output(["git","rev-parse","HEAD"],cwd=R,text=True).strip()==HEAD
assert subprocess.check_output(["git","ls-remote","origin","refs/heads/feat/operator-parity-20261006"],cwd=R,text=True).split()[0]==HEAD
assert all(not p.exists() for p in (C,O,B,Q))
blobs={}
for n,pin in pins.items():
 raw=subprocess.check_output(["git","show",HEAD+":"+n],cwd=R)
 assert hashlib.sha256(raw).hexdigest()==pin
 blobs[n]=raw
C.mkdir(mode=0o700)
for n,raw in blobs.items():
 p=C/n;p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,"wb") as f:f.write(raw);f.flush();os.fsync(f.fileno())
stage="/home/qian-qi/hepta-runtime-successor-v9-stage-5037262-20261013-r1/manifest.json"
source="/home/qian-qi/hepta-runtime-v9-code-frozen-5037262-20261013"
review="/home/qian-qi/hepta-runtime-successor-v9-private-profile-5037262-20261013-r1/review.json"
argv=["/usr/bin/python3","-B",str(C/"deploy/preflight_dc_successor.py"),"--stage-manifest",stage,"--stage-manifest-sha256","70357b2065afa9a9f9b5206047bf4134365b540685ac95e2e2588361b0d89689","--source-root",source,"--output-directory",str(O),"--prepare-backups","--backup-directory",str(B),"--profile-review-manifest",review,"--profile-review-manifest-sha256","32b3d300e1a7c10c32a3669095d23a731ef6d40b42a957a2b07db8771f456d76"]
Q.mkdir(mode=0o700);(Q/"driver.py").write_bytes(pathlib.Path(__file__).read_bytes())
(Q/"intent.json").write_text(json.dumps({"checker_head":HEAD,"checker_source_pins":pins,"source_root":source,"stage_manifest":stage,"private_profile_proof":review,"output":str(O),"backup":str(B),"candidate_execution_or_activation":False,"prior_r3_destinations_touched":False},sort_keys=True,indent=2)+"\n")
result=subprocess.run(argv,cwd=C,capture_output=True,text=True)
(Q/"checker-stdout.json").write_text(result.stdout);(Q/"checker-stderr.log").write_text(result.stderr)
assert result.returncode==0,"retain originals and reconcile; do not retry create-only destinations"
raw=(O/"report.json").read_bytes();report=json.loads(raw)
safe={"checker_head":HEAD,"checker_source_pins":pins,"report_path":str(O/"report.json"),"report_sha256":hashlib.sha256(raw).hexdigest(),"status":report["status"],"validation_complete":True,"private_profile_review":report["private_profile_review"],"blockers":[{"code":x["code"],"scope":x["scope"]} for x in report["blockers"]],"live_candidate_activated":False,"full_dc_replacement_qualified":False,"fresh_root_producer_executed":True,"original_r27_producer_not_established":True}
assert safe["private_profile_review"]["prepared"] is True and safe["private_profile_review"]["administrator_review_completed"] is False and safe["status"]=="HOLD"
assert "PRIVATE_PROFILE_REVIEW_REQUIRED" in {x["code"] for x in safe["blockers"]}
(Q/"public-receipt.json").write_text(json.dumps(safe,sort_keys=True,indent=2)+"\n")
print(json.dumps(safe,sort_keys=True))
