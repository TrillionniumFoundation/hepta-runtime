#!/usr/bin/env python3
import pathlib,subprocess,json,hashlib
R=pathlib.Path("/home/qian-qi/hepta-runtime-dc-functional-20261013")
Q=R/"docs/qualification/dc-functional-v9-integrated-evidence-20261013/r33-exact-checker-ci"
GH="/home/qian-qi/.linuxbrew/bin/gh"
REPO="TrillionniumFoundation/hepta-runtime"
runs=[("3791c11","38477326498","3791c11e17d09e90695ab2cac2bb84b5ba34845c","success"),("6cd61bd","38476670079","6cd61bdc7176b6f816f3809c1e5ebf8b3f9b6399","cancelled"),("9776457","38484196796","97764573fafe03d2167ee7c36a52efe57107d7aa","success")]
assert not Q.exists();Q.mkdir(mode=0o700)
(Q/"driver.py").write_bytes(pathlib.Path(__file__).read_bytes())
rows=[]
for label,run,head,expected in runs:
 args=[GH,"run","view",run,"--repo",REPO,"--json","databaseId,headSha,status,conclusion,url,jobs"]
 first=subprocess.run(args,cwd=R,capture_output=True,text=True)
 assert first.returncode==0
 data=json.loads(first.stdout);assert data["headSha"]==head
 if data["status"]!="completed":
  assert label=="9776457"
  with (Q/"9776457-watch.log").open("w") as log:
   watch=subprocess.run([GH,"run","watch",run,"--repo",REPO,"--exit-status","--interval","10"],cwd=R,stdout=log,stderr=subprocess.STDOUT,timeout=1500)
  (Q/"9776457-watch-exit.json").write_text(json.dumps({"exit":watch.returncode})+"\n")
  final=subprocess.run(args,cwd=R,capture_output=True,text=True);assert final.returncode==0
  raw=final.stdout;data=json.loads(raw)
 else:raw=first.stdout
 (Q/(label+"-run.json")).write_text(raw)
 assert data["headSha"]==head and data["status"]=="completed" and data["conclusion"]==expected
 rows.append({"head":head,"run":int(run),"status":data["status"],"conclusion":data["conclusion"],"url":data["url"],"raw_sha256":hashlib.sha256(raw.encode()).hexdigest()})
 (Q/"partial-observations.json").write_text(json.dumps(rows,sort_keys=True,indent=2)+"\n")
receipt={"completed":True,"observations":rows,"cancelled_is_not_success":True,"six_host_or_full_replacement_claim":False}
(Q/"receipt.json").write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")
print(json.dumps(receipt,sort_keys=True))
