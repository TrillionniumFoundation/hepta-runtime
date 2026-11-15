#!/usr/bin/env python3
import pathlib,subprocess,json,hashlib,os
R=pathlib.Path("/home/qian-qi/hepta-runtime-dc-functional-20261013")
Q=R/"docs/qualification/dc-functional-v10-integrated-evidence-20261013/r6-prior-head-ci"
H="aa41acbdd181a814f51b51c91e01fceedb797fab"
assert subprocess.check_output(["git","rev-parse","HEAD"],cwd=R,text=True).strip()==H
assert not Q.exists();Q.mkdir(mode=0o700);os.umask(0o077)
(Q/"driver.py").write_bytes(pathlib.Path(__file__).read_bytes())
p=subprocess.run(["git","ls-remote","origin","refs/heads/feat/operator-parity-20261006"],cwd=R,capture_output=True,text=True,timeout=60)
(Q/"remote-head.stdout").write_text(p.stdout);(Q/"remote-head.stderr").write_text(p.stderr)
assert p.returncode==0 and p.stdout.split()[0]==H
argv=["/home/qian-qi/.linuxbrew/bin/gh","run","view","38486960040","--repo","TrillionniumFoundation/hepta-runtime","--json","databaseId,headSha,status,conclusion,url,jobs"]
r=subprocess.run(argv,cwd=R,capture_output=True,text=True,timeout=60)
(Q/"run.stderr").write_text(r.stderr);(Q/"run.json").write_text(r.stdout)
assert r.returncode==0
d=json.loads(r.stdout);assert d["headSha"]==H
receipt={"completed":d["status"]=="completed","head":H,"remote_head_matches":True,"run":38486960040,"status":d["status"],"conclusion":d["conclusion"],"url":d["url"],"raw_sha256":hashlib.sha256(r.stdout.encode()).hexdigest(),"current_uncommitted_v10_checks_are_separate":True,"full_dc_replacement_qualified":False}
(Q/"receipt.json").write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")
print(json.dumps(receipt,sort_keys=True))
