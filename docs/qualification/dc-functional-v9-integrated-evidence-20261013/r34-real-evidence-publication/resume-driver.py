#!/usr/bin/env python3
import pathlib,json,hashlib,subprocess
R=pathlib.Path("/home/qian-qi/hepta-runtime-dc-functional-20261013")
Q=R/"docs/qualification/dc-functional-v9-integrated-evidence-20261013/r34-real-evidence-publication"
HEAD="97764573fafe03d2167ee7c36a52efe57107d7aa"
def git(*args):return subprocess.check_output(["git",*args],cwd=R,text=True).strip()
assert git("rev-parse","HEAD")==HEAD and git("ls-remote","origin","refs/heads/feat/operator-parity-20261006").split()[0]==HEAD
pins=json.loads((Q/"selected-file-pins.json").read_bytes())
for name,pin in pins.items():
 raw=(R/name).read_bytes()
 assert len(raw)==pin["bytes"] and hashlib.sha256(raw).hexdigest()==pin["sha256"]
staged=git("diff","--cached","--name-only").splitlines()
assert staged and all(n in pins or n in ("docs/WORK_HANDOFF_DC_REPLACEMENT_20261013.md","docs/DC_FUNCTIONAL_V9_INTEGRATED_CANDIDATE.md") or n.startswith(str(Q.relative_to(R))+"/") for n in staged)
assert not git("diff","--cached","--name-only","--","src","Cargo.toml","Cargo.lock","deploy","tests")
original=(Q/"diff-check.log").read_text()
assert original=="docs/qualification/dc-functional-v9-integrated-evidence-20261013/r33-exact-checker-ci/9776457-watch.log:479: new blank line at EOF.\n"
check=subprocess.run(["git","diff","--cached","--check","--","docs/WORK_HANDOFF_DC_REPLACEMENT_20261013.md","docs/DC_FUNCTIONAL_V9_INTEGRATED_CANDIDATE.md"],cwd=R,capture_output=True,text=True)
assert check.returncode==0
for name in ("shipping-document-check.log","r2-raw-watch-whitespace-refusal.json","resume-driver.py"):
 assert not (Q/name).exists()
(Q/"shipping-document-check.log").write_text(check.stdout+check.stderr)
(Q/"r2-raw-watch-whitespace-refusal.json").write_text(json.dumps({"job":"1a137ab09e0-b2f-b27","exit":1,"commit_or_push_performed":False,"staged_index_preserved_for_reconciliation":True,"raw_ci_watch_stdout_retained_byte_exact":True,"only_refusal":"new blank line at EOF in original terminal log","shipping_document_check_exit":0,"archive_bytes_not_reformatted":True},sort_keys=True,indent=2)+"\n")
(Q/"resume-driver.py").write_bytes(pathlib.Path(__file__).read_bytes())
subprocess.run(["git","add","--",str(Q.relative_to(R))],cwd=R,check=True)
staged=git("diff","--cached","--name-only").splitlines()
commit=git("commit","-m","docs: retain real host failures and private successor preflight evidence")
head=git("rev-parse","HEAD")
push=subprocess.run(["git","push","origin","HEAD:feat/operator-parity-20261006"],cwd=R,capture_output=True,text=True)
pathlib.Path("/tmp/hepta-real-evidence-publication-push-20261013-r34-r3.log").write_text(commit+"\n"+push.stdout+push.stderr)
assert push.returncode==0,"reconcile existing commit before any new commit"
assert git("ls-remote","origin","refs/heads/feat/operator-parity-20261006").split()[0]==head
print(json.dumps({"pushed_head":head,"parent":HEAD,"staged_files":len(staged),"source_changed":False,"exact_checker_ci":"38484196796","full_dc_replacement_qualified":False},sort_keys=True))
