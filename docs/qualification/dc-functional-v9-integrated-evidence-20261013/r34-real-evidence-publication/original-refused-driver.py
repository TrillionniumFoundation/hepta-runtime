#!/usr/bin/env python3
import pathlib,json,hashlib,subprocess,os,stat
R=pathlib.Path("/home/qian-qi/hepta-runtime-dc-functional-20261013")
Q=R/"docs/qualification/dc-functional-v9-integrated-evidence-20261013"
HEAD="97764573fafe03d2167ee7c36a52efe57107d7aa"
def git(*args):return subprocess.check_output(["git",*args],cwd=R,text=True).strip()
assert git("rev-parse","HEAD")==HEAD and git("ls-remote","origin","refs/heads/feat/operator-parity-20261006").split()[0]==HEAD
assert not git("diff","--cached","--name-only")
for n,pin in {"deploy/preflight_dc_successor.py":"e3bf754dbcf58219994af79f935f9166d9ff39534ae8b55b4d6593446c843fec","tests/dc_successor_preflight_tests.py":"35ca6e4d3993d834ce84899a929e7605ccbaed02d8769b076d94629ce4fdfdde"}.items():assert hashlib.sha256((R/n).read_bytes()).hexdigest()==pin
M=Q/"r19-real-functional-matrix"
seal=M/"r19-complete-cohort-publication-seal-r2.json"
assert hashlib.sha256(seal.read_bytes()).hexdigest()=="25e41ff8ea6fb90b011e052358b425b8fb5c5789199b266d0c8c572da2402229"
value=json.loads(seal.read_bytes())
assert value["R19_full_matrix_complete"] is False and value["batch_qualified"] is False and value["signal_qualified"] is False
assert len(value["complete_cohorts"])==7 and all(x["complete"] is True and x["all_inputs_stable"] is True for x in value["complete_cohorts"])
selected=[]
for n,pin in {**value["explicit_selected_files"],**value["retained_original_failed_artifact_pins"]}.items():
 p=M/n;assert not pathlib.Path(n).is_absolute() and ".." not in pathlib.Path(n).parts
 raw=p.read_bytes();assert len(raw)==pin["bytes"] and hashlib.sha256(raw).hexdigest()==pin["sha256"]
 selected.append(p)
selected.extend([seal,M/"r19-complete-cohort-publication-seal-r1.json"])
assert hashlib.sha256(selected[-1].read_bytes()).hexdigest()=="ce0b40aae72294b6472d4eb30ca19334c625a56806ea79230ebf7b56940fb7c3"
for folder in ("02-search","11-inventory","12-inventory-response-diagnostic"):
 selected.extend(p for p in (M/folder).rglob("*") if p.is_file())
for name in ("r19-matrix-owned-stage-driver-r2.py","r19-matrix-owned-stage-driver-r3.py","r19-matrix-inventory-diagnostic-stage-driver.py"):
 selected.append(M/name)
for folder in ("r27-actual-production-inventory-after-token-fix","r31-root-inactive-cache-cleanup","r32-private-profile-production-proof","r33-exact-checker-ci"):
 selected.extend(p for p in (Q/folder).rglob("*") if p.is_file())
assert hashlib.sha256((Q/"r31-root-inactive-cache-cleanup/receipt.json").read_bytes()).hexdigest()=="3e7bbc4f0f3a7ccb7d841d9a5446b433449d442cd33caebf1b50fab5bcfc0cc1"
assert hashlib.sha256((Q/"r32-private-profile-production-proof/public-receipt.json").read_bytes()).hexdigest()=="c90d68d698a740f9111dec8a735170d62e2175c654ded911ad3315a388fc0f2f"
ci=json.loads((Q/"r33-exact-checker-ci/receipt.json").read_bytes())
assert ci["completed"] is True and ci["cancelled_is_not_success"] is True
assert any(x["head"]==HEAD and x["conclusion"]=="success" for x in ci["observations"])
provenance=Q/"r27-actual-production-inventory-after-token-fix/root-provenance-limitation.json"
assert not provenance.exists()
provenance.write_text(json.dumps({"original_r27_producer_independently_established":False,"original_report_not_used_for_active_zero_or_cutover_permission":True,"later_root_create_only_job":"1a137634cb4-b2f-94b","later_root_create_only_exit":1,"existing_destinations_refused_before_helper_execution":True,"independent_root_authentication_and_4096_registry_refusal_job":"1a1376533e0-b2f-95f","fresh_root_profile_proof_job":"1a13798e7f4-b2f-a83","fresh_root_profile_proof_receipt":"../r32-private-profile-production-proof/public-receipt.json","full_dc_replacement_qualified":False},sort_keys=True,indent=2)+"\n")
selected.append(provenance)
pins={}
for p in sorted(set(selected)):
 assert Q in p.parents
 s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_uid==os.getuid() and s.st_nlink==1 and s.st_size<=2*1024*1024 and not s.st_mode&0o022
 pins[str(p.relative_to(R))]={"bytes":s.st_size,"sha256":hashlib.sha256(p.read_bytes()).hexdigest()}
note="""
### Fresh private profile proof and retained real-host failures

Checker source 97764573fafe03d2167ee7c36a52efe57107d7aa passed exact-head hosted CI 38484196796. R33 stores original complete run JSON for this success, the earlier 3791c11 success, and the cancelled 6cd61bd documentation run. Cancellation is not a green result.

Fresh root-produced R32 actually executed the frozen checker against the unchanged source503 stage and exact private R26 packet. The private candidate is prepared and preserves all undeclared fields, but administrator review is false and the published result is HOLD. Exact private rollback backups exist outside Git. The 4096-row inventory refusal still prevents complete job/PTY/stream observations; admission freeze and authoritative native/facade dispatch state remain unavailable. R27 original files are archived with a separate explicit producer limitation; they never prove zero active work or grant cutover permission.

R19 publishes only seven separately completed cohorts: credential14, actual six-host facade36, main native disposable files13, Python identity main8/Mac2, main search acknowledgement faults5, and six-host read-only health rows plus reconnect/override controls. Python backend identity tests are not native binary signal qualification. Original search65/78 ENOSPC, failed large-registry inventory and exact bounded-response diagnostic remain preserved alongside successful subsets. Batch, signal, neutral, real business and the full matrix remain false. The old unknown pocket4 partial fixture was not guessed, replayed or deleted.

R31 removed only the active functional worktree's verified inactive Cargo incremental cache, preserving all compiled artifact hashes/inodes/link counts and protected service identities. No V10 or unrelated worktree was touched. V10's separate repaired source has passed a fresh complete-input local suite; original product admission failures and the later native harness failure remain retained until fresh complete native acceptance and integration. No installation, Refresh, DC stop or full replacement is claimed.
"""
for name in ("docs/WORK_HANDOFF_DC_REPLACEMENT_20261013.md","docs/DC_FUNCTIONAL_V9_INTEGRATED_CANDIDATE.md"):
 p=R/name;p.write_text(p.read_text()+"\n"+note)
pub=Q/"r34-real-evidence-publication"
assert not pub.exists();pub.mkdir(mode=0o700)
(pub/"driver.py").write_bytes(pathlib.Path(__file__).read_bytes())
(pub/"selected-file-pins.json").write_text(json.dumps(pins,sort_keys=True,indent=2)+"\n")
paths=sorted(pins)+["docs/WORK_HANDOFF_DC_REPLACEMENT_20261013.md","docs/DC_FUNCTIONAL_V9_INTEGRATED_CANDIDATE.md",str(pub.relative_to(R))]
subprocess.run(["git","add","--",*paths],cwd=R,check=True)
check=subprocess.run(["git","diff","--cached","--check"],cwd=R,capture_output=True,text=True)
(pub/"diff-check.log").write_text(check.stdout+check.stderr)
assert check.returncode==0
subprocess.run(["git","add","--",str(pub.relative_to(R))],cwd=R,check=True)
staged=git("diff","--cached","--name-only").splitlines();assert all(n.startswith("docs/") for n in staged)
commit=git("commit","-m","docs: retain real host failures and private successor preflight evidence")
head=git("rev-parse","HEAD")
push=subprocess.run(["git","push","origin","HEAD:feat/operator-parity-20261006"],cwd=R,capture_output=True,text=True)
pathlib.Path("/tmp/hepta-real-evidence-publication-push-20261013-r34.log").write_text(commit+"\n"+push.stdout+push.stderr)
assert push.returncode==0,"reconcile existing commit, never create another before pushing"
assert git("ls-remote","origin","refs/heads/feat/operator-parity-20261006").split()[0]==head
print(json.dumps({"pushed_head":head,"parent":HEAD,"staged_files":len(staged),"source_changed":False,"exact_checker_ci":"38484196796","full_dc_replacement_qualified":False},sort_keys=True))
