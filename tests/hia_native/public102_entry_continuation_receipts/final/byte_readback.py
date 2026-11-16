"""Byte-complete recovery of the successful 7afd continuation; no HIA/Rust launch."""
from pathlib import Path, PurePosixPath
from concurrent.futures import ThreadPoolExecutor
import hashlib,json,os,shutil,signal,stat,subprocess,sys,time,traceback,urllib.request,zipfile
sys.dont_write_bytecode=True
def enc(v):return (json.dumps(v,sort_keys=True,indent=2)+"\n").encode()
def pin(p):
 s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and p.resolve(strict=True)==p.absolute()
 with p.open("rb") as f:h=hashlib.file_digest(f,"sha256").hexdigest()
 assert p.stat().st_size==s.st_size
 return dict(bytes=s.st_size,sha256=h)
def doc(p):pin(p);return json.loads(p.read_bytes())
def put(p,v):
 with p.open("xb") as f:f.write(enc(v))
def blob(b):return hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest()
def safe(n):
 p=PurePosixPath(n);assert n and not p.is_absolute() and ".." not in p.parts and str(p)==n and "\\" not in n
 return Path(*p.parts)
def check(root):
 assert pin(root/"joint-source.json")["sha256"]==PROFILE
 for n,r in doc(root/"joint-source.json")["files"].items():
  p=root/safe(n);assert pin(p)=={k:r[k] for k in ("bytes","sha256")},n
  assert blob(p.read_bytes())==r["git_blob"],n
def fetch(row):
 m=row["metadata"];p=ROOT/"zips"/(str(m["id"])+".zip")
 assert m["expired"] is False
 assert m["workflow_run"]["id"]==(43926475626 if row["kind"]=="batch" else 43937415527)
 assert m["workflow_run"]["head_sha"]==(RUNTIME if row["kind"]=="batch" else HEAD)
 with urllib.request.urlopen(row["download_url"],timeout=60) as a,p.open("xb") as b:shutil.copyfileobj(a,b,1<<20)
 assert pin(p)==dict(bytes=m["size_in_bytes"],sha256=m["digest"].removeprefix("sha256:"))
 out=ROOT/"downloads"/str(m["id"]);out.mkdir();rows={}
 with zipfile.ZipFile(p) as z:
  for mbr in z.infolist():
   n=mbr.filename;assert not mbr.is_dir() and n not in rows and stat.S_IFMT(mbr.external_attr>>16) in (0,stat.S_IFREG)
   dst=out/safe(n);dst.parent.mkdir(parents=True,exist_ok=True)
   with z.open(mbr) as a,dst.open("xb") as b:shutil.copyfileobj(a,b,1<<20)
   rows[n]=pin(dst);assert rows[n]["bytes"]==mbr.file_size
 return dict(kind=row["kind"],metadata=m,zip=pin(p),zip_members=rows,root=str(out))
def read(name,args):
 out=ROOT/"readers";start=time.monotonic();p=None;errors=[];rc=None
 try:
  with (out/(name+".stdout")).open("xb") as a,(out/(name+".stderr")).open("xb") as b:
   p=subprocess.Popen(args,cwd=ROOT,stdout=a,stderr=b,start_new_session=True,
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE="1",LC_ALL="C.UTF-8"))
   rc=p.wait(timeout=300)
 except BaseException:
  errors.append(traceback.format_exc());raise
 finally:
  if p is not None:
   try:
    if p.poll() is None:os.killpg(p.pid,signal.SIGKILL)
   except ProcessLookupError:pass
   except BaseException:errors.append(traceback.format_exc())
   try:p.wait()
   except BaseException:errors.append(traceback.format_exc())
  receipt=dict(command=args,cwd=str(ROOT),exit_code=rc,seconds=time.monotonic()-start,
   errors=errors,stdout=pin(out/(name+".stdout")),stderr=pin(out/(name+".stderr")),native_or_rust_executions=0)
  put(out/(name+".process.json"),receipt)
 assert rc==0 and not errors and receipt["stderr"]["bytes"]==0,(name,receipt)
 return doc(out/(name+".stdout")),receipt
I=json.load(sys.stdin);ROOT=Path(I["root"]).absolute()
RUNTIME="7afd543feea2938b08ae8c10f1c6a911f23621ed"
HEAD="722469304e375088732b425ceb8bf83a086e45ea"
PROFILE="5ff90d433a604920d689f56ffd38e3c95e622f0ab5b72bc143d500d4c9e6404d"
assert not ROOT.exists();ROOT.mkdir(parents=True)
for n in ("zips","downloads","readers"):(ROOT/n).mkdir()
put(ROOT/"INPUT.json",dict(root=str(ROOT),prior_joint=I["prior_joint"],entry_git_blob=I["entry_git_blob"],
 artifacts=[dict(kind=x["kind"],metadata=x["metadata"]) for x in I["artifacts"]]))
started=time.monotonic()
try:
 prior=Path(I["prior_joint"]);check(prior)
 ep=prior/"extract_archive.py";ns={"__name__":"_frozen_f5_extractor","__file__":str(ep)}
 exec(compile(ep.read_bytes(),str(ep),"exec"),ns);extract=ns["extract"]
 with ThreadPoolExecutor(max_workers=3) as p:got=list(p.map(fetch,I["artifacts"]))
 assert len(got)==8 and len({x["metadata"]["id"] for x in got})==8;put(ROOT/"DOWNLOADS.json",got)
 by={x["kind"]:x for x in got};assert set(by)=={"metadata","readonly","batch","part00","part01","part02","part03","part04"}
 md=Path(by["metadata"]["root"]);rd=Path(by["readonly"]["root"])
 idx=doc(md/"metadata/parts.json");ai=md/"metadata/archive.json"
 assert idx["schema"]=="hepta.public102.entry-continuation.parts.v1" and pin(ai)==idx["index"]
 assert [x["name"] for x in idx["parts"]]==["part%02d.bin"%i for i in range(5)]
 tar=ROOT/"continuation-complete.tar.gz"
 with tar.open("xb") as out:
  for i,row in enumerate(idx["parts"]):
   d=by["part%02d"%i];assert set(d["zip_members"])=={row["name"]}
   src=Path(d["root"])/row["name"];assert pin(src)=={k:row[k] for k in ("bytes","sha256")}
   assert 0<row["bytes"]<=128*1024*1024
   if i<4:assert row["bytes"]==128*1024*1024
   with src.open("rb") as f:shutil.copyfileobj(f,out,1<<20)
 assert pin(tar)==idx["archive"]
 auth=ROOT/"authority";batch=ROOT/"batch"
 ae=extract("authority",tar,ai,auth);bd=Path(by["batch"]["root"])/"joint-batch-evidence"
 be=extract("batch",bd/"batch-public-complete.tar.gz",bd/"archive.json",batch)
 put(ROOT/"EXTRACTIONS.json",dict(authority=ae,batch=be))
 joint=auth/"joint-source";check(joint)
 ci=doc(rd/"public102-continuation-FINAL.json")
 assert ci["status"]=="SAME_HEAD_FRESH_CAPTURE_DEFAULT_ENTRY_AND_JOINT_READONLY_PASS"
 assert ci["qualified_runtime_commit"]==RUNTIME and ci["original_authority_job_conclusion"]=="cancelled" and ci["original_cancellation_relabelled"] is False
 for n,row in ci["readonly_reports"].items():assert pin(rd/"continuation-readers"/safe(n))==row,n
 jr,jp=read("joint-complete",[sys.executable,"-I","-B",str(joint/"verify_joint.py"),"--source",str(joint),
  "--expected-source-sha256",PROFILE,"--authority",str(auth),"--batch",str(batch)])
 assert jr["status"]=="READONLY_AUTHORITY102_AND_COMPLETE_BATCH_PASS" and jr["readonly"]["complete_before_after_equal"] is True and len(jr["readonly"]["probes"])==11
 run=auth/"run";entry_out=run/"installed-main-entry";runtime=ROOT/"runtime-source"
 shutil.copytree(entry_out/"installed-source",runtime,symlinks=False)
 raw=I["entry_source"].encode();assert blob(raw)==I["entry_git_blob"]=="238f3cc19569d8458742424f723c50e511964ba5"
 assert raw==(entry_out/"producer.py").read_bytes()
 entry=runtime/"tests/hia_native/public102_entry.py";entry.parent.mkdir(parents=True,exist_ok=True)
 assert not entry.exists();entry.write_bytes(raw)
 er,ep=read("installed-main-relocated",[sys.executable,"-I","-B",str(entry),"--source",str(runtime),
  "--reference-package",str(joint/"authority"),"--run",str(run),"--output",str(entry_out),"--verify-only"])
 assert er["evidence"]["status"]=="ACTUAL_MAIN_DEFAULT_ENTRY_EQUALS_QUALIFIED_PUBLIC102" and len(er["probes"])==11 and er["before"]==er["after"]
 proof=entry_out/"continuation-proof";old=doc(proof/"prior-authority/artifact-manifest.json")["files"]
 old={n:r for n,r in old.items() if n.startswith("run/")};current=doc(auth/"artifact-manifest.json")["files"]
 assert {n:current[n] for n in old}==old
 new=[n for n in current if n.startswith("run/") and n not in old]
 assert new and all(n.startswith("run/installed-main-entry/") for n in new)
 for n,r in old.items():assert pin(auth/safe(n))==r,n
 assert pin(proof/"prior-authority/artifact-manifest.json")==dict(bytes=2818586,sha256="5a73377ea6143a6b641055840406414792e25891fa6b6ad548c9898c3f9e2951")
 summary=dict(status="COMPLETE_CONTINUATION_BYTES_AND_UNCHANGED_JOINT_DEFAULT_READERS_PASS",
  runtime_commit=RUNTIME,continuation_commit=HEAD,continuation_run=43937415527,
  old_authority_job_remains_cancelled=True,archive=pin(tar),archive_index=pin(ai),
  artifacts=[dict(id=x["metadata"]["id"],name=x["metadata"]["name"],zip=x["zip"],zip_files=len(x["zip_members"])) for x in got],
  all_zip_bytes=sum(x["zip"]["bytes"] for x in got),extraction=dict(authority=ae,batch=be),
  ci_final=pin(rd/"public102-continuation-FINAL.json"),original_run_files_preserved=len(old),
  original_run_bytes_preserved=sum(r["bytes"] for r in old.values()),added_run_files=len(new),
  added_only_installed_main_entry=True,joint_evidence=jr["evidence"],joint_guard_probes=11,
  entry_evidence=er["evidence"],entry_guard_probes=11,reader_processes=dict(joint=jp,entry=ep),
  python_reader_processes=2,native_or_rust_executions=0,seconds=time.monotonic()-started,
  whole_runtime_replaced=False,full_sdk_qualified=False,full_async_qualified=False,
  production_activated=False,old_path_removed=False)
 put(ROOT/"SUMMARY.json",summary)
 print(json.dumps(dict(status=summary["status"],summary=pin(ROOT/"SUMMARY.json"),archive=pin(tar),
  original_run_files_preserved=len(old),seconds=summary["seconds"],native_or_rust_executions=0),sort_keys=True))
except BaseException:
 put(ROOT/"FAILURE.json",dict(traceback=traceback.format_exc(),seconds=time.monotonic()-started));raise
