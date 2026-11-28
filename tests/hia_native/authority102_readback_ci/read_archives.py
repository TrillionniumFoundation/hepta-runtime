from pathlib import Path, PurePosixPath
import argparse, hashlib, json, os, stat, subprocess, traceback, zipfile
REPO="TrillionniumFoundation/hepta-runtime"
HEAD="f5b021fbfdc2e02d0df0bb4089001da4bae2ac3a"
RUN=43898698837
REPORTS=("joint-authority-extraction.json","joint-batch-extraction.json","joint-complete-readback.json")
ARTIFACTS=(
 ("authority",14241940871,533430345,"d2e7ac7acbb3a0aa736f6f28b4541384df395eab96abbd1a54d785f161e40385",
  {"joint-authority-evidence.tar.gz":"authority.tar.gz","joint-authority-evidence.archive.json":"authority.index.json"}),
 ("batch",14239969473,118827336,"03bea3846a9aff2483008c3525c0534c283e5c944b67c91f141e55cb1f95f225",
  {"joint-batch-evidence/batch-public-complete.tar.gz":"batch.tar.gz","joint-batch-evidence/archive.json":"batch.index.json"}),
 ("joint",14240248945,2804,"3c85e74870d7865727286b8c775a333032d45ccbf0df7a8eccc63abd9db0c84e",
  {name:"original-"+name for name in REPORTS}))
def pin(path):
 with Path(path).open("rb") as stream:
  return dict(bytes=Path(path).stat().st_size,sha256=hashlib.file_digest(stream,"sha256").hexdigest())
def write(path,value):
 Path(path).write_text(json.dumps(value,sort_keys=True,indent=2)+"\n",encoding="utf-8")
def download(out):
 assert not out.exists()
 out.mkdir(parents=True)
 write(out/"started.json",dict(qualification_head=HEAD,qualification_run=RUN,driver=pin(__file__),native_or_rust_executions=0))
 rows=[]
 for name,ident,size,sha,selection in ARTIFACTS:
  endpoint=f"repos/{REPO}/actions/artifacts/{ident}"
  p=subprocess.run(["gh","api",endpoint],check=True,capture_output=True,timeout=60)
  metadata=json.loads(p.stdout)
  assert metadata["id"]==ident and metadata["size_in_bytes"]==size and metadata["expired"] is False
  assert metadata["digest"]=="sha256:"+sha
  assert metadata["workflow_run"]["id"]==RUN and metadata["workflow_run"]["head_sha"]==HEAD
  write(out/(name+"-metadata.json"),metadata)
  archive=out/(name+".zip")
  with archive.open("xb") as destination:
   subprocess.run(["gh","api",endpoint+"/zip"],check=True,stdout=destination,timeout=300)
  assert pin(archive)==dict(bytes=size,sha256=sha)
  members={}; selected=set()
  with zipfile.ZipFile(archive) as zipped:
   for item in zipped.infolist():
    raw=item.filename; path=PurePosixPath(raw)
    assert raw and not path.is_absolute() and ".." not in path.parts and "\\" not in raw
    assert raw.rstrip("/")==str(path) and raw not in members
    kind=stat.S_IFMT(item.external_attr>>16)
    if item.is_dir():
     assert kind in (0,stat.S_IFDIR)
     members[raw]=dict(kind="directory"); continue
    assert kind in (0,stat.S_IFREG) and not item.flag_bits&1
    digest=hashlib.sha256(); count=0
    target=(out/selection[raw]).open("xb") if raw in selection else None
    try:
     with zipped.open(item) as source:
      while block:=source.read(1<<20):
       digest.update(block); count+=len(block)
       if target is not None: target.write(block)
    finally:
     if target is not None: target.close()
    assert count==item.file_size
    members[raw]=dict(kind="file",bytes=count,sha256=digest.hexdigest())
    if raw in selection:
     selected.add(raw)
     assert pin(out/selection[raw])=={k:members[raw][k] for k in ("bytes","sha256")}
  assert selected==set(selection)
  rows.append(dict(name=name,artifact_id=ident,archive=pin(archive),metadata=pin(out/(name+"-metadata.json")),members=members))
 result=dict(status="ALL_THREE_COMPLETE_PUBLISHED_ZIP_HASHES_PASS",qualification_head=HEAD,qualification_run=RUN,
  archives=rows,driver=pin(__file__),native_or_rust_executions=0)
 write(out/"outer-archives.json",result); print(json.dumps(result,sort_keys=True))
def compare(out):
 reports={}
 for name in REPORTS:
  original=out/("original-"+name); actual=out/name
  assert actual.read_bytes()==original.read_bytes(),("complete readonly receipt differs",name)
  reports[name]=dict(pin=pin(actual),contents=json.loads(actual.read_bytes()))
  print(json.dumps(dict(report=name,**reports[name]),sort_keys=True))
 joint=reports["joint-complete-readback.json"]["contents"]
 assert joint["status"]=="READONLY_AUTHORITY102_AND_COMPLETE_BATCH_PASS"
 assert joint["readonly"]["native_or_rust_executions"]==0 and joint["readonly"]["complete_before_after_equal"] is True
 assert len(joint["readonly"]["probes"])==11 and joint["evidence"]["join_controls"]["refusals"]==12
 assert joint["evidence"]["both_profiles_fresh_original_build"] is True and joint["evidence"]["products"]["physical_images"]==102
 result=dict(status="AUTHORITY102_EXTERNAL_COMPLETE_ARCHIVE_AND_JOINT_READBACK_PASS",qualification_head=HEAD,
  qualification_run=RUN,readback_head=os.environ["GITHUB_SHA"],readback_run=int(os.environ["GITHUB_RUN_ID"]),
  complete_original_reports_byte_equal=True,outer_archives=pin(out/"outer-archives.json"),
  reports={n:v["pin"] for n,v in reports.items()},native_or_rust_executions=0,shared_main_modified=False,
  root_local_artifact_readback=False,driver=pin(__file__))
 write(out/"readback-result.json",result); print(json.dumps(result,sort_keys=True))
if __name__=="__main__":
 p=argparse.ArgumentParser()
 p.add_argument("--phase",choices=("download","compare"),required=True); p.add_argument("--output",type=Path,required=True)
 args=p.parse_args()
 try: (download if args.phase=="download" else compare)(args.output)
 except BaseException as error:
  if args.output.is_dir():
   write(args.output/("failure-"+args.phase+".json"),dict(status="FAIL",error=repr(error),traceback=traceback.format_exc(),
    qualification_head=HEAD,qualification_run=RUN,native_or_rust_executions=0))
  raise
