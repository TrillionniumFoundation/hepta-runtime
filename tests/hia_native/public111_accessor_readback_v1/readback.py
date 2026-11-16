"""Read every existing accessor artifact byte and repeat only pure readers."""
# Copyright 2026 Muvon Un Limited
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


from pathlib import Path,PurePosixPath
import argparse,base64,collections,gzip,hashlib,io,json,os,re,shutil,stat,struct,sys,tarfile,urllib.error,urllib.parse,urllib.request,zipfile
sys.dont_write_bytecode=True
WANTED={"id":14279664641,"bytes":66881812,"sha256":"0fe78d206023e6dc614a53f31622a83798bbf3ae960649dd74b78d89e6e7ed4b"}
HEAD="9ddb9795b0b787fab19d2558b8c634238a26d80d"
RUN=43976290161
SOURCE="377327c584d81fde922274f1d883fe31a8d0f87a2fa05fab1bc812d55dd51813"
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):return None
def sha(raw):return hashlib.sha256(raw).hexdigest()
def pin(path):
 with path.open("rb") as f:d=hashlib.file_digest(f,"sha256").hexdigest()
 return {"bytes":path.stat().st_size,"sha256":d}
def save(p,value):
 with p.open("x",encoding="utf-8") as f:json.dump(value,f,sort_keys=True,indent=2);f.write("\n")
def safe(name):
 p=PurePosixPath(name)
 assert isinstance(name,str) and name and not p.is_absolute() and p.as_posix()==name and all(x not in ("",".","..") for x in p.parts)
 return name
def load_module(path,expected):
 raw=path.read_bytes();assert sha(raw)==expected
 scope={"__name__":"_fixed_"+path.stem,"__file__":str(path)}
 exec(compile(raw,str(path),"exec"),scope)
 return scope
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument("--output",type=Path,required=True);a=p.parse_args()
 out=a.output.absolute();assert os.environ.get("GITHUB_ACTIONS")=="true" and not out.exists();out.mkdir(parents=True)
 repo="TrillionniumFoundation/hepta-runtime";url=f"https://api.github.com/repos/{repo}/actions/artifacts/{WANTED['id']}"
 headers={"Authorization":"Bearer "+os.environ["GH_TOKEN"],"Accept":"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28"}
 with urllib.request.urlopen(urllib.request.Request(url,headers=headers),timeout=60) as r:md=json.load(r)
 assert md["id"]==WANTED["id"] and md["size_in_bytes"]==WANTED["bytes"] and md["digest"]=="sha256:"+WANTED["sha256"] and md["expired"] is False
 assert md["workflow_run"]["id"]==RUN and md["workflow_run"]["head_sha"]==HEAD
 try:response=urllib.request.build_opener(NoRedirect).open(urllib.request.Request(url+"/zip",headers=headers),timeout=60)
 except urllib.error.HTTPError as e:
  assert e.code in (301,302,303,307,308)
  redirect=urllib.parse.urlsplit(e.headers["Location"]);assert redirect.scheme=="https" and redirect.hostname and redirect.username is None
  response=urllib.request.urlopen(urllib.request.Request(e.headers["Location"]),timeout=60)
 archive=out/"artifact.zip"
 with response,archive.open("xb") as f:shutil.copyfileobj(response,f,1<<20)
 assert pin(archive)=={k:WANTED[k] for k in ("bytes","sha256")}
 with zipfile.ZipFile(archive) as z:
  assert len(z.infolist())==2 and set(z.namelist())=={"archive.json","capture.tar.gz"} and z.testzip() is None
  for name in z.namelist():
   with z.open(name) as s,(out/name).open("xb") as f:shutil.copyfileobj(s,f,1<<20)
 receipt=json.loads((out/"archive.json").read_bytes())
 assert receipt["git_head"]==HEAD and receipt["run_id"]==str(RUN) and receipt["run_attempt"]=="1"
 assert receipt["source_manifest_sha256"]==SOURCE and pin(out/"capture.tar.gz")==receipt["archive"]
 root=out/"capture";root.mkdir();seen=set();manifest=None;expected=None
 with tarfile.open(out/"capture.tar.gz","r:gz") as tar:
  for member in tar:
   assert member.name.startswith("capture/") and member.isfile() and not member.islnk() and not member.issym()
   name=safe(member.name.removeprefix("capture/"));assert name not in seen
   stream=tar.extractfile(member);assert stream is not None
   if not seen:
    assert name=="artifact-manifest.json" and member.mode==0o600
    with stream:raw=stream.read()
    assert {"bytes":len(raw),"sha256":sha(raw)}==receipt["manifest"]
    manifest=json.loads(raw);expected=dict(manifest["files"])
    assert manifest["schema"]=="hepta.runtime.complete-ci-archive.v2" and manifest["source_manifest_sha256"]==SOURCE
    for relative,row in expected.items():
     safe(relative);assert set(row)=={"bytes","sha256","mode"} and type(row["bytes"]) is int and row["bytes"]>=0 and type(row["mode"]) is int and 0<=row["mode"]<=0o777
    assert name not in expected;expected[name]={**receipt["manifest"],"mode":0o600}
    (root/name).write_bytes(raw);os.chmod(root/name,0o600)
   else:
    assert name in expected;row=expected[name];assert member.size==row["bytes"] and member.mode==row["mode"]
    target=root/name;target.parent.mkdir(parents=True,exist_ok=True)
    with stream,target.open("xb") as f:shutil.copyfileobj(stream,f,1<<20)
    assert pin(target)=={k:row[k] for k in ("bytes","sha256")};os.chmod(target,row["mode"])
   seen.add(name)
 assert seen==set(expected) and receipt["readback"]=={"files":len(seen),"logical_bytes":sum(v["bytes"] for v in expected.values())}
 for name,mode in manifest["directories"].items():
  safe(name);assert type(mode) is int and 0<=mode<=0o777;(root/name).mkdir(parents=True,exist_ok=True)
 assert {q.relative_to(root).as_posix() for q in root.rglob("*") if q.is_dir()}==set(manifest["directories"])
 for name,mode in sorted(manifest["directories"].items(),key=lambda x:len(Path(x[0]).parts),reverse=True):os.chmod(root/name,mode)
 package=root/"ci-package";source_raw=(package/"SOURCE.json").read_bytes();assert sha(source_raw)==SOURCE
 source_files=json.loads(source_raw)["files"]
 assert {q.relative_to(package).as_posix() for q in package.rglob("*") if q.is_file()}==set(source_files)|{"SOURCE.json"}
 for name,row in source_files.items():assert pin(package/name)==row
 guard_file=Path(__file__).parent/"read_only_guard.py"
 guard=load_module(guard_file,"7c45f0610e28742fe73323fb7c133ee3e04e5e41f4ea77a815b516e059849a1b")
 pairs=load_module(package/"read_pairs.py","df286f8d6474e21d6d03fa70f02842065270a103ac0dc3fe387accc496fdac2a")
 profile=load_module(package/"read_profile.py","c7699895f0e1c95d4f4d04dca76d7456bc730ecb0800cdcf20881bf5f998b22a")
 load_module(package/"wire_compare.py","b23cb303a3e6fd62731bacd297ae8c3eb7c0351730c0e5f0347d8d526aa60a40")
 def operation():
  corpus=json.loads((package/"CORPUS.json").read_bytes());record=json.loads((root/"PROFILE.json").read_bytes());pr=[];cr=[]
  for row in corpus["rows"]:
   for component in ("message","value"):
    label="pair-"+row["name"]+"-"+component
    proof=pairs["read"](root/"pairs"/label)
    assert proof==json.loads((root/"processes"/("read-"+label+".stdout")).read_bytes());pr.append(proof)
   result=profile["read"](root/row["name"],root/"build/profile/manifest.json",package,root/"inputs",row)
   assert result==json.loads((root/"processes"/("read-"+row["name"]+".stdout")).read_bytes());cr.append(result)
  assert record["paired_reports"]==pr and record["reports"]==cr and record["paired_actual_native_calls"]==48 and record["paired_full_buffer_cases"]==24
  assert record["whole_1394_or_async_qualified"] is False and record["hia_images_changed"]==2
  return {"status":"ALL_24_FULL_BUFFER_PAIRS_AND_THREE_COMPLETE_WIRES_REOPENED","pairs":pr,"reports":cr}
 readonly=guard["guarded"](operation,roots=[root,Path(__file__).parent.absolute()],foreign_path=out/"unadmitted")
 save(out/"READONLY.json",readonly)
 times=[]
 for report in readonly["evidence"]["reports"]:
  times.append({"sequence":report["sequence"],"process_seconds":report["process_seconds"],"solver_wire_wall_seconds":report["solver_wire_wall_seconds"],"slots":report["slots"],"timing_kind":"monotonic wall, not CPU"})
 pair_times=[]
 for sequence in (38,275,276):
  for component in ("message","value"):
   r=json.loads((root/"pairs"/f"pair-sequence-{sequence}-{component}"/"PAIRS.json").read_bytes())
   pair_times.append({"sequence":sequence,"component":component,"observations":[{"case":c["case"],"before_ns":c["sides"][0]["elapsed_ns"],"after_ns":c["sides"][1]["elapsed_ns"],"actual_return":c["sides"][0]["actual_return"]} for c in r["observations"]]})
 summary={"status":"COMPLETE_EXISTING_ACCESSOR_ARTIFACT_AND_PURE_READERS_PASS","original_head":HEAD,"original_run":RUN,"artifact":WANTED,
  "archive":receipt["archive"],"members":len(expected),"logical_bytes":receipt["readback"]["logical_bytes"],"source_files":len(source_files)+1,
  "physical_guard_probes":len(readonly["probes"]),"unchanged_entries":len(readonly["before"]),
  "before_sha256":sha(json.dumps(readonly["before"],sort_keys=True,separators=(",",":")).encode()),"after_sha256":sha(json.dumps(readonly["after"],sort_keys=True,separators=(",",":")).encode()),
  "native_or_rust_reader_executions":0,"reader_writes":0,"timings":times,"pair_timings":pair_times,"full1394_pass":False}
 save(out/"READBACK.json",summary)
 for name in ("optimized-source/native/fixed_accessor_contraction.json","build/profile/manifest.json"):
  raw=(root/name).read_bytes()
  print("RECOVER_FILE "+json.dumps({"path":name,"bytes":len(raw),"sha256":sha(raw),"text":raw.decode()},sort_keys=True))
 print("READBACK_SUMMARY "+json.dumps(summary,sort_keys=True))
if __name__=="__main__":main()
