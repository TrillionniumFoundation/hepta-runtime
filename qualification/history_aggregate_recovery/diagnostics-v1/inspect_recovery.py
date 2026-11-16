#!/usr/bin/env python3
"""Inspect complete recovery archive bytes; execute no qualification code."""
import argparse,gzip,hashlib,json,os,tarfile,zipfile
from pathlib import Path,PurePosixPath
ARTIFACT_RUN=43976820851
ARTIFACT_HEAD="064b2281454735ff93b63ffba2b0cb19dcaef3da"
SELECT={"recovery/logs/reader.stderr","recovery/logs/preflight.stdout","recovery/logs/preflight.stderr",
 "recovery/logs/restoration.stderr","recovery/reader/MECHANICAL_READS.json",
 "recovery/failure-working-copy-delta/DELTA.json","recovery/RESTORATION.json",
 "recovery/logs/skipped.stderr"}
def need(v,s):
 if not v:raise ValueError(s)
def sha(path):
 with path.open("rb") as f:return hashlib.file_digest(f,"sha256").hexdigest()
def put(path,v):path.write_bytes((json.dumps(v,sort_keys=True,indent=2)+"\n").encode())
def main():
 p=argparse.ArgumentParser();p.add_argument("--zip",type=Path,required=True);p.add_argument("--metadata",type=Path,required=True)
 p.add_argument("--output",type=Path,required=True);a=p.parse_args();out=a.output
 out.mkdir(parents=True,exist_ok=False)
 meta=json.loads(a.metadata.read_bytes());need(meta["workflow_run"]["id"]==ARTIFACT_RUN and meta["workflow_run"]["head_sha"]==ARTIFACT_HEAD and meta["expired"] is False,"fixed recovery artifact provenance")
 digest=sha(a.zip);need(meta["id"]==14281552031 and meta["size_in_bytes"]==28735281 and digest=="d08d911157b9ed7bbdd258b696cbf3b45e87e1fd10378a876aab1996c44c3fad" and meta["digest"]=="sha256:"+digest and meta["size_in_bytes"]==a.zip.stat().st_size,"whole recovery ZIP")
 seen=set();files=0;logical=0;selected=[]
 with zipfile.ZipFile(a.zip) as archive:
  need(set(archive.namelist())=={"manifest.json","recovery-evidence.tar.gz"} and len(archive.namelist())==2,"exact recovery ZIP entries")
  manifest=json.loads(archive.read("manifest.json"));rows={x["path"]:x for x in manifest["members"]}
  need(len(rows)==len(manifest["members"]) and manifest["status"]=="COMPLETE","complete recovery exporter")
  with archive.open("recovery-evidence.tar.gz") as stream:
   h=hashlib.sha256();n=0
   while block:=stream.read(1<<20):h.update(block);n+=len(block)
  need(manifest["archive"]=={"bytes":n,"sha256":h.hexdigest()},"whole inner gzip identity")
  with archive.open("recovery-evidence.tar.gz") as stream,tarfile.open(fileobj=stream,mode="r|gz") as tar,gzip.open(out/"tar-index.jsonl.gz","wb",compresslevel=1) as index:
   for item in tar:
    name=item.name
    need(name not in seen and name in rows and not name.startswith("/") and ".." not in PurePosixPath(name).parts,"unique admitted archive path")
    seen.add(name);row=rows[name]
    need(item.mode==row["mode"] and (item.isfile() or item.isdir()),"complete type and mode")
    if item.isfile():
     need(row["type"]=="file" and item.size==row["bytes"],"full file extent")
     f=tar.extractfile(item);h=hashlib.sha256();n=0;save=bytearray() if name in SELECT else None
     while block:=f.read(1<<20):
      h.update(block);n+=len(block)
      if save is not None:save.extend(block)
     need(n==row["bytes"] and h.hexdigest()==row["sha256"],"full member identity: "+name)
     files+=1;logical+=n
     if save is not None:
      target=out/("selected-"+str(len(selected)).zfill(2)+".bin");target.write_bytes(save)
      selected.append({"original":name,"retained":target.name,"bytes":n,"sha256":h.hexdigest()})
      if name.endswith(".stderr") or name.endswith("preflight.stdout"):
       print(json.dumps({"path":name,"complete_utf8":save.decode("utf-8")},sort_keys=True),flush=True)
      if name.endswith("MECHANICAL_READS.json"):
       value=json.loads(save);print(json.dumps({"mechanical_actual_records":len(value["records"]),"mechanical_replayed":len(value["replayed_metadata"]),"directory_noops":len(value["existing_directory_noops"]),"violations":value["violations"]},sort_keys=True),flush=True)
    else:need(row["type"]=="directory","directory identity")
    index.write((json.dumps(row,sort_keys=True)+"\n").encode())
  need(set(seen)==set(rows),"every original recovery member")
 result={"schema":"hepta.history.recovery-diagnostic.v1","status":"FULL_ARCHIVE_BYTE_READBACK_PASS",
  "artifact":meta,"zip_sha256":digest,"archive":manifest["archive"],"members":len(seen),"files":files,
  "logical_bytes":logical,"selected":selected,"recovery_pass":manifest["aggregate_recovery_pass"],
  "native_or_rust_executions":0,"original_failure_reclassified_as_pass":False}
 put(out/"READBACK.json",result);put(out/"manifest.json",manifest)
 print(json.dumps({k:v for k,v in result.items() if k!="artifact"},sort_keys=True))
if __name__=="__main__":main()
