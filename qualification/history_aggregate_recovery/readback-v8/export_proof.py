#!/usr/bin/env python3
"""Archive this recovery's complete proof and any changed working-copy bytes."""
from __future__ import annotations
import argparse,gzip,hashlib,json,os,shutil,stat,sys,tarfile,time,zipfile
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from read_recovered import SOURCE,CAPTURE,REPORT_SHA,need,pin,put,encoded
from restore_archive import INDEX_MEMBER,INDEX_MEMBER_SHA
def hash_file(path):
 with path.open("rb") as f:return hashlib.file_digest(f,"sha256").hexdigest()
def meta(info):
 return {"mode":info.st_mode,"bytes":info.st_size,"inode":info.st_ino,"device":info.st_dev,
  "mtime_ns":info.st_mtime_ns,"ctime_ns":info.st_ctime_ns}
def delta(proof,index_zip):
 folder=proof/"failure-working-copy-delta";folder.mkdir(mode=0o700)
 before={}
 if index_zip.is_file():
  with zipfile.ZipFile(index_zip) as arc:
   raw=arc.read(INDEX_MEMBER);need(hashlib.sha256(raw).hexdigest()==INDEX_MEMBER_SHA,"retained failure index")
   before={row["path"]:row for row in map(json.loads,gzip.decompress(raw).splitlines())}
 rows=[];seen=set()
 if CAPTURE.is_dir():
  for path in [CAPTURE,*sorted(CAPTURE.rglob("*"))]:
   name="." if path==CAPTURE else path.relative_to(CAPTURE).as_posix();seen.add(name);info=path.lstat()
   row={"path":name,"observed":meta(info)};old=before.get(name);changed=False
   if stat.S_ISREG(info.st_mode):
    digest=hash_file(path);row["observed"]["sha256"]=digest
    changed=not old or old["type"]!="0" or old["data"]!={"bytes":info.st_size,"sha256":digest} or old["mode"]!=stat.S_IMODE(info.st_mode)
    if changed:
     target=folder/"capture"/name;target.parent.mkdir(parents=True,exist_ok=True)
     shutil.copyfile(path,target);target.chmod(stat.S_IMODE(info.st_mode))
     need(hash_file(target)==digest and meta(path.lstat())==meta(info),"failure delta changed during copy")
     row["retained"]=target.relative_to(proof).as_posix()
   elif stat.S_ISDIR(info.st_mode):changed=not old or old["type"]!="5" or old["mode"]!=stat.S_IMODE(info.st_mode)
   elif stat.S_ISLNK(info.st_mode):row["observed"]["linkname"]=os.readlink(path);changed=True
   else:changed=True
   if changed:row["original"]=old;rows.append(row)
  for name in sorted(set(before)-seen):rows.append({"path":name,"missing":True,"original":before[name]})
 # Preserve the current admitted source closure as physical files on failure;
 # comparison remains against the original immutable Git/materializer source.
 source_rows={}
 if SOURCE.is_dir():
  for path in sorted(SOURCE.rglob("*")):
   if path.is_file() and not path.is_symlink():
    name=path.relative_to(SOURCE).as_posix();target=folder/"materialized-source"/name
    target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(path,target)
    source_rows[name]=pin(target)
 put(folder/"DELTA.json",{"schema":"hepta.history.failed-working-copy-delta.v1","status":"RETAINED",
  "capture_entries":rows,"retained_source_files":source_rows,"original_archive_modified":False,
  "original_failure_reclassified_as_pass":False,"native_or_rust_executions":0})
def main():
 p=argparse.ArgumentParser();p.add_argument("--proof",type=Path,required=True)
 p.add_argument("--output",type=Path,required=True);p.add_argument("--index-zip",type=Path,required=True);a=p.parse_args()
 proof=a.proof.absolute();out=a.output.absolute();out.mkdir(mode=0o700,parents=True,exist_ok=False)
 if not (proof/"FINAL.json").is_file():delta(proof,a.index_zip)
 source=proof/"recovery-source";source.mkdir(mode=0o700)
 for path in sorted(HERE.rglob("*")):
  if path.is_file():
   target=source/path.relative_to(HERE);target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(path,target)
 rows=[]
 archive=out/"recovery-evidence.tar.gz"
 with tarfile.open(archive,"w:gz",compresslevel=1,format=tarfile.PAX_FORMAT) as tar:
  for path in [proof,*sorted(proof.rglob("*"))]:
   info=path.lstat();need(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode),"ordinary owned proof entries")
   name="recovery" if path==proof else "recovery/"+path.relative_to(proof).as_posix()
   row={"path":name,"mode":stat.S_IMODE(info.st_mode),"bytes":info.st_size,"type":"file" if path.is_file() else "directory"}
   if path.is_file():row["sha256"]=hash_file(path)
   tar.add(path,arcname=name,recursive=False);need(meta(path.lstat())==meta(info),"proof changed during export")
   rows.append(row)
 manifest={"schema":"hepta.history.recovery-export.v1","status":"COMPLETE",
  "aggregate_recovery_pass":(proof/"FINAL.json").is_file(),"members":rows,
  "archive":{"bytes":archive.stat().st_size,"sha256":hash_file(archive)},"original_artifact":14274528318,
  "original_zip_sha256":"9bb775eccc8fdb92a0eaf5c38021373c76a71ea7430ff43dfdd3636c42bc19b4",
  "original_failure_reclassified_as_pass":False,"native_or_rust_executions":0}
 put(out/"manifest.json",manifest)
 print(json.dumps({"status":manifest["status"],"aggregate_recovery_pass":manifest["aggregate_recovery_pass"],
  "members":len(rows),"archive":manifest["archive"]},sort_keys=True))
if __name__=="__main__":main()
