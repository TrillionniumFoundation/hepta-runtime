#!/usr/bin/env python3
"""Restore only the already fully indexed 08ce bytes at their recorded root."""
from __future__ import annotations
import argparse, decimal, gzip, hashlib, json, os, shutil, stat, sys, tarfile, time, zipfile
from pathlib import Path
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from index_archive import ARTIFACT,RUN,HEAD,ZIP_BYTES,ZIP_SHA,CHUNK,HashingReader,safe,need,encoded,sha_file

INDEX_ARTIFACT=14276342887
INDEX_RUN=43966941226
INDEX_HEAD="96e40e59c2b9b42475840832b76b68c9dfa653a6"
INDEX_BYTES=90869688
INDEX_SHA="a0f581904dba96b2959da711542fded9f716e03c54d71ff924e737fbb5ae2a37"
INDEX_MEMBER="history-aggregate-index/tar-index.jsonl.gz"
INDEX_MEMBER_SHA="ad4d01ef4fa926526bc0483a6160d0d9453e8529b8b2c770fe03d2345c3edf40"
TAR_SHA="39018cbe9b4c829a55fb564b39d4ed5ad4963be5969c2e5a05ebc7302fa19a3d"
TAR_BYTES=27227545600
FILES=151622
DIRECTORIES=26653
LOGICAL_BYTES=26910012457
DESTINATION=Path("/home/runner/work/_temp/hia-runtime-native")

def artifact(value,*,identity,run,head,size,digest):
    need(value["id"]==identity and value["workflow_run"]["id"]==run
         and value["workflow_run"]["head_sha"]==head and value["size_in_bytes"]==size
         and value["digest"]=="sha256:"+digest and value["expired"] is False,"immutable API artifact identity")

def verify_zip(path,size,digest):
    before=path.lstat();need(stat.S_ISREG(before.st_mode) and before.st_size==size,"regular exact ZIP")
    need(sha_file(path)==digest,"complete ZIP SHA256")
    return [before.st_dev,before.st_ino,before.st_mode,before.st_size,before.st_mtime_ns,before.st_ctime_ns]

def metadata(path):
    v=path.lstat();return [v.st_dev,v.st_ino,v.st_mode,v.st_size,v.st_mtime_ns,v.st_ctime_ns]

def header(item):
    return {"path":safe(item.name.rstrip("/")),"name":item.name,"type":item.type.decode("ascii"),
        "mode":item.mode,"uid":item.uid,"gid":item.gid,"size":item.size,"mtime":item.mtime,
        "linkname":item.linkname,"offset":item.offset,"offset_data":item.offset_data,"pax_headers":item.pax_headers}

def seconds_ns(item,name):
    raw=item.pax_headers.get(name,str(item.mtime))
    return int(decimal.Decimal(raw)*1000000000)

def main():
    p=argparse.ArgumentParser();p.add_argument("--zip",type=Path,required=True)
    p.add_argument("--metadata",type=Path,required=True);p.add_argument("--index-zip",type=Path,required=True)
    p.add_argument("--index-metadata",type=Path,required=True);p.add_argument("--proof",type=Path,required=True)
    a=p.parse_args();started=time.monotonic_ns();need(not a.proof.exists(),"create-only proof")
    original=json.loads(a.metadata.read_bytes());indexed=json.loads(a.index_metadata.read_bytes())
    artifact(original,identity=ARTIFACT,run=RUN,head=HEAD,size=ZIP_BYTES,digest=ZIP_SHA)
    artifact(indexed,identity=INDEX_ARTIFACT,run=INDEX_RUN,head=INDEX_HEAD,size=INDEX_BYTES,digest=INDEX_SHA)
    original_before=verify_zip(a.zip,ZIP_BYTES,ZIP_SHA)
    index_before=verify_zip(a.index_zip,INDEX_BYTES,INDEX_SHA)
    need(not DESTINATION.exists() and not DESTINATION.is_symlink(),"recorded restoration root must be absent")
    need(DESTINATION.parent.resolve(strict=True)==DESTINATION.parent,"non-aliased recorded parent")
    need(shutil.disk_usage(DESTINATION.parent).free>LOGICAL_BYTES+(1<<30),"insufficient complete-restore free space")
    dirs=[];files=0;logical=0;seen=set();tar_digest=None;manifest=None
    DESTINATION.mkdir(mode=0o700)
    with zipfile.ZipFile(a.index_zip) as index_archive,zipfile.ZipFile(a.zip) as archive:
        need(len(index_archive.namelist())==len(set(index_archive.namelist())),"unique index ZIP entries")
        need(len(archive.namelist())==len(set(archive.namelist())),"unique original ZIP entries")
        need(sum(n=="failure-evidence.tar" for n in archive.namelist())==1,"one original TAR")
        info=index_archive.getinfo(INDEX_MEMBER)
        with index_archive.open(info) as source:
            h=hashlib.sha256()
            while block:=source.read(CHUNK):h.update(block)
        need(h.hexdigest()==INDEX_MEMBER_SHA,"complete retained member index")
        manifest=json.loads(archive.read("manifest.json"))
        need(manifest["status"]=="COMPLETE" and manifest["diagnostics_complete"] is True
             and manifest["archive"]["complete"] is True and manifest["archive"]["exit_code"]==0
             and manifest["archive"]["timed_out"] is False
             and manifest["archive"]["archive"]["sha256"]==TAR_SHA
             and manifest["archive"]["archive"]["bytes"]==TAR_BYTES
             and manifest["source"]==str(DESTINATION),"original archive custody")
        with index_archive.open(INDEX_MEMBER) as packed, gzip.GzipFile(fileobj=packed,mode="rb") as index:
            with archive.open("failure-evidence.tar") as raw:
                whole=HashingReader(raw)
                with tarfile.open(fileobj=whole,mode="r|") as retained:
                    for item in retained:
                        line=index.readline();need(bool(line),"TAR exceeds complete frozen index")
                        expected=json.loads(line);actual=header(item);name=actual["path"]
                        need(name not in seen,"duplicate TAR path");seen.add(name)
                        need(item.isdir() or item.isfile(),"this indexed capture contains only regular files/directories")
                        path=DESTINATION if name=="." else DESTINATION/name
                        need(path.parent.resolve(strict=True)==path.parent,"non-aliased existing TAR parent")
                        if item.isdir():
                            if name!=".":path.mkdir(mode=0o700)
                            dirs.append((path,item.mode,seconds_ns(item,"atime"),seconds_ns(item,"mtime")))
                        else:
                            need(name!=".","regular root forbidden")
                            need(not path.exists() and not path.is_symlink(),"create-only regular evidence")
                            reader=retained.extractfile(item);need(reader is not None,"regular data missing")
                            h=hashlib.sha256();n=0
                            with path.open("xb") as target:
                                while block:=reader.read(CHUNK):target.write(block);h.update(block);n+=len(block)
                            need(n==item.size,"short complete member")
                            actual["data"]={"bytes":n,"sha256":h.hexdigest()}
                            path.chmod(item.mode)
                            os.utime(path,ns=(seconds_ns(item,"atime"),seconds_ns(item,"mtime")),follow_symlinks=False)
                            files+=1;logical+=n
                        need(actual==expected,"full indexed header/bytes changed: "+repr(name))
                while whole.read(CHUNK):pass
                tar_digest={"bytes":whole.count,"sha256":whole.sha.hexdigest()}
            need(index.readline()==b"","omitted complete indexed member")
        need(tar_digest=={"bytes":TAR_BYTES,"sha256":TAR_SHA},"full TAR stream identity")
        # All other ZIP entries are fully CRC/hash-read too, without materializing
        # their diagnostic duplicates into the original evidence root.
        outer=[]
        for item in archive.infolist():
            if item.is_dir():continue
            if item.filename=="failure-evidence.tar":
                outer.append({"path":item.filename,**tar_digest});continue
            h=hashlib.sha256();n=0
            with archive.open(item) as f:
                while block:=f.read(CHUNK):h.update(block);n+=len(block)
            need(n==item.file_size,"short ZIP diagnostic")
            outer.append({"path":item.filename,"bytes":n,"sha256":h.hexdigest()})
    for path,mode,atime,mtime in reversed(dirs):
        path.chmod(mode);os.utime(path,ns=(atime,mtime),follow_symlinks=False)
    need(files==FILES and len(dirs)==DIRECTORIES and logical==LOGICAL_BYTES,"full original extent accounting")
    need(metadata(a.zip)==original_before and metadata(a.index_zip)==index_before,"input ZIP modified")
    # Reopen every actual restored byte and mode against the full retained index.
    with zipfile.ZipFile(a.index_zip) as archive,archive.open(INDEX_MEMBER) as packed,gzip.GzipFile(fileobj=packed,mode="rb") as f:
        observed=0
        for line in f:
            row=json.loads(line);path=DESTINATION if row["path"]=="." else DESTINATION/row["path"];st=path.lstat()
            need(stat.S_IMODE(st.st_mode)==row["mode"],"restored complete mode")
            need(path.resolve()==path,"restored path alias")
            if row["type"]=="0":
                need(stat.S_ISREG(st.st_mode) and st.st_size==row["data"]["bytes"]
                     and sha_file(path)==row["data"]["sha256"],"restored full file bytes")
            else:need(stat.S_ISDIR(st.st_mode),"restored directory type")
            observed+=1
    need(observed==FILES+DIRECTORIES,"restored complete member count")
    result={"schema":"hepta.history.aggregate.restoration.v1","status":"COMPLETE_RESTORED_BYTES_AND_MODES_PASS",
        "original_artifact":original,"index_artifact":indexed,"original_zip":original_before,"index_zip":index_before,
        "tar":tar_digest,"root":str(DESTINATION),"files":files,"directories":len(dirs),"logical_bytes":logical,
        "zip_members":outer,"original_failure_reclassified_as_pass":False,"source_pins_rebound":False,
        "original_report_modified":False,"native_or_rust_executions":0,"restored_inode_identity_claimed":False,
        "retained_original_pax_metadata_unchanged":True,"elapsed_ns":time.monotonic_ns()-started,
        "pid":os.getpid(),"parent_pid":os.getppid(),"pgid":os.getpgrp()}
    a.proof.parent.mkdir(parents=True,exist_ok=True)
    with a.proof.open("xb") as f:f.write(encoded(result))
    print(json.dumps({k:v for k,v in result.items() if k not in ("original_artifact","index_artifact","zip_members")},sort_keys=True))
if __name__=="__main__":main()
