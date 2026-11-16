#!/usr/bin/env python3
"""Read every byte of one immutable failed aggregate; execute no implementation."""
from __future__ import annotations
import argparse, gzip, hashlib, json, os, stat, tarfile, time, zipfile
from pathlib import Path, PurePosixPath

ARTIFACT = 14274528318
RUN = 43944061609
HEAD = "08ce7b6fdfda64aa382e3238a1547c5e379f156a"
ZIP_BYTES = 4386065194
ZIP_SHA = "9bb775eccc8fdb92a0eaf5c38021373c76a71ea7430ff43dfdd3636c42bc19b4"
CHUNK = 1 << 20

def encoded(v):
    return (json.dumps(v, ensure_ascii=True, sort_keys=True, indent=2, allow_nan=False)+"\n").encode()

def sha_file(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f,"sha256").hexdigest()

def need(value, label):
    if not value:
        raise ValueError(label)

def safe(name):
    need(type(name) is str and name and not name.startswith("/"), "absolute/empty member")
    raw = name.removeprefix("./")
    if raw in ("", "."):
        return "."
    p = PurePosixPath(raw)
    need(all(part not in ("", ".", "..") for part in raw.split("/")), "unsafe component: "+repr(name))
    need(str(p)==raw, "noncanonical member: "+repr(name))
    return raw

class HashingReader:
    def __init__(self, f):
        self.f=f; self.sha=hashlib.sha256(); self.count=0
    def read(self,n=-1):
        raw=self.f.read(n); self.sha.update(raw); self.count+=len(raw); return raw

def stream_pin(reader, destination=None):
    h=hashlib.sha256(); size=0
    while True:
        raw=reader.read(CHUNK)
        if not raw: break
        h.update(raw);size+=len(raw)
        if destination is not None: destination.write(raw)
    return {"bytes":size,"sha256":h.hexdigest()}

def put(path,v):
    with path.open("xb") as f: f.write(encoded(v))

def main():
    p=argparse.ArgumentParser(); p.add_argument("--zip",type=Path,required=True)
    p.add_argument("--metadata",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args(); started=time.monotonic_ns(); output=a.output.absolute()
    output.mkdir(mode=0o700,parents=True,exist_ok=False); (output/"selected").mkdir(mode=0o700)
    metadata=json.loads(a.metadata.read_bytes())
    need(metadata["id"]==ARTIFACT and metadata["workflow_run"]["id"]==RUN
         and metadata["workflow_run"]["head_sha"]==HEAD and metadata["expired"] is False
         and metadata["size_in_bytes"]==ZIP_BYTES
         and metadata["digest"]=="sha256:"+ZIP_SHA, "GitHub artifact identity changed")
    before=a.zip.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_size==ZIP_BYTES,"ZIP is not exact regular file")
    need(sha_file(a.zip)==ZIP_SHA,"complete ZIP digest changed")
    zip_rows=[]; tar_rows=0; data_bytes=0; hardlinks=0; symlinks=0; dirs=0; special=[]
    names=set(); member_pins={}; selected=[]; tar_pin=None
    with zipfile.ZipFile(a.zip) as archive:
        infos=archive.infolist()
        need(len(infos)==len({v.filename for v in infos}),"duplicate ZIP entry")
        need(sum(v.filename=="failure-evidence.tar" for v in infos)==1,"one complete TAR required")
        outer_manifest=json.loads(archive.read("manifest.json"))
        need(outer_manifest["status"]=="COMPLETE" and outer_manifest["diagnostics_complete"] is True
             and outer_manifest["archive"]["complete"] is True
             and outer_manifest["archive"]["exit_code"]==0
             and outer_manifest["archive"]["timed_out"] is False
             and outer_manifest["original_failure_reclassified_as_pass"] is False,
             "archive producer did not record complete failed evidence")
        expected_tar=outer_manifest["archive"]["archive"]
        for info in infos:
            name=safe(info.filename.rstrip("/"))
            row={"path":info.filename,"bytes":info.file_size,"compressed_bytes":info.compress_size,
                 "crc":info.CRC,"external_attr":info.external_attr,"compression":info.compress_type}
            if info.is_dir():
                need(info.file_size==0,"nonempty ZIP directory");zip_rows.append(row);continue
            need(stat.S_IFMT(info.external_attr>>16) in (0,stat.S_IFREG),"nonregular ZIP entry")
            if name=="failure-evidence.tar":
                with archive.open(info) as raw:
                    whole=HashingReader(raw)
                    with gzip.open(output/"tar-index.jsonl.gz","xb",compresslevel=1) as index:
                        with tarfile.open(fileobj=whole,mode="r|") as retained:
                            for item in retained:
                                key=safe(item.name.rstrip("/"))
                                need(key not in names,"duplicate TAR entry: "+repr(key));names.add(key)
                                record={"path":key,"name":item.name,"type":item.type.decode("ascii"),
                                    "mode":item.mode,"uid":item.uid,"gid":item.gid,"size":item.size,
                                    "mtime":item.mtime,"linkname":item.linkname,
                                    "offset":item.offset,"offset_data":item.offset_data,
                                    "pax_headers":item.pax_headers}
                                if item.isfile():
                                    reader=retained.extractfile(item);need(reader is not None,"missing regular data")
                                    record["data"]=stream_pin(reader)
                                    need(record["data"]["bytes"]==item.size,"short TAR member")
                                    member_pins[key]=record["data"];data_bytes+=item.size
                                elif item.islnk():
                                    target=safe(item.linkname)
                                    need(target in member_pins,"hardlink target not prior regular file")
                                    record["data"]=member_pins[target];member_pins[key]=record["data"];hardlinks+=1
                                elif item.issym():symlinks+=1
                                elif item.isdir():dirs+=1
                                else:special.append({"path":key,"type":record["type"]})
                                index.write(json.dumps(record,ensure_ascii=True,sort_keys=True,allow_nan=False).encode()+b"\n")
                                tar_rows+=1
                    while whole.read(CHUNK):pass
                    tar_pin={"bytes":whole.count,"sha256":whole.sha.hexdigest()}
                need(tar_pin["bytes"]==info.file_size==expected_tar["bytes"]
                     and tar_pin["sha256"]==expected_tar["sha256"],"complete TAR digest changed")
                row.update(tar_pin)
            else:
                keep=name.endswith(".json")
                dest=output/"selected"/name if keep else None
                if dest is not None:
                    dest.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
                    with archive.open(info) as reader, dest.open("xb") as writer:
                        identity=stream_pin(reader,writer)
                    selected.append({"path":name,**identity})
                else:
                    with archive.open(info) as reader:identity=stream_pin(reader)
                need(identity["bytes"]==info.file_size,"short ZIP entry")
                row.update(identity)
            zip_rows.append(row)
    after=a.zip.lstat()
    need((before.st_dev,before.st_ino,before.st_mode,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==
         (after.st_dev,after.st_ino,after.st_mode,after.st_size,after.st_mtime_ns,after.st_ctime_ns),
         "ZIP changed during full read")
    put(output/"ZIP_INDEX.json",{"schema":"hepta.history.aggregate.zip-index.v1","entries":zip_rows})
    put(output/"ARTIFACT.json",metadata)
    result={"schema":"hepta.history.aggregate.full-index.v1","status":"COMPLETE_BYTE_READBACK_PASS",
        "original_run":RUN,"original_head":HEAD,"original_artifact":ARTIFACT,
        "original_aggregate_status":"FAILURE","original_failure_reclassified_as_pass":False,
        "zip":{"bytes":ZIP_BYTES,"sha256":ZIP_SHA},"tar":tar_pin,
        "tar_index":{"path":"tar-index.jsonl.gz","bytes":(output/"tar-index.jsonl.gz").stat().st_size,
                     "sha256":sha_file(output/"tar-index.jsonl.gz"),"entries":tar_rows},
        "regular_member_bytes":data_bytes,"directories":dirs,"hardlinks":hardlinks,"symlinks":symlinks,
        "special_members":special,"selected_json":selected,
        "pid":os.getpid(),"parent_pid":os.getppid(),"pgid":os.getpgrp(),
        "elapsed_ns":time.monotonic_ns()-started,"semantic_executions":0,
        "original_evidence_modified":False,"tar_members_materialized":False,
        "new_qualification_inferred_from_archive":False}
    put(output/"INDEX_PROOF.json",result)
    print(json.dumps({k:v for k,v in result.items() if k!="selected_json"},sort_keys=True))
if __name__=="__main__":main()
