#!/usr/bin/env python3
"""Read the complete original ZIP/TAR/index, restoring only the sealed config/regex inputs."""
from __future__ import annotations
import argparse,decimal,gzip,hashlib,json,os,stat,sys,tarfile,time,zipfile
from pathlib import Path
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from index_archive import HashingReader,CHUNK,safe,need,encoded,sha_file,ARTIFACT,RUN,HEAD,ZIP_BYTES,ZIP_SHA
from restore_archive import artifact,verify_zip,metadata,header,seconds_ns
SOURCE=Path("/home/runner/work/_temp/hia-historical-public58")
CAPTURE=Path("/home/runner/work/_temp/hia-runtime-native")
REPORT={"bytes":94614535,"sha256":"6159169d8c0763d2418c8f625e5cd67099a06179f69927f7a1e62972a1eafa41"}
INDEX_BYTES=90869688
INDEX_SHA="a0f581904dba96b2959da711542fded9f716e03c54d71ff924e737fbb5ae2a37"
INDEX_MEMBER="history-aggregate-index/tar-index.jsonl.gz"
INDEX_MEMBER_SHA="ad4d01ef4fa926526bc0483a6160d0d9453e8529b8b2c770fe03d2345c3edf40"
TAR={"bytes":27227545600,"sha256":"39018cbe9b4c829a55fb564b39d4ed5ad4963be5969c2e5a05ebc7302fa19a3d"}
def pin(path):
    info=path.lstat();need(stat.S_ISREG(info.st_mode) and path.resolve()==path.absolute(),"ordinary complete input")
    old=metadata(path);result={"bytes":info.st_size,"sha256":sha_file(path)}
    need(metadata(path)==old,"complete input stable");return result
def read(path):return json.loads(path.read_bytes())
def put(path,value):
    with path.open("xb") as f:f.write(encoded(value))
def copy_file(src,dst,row):
    need(pin(src)=={k:row[k] for k in ("bytes","sha256")},"exact retained source before copying")
    dst.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    with src.open("rb") as incoming,dst.open("xb") as outgoing:
        while block:=incoming.read(CHUNK):outgoing.write(block)
    dst.chmod(row["mode"])
    need(pin(dst)=={k:row[k] for k in ("bytes","sha256")},"entire new source copy")
def main():
    parser=argparse.ArgumentParser();parser.add_argument("--readback",type=Path,required=True)
    parser.add_argument("--zip",type=Path,required=True);parser.add_argument("--metadata",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True);args=parser.parse_args();start=time.monotonic_ns()
    need(not SOURCE.exists() and not CAPTURE.exists() and not args.output.exists(),"new exact recorded source/capture/receipt")
    archive_read=read(args.readback/"COMPLETE_READBACK.json")
    need(archive_read["status"]=="COMPLETE_ARCHIVE_BYTES_AND_GIT_SOURCES_PASS" and archive_read["kind"]=="filesystem"
         and archive_read["zip"]=={"bytes":210134590,"sha256":"fa523a6a9fcf2420253dd186754669fbb973160b585aee8ae38d06013eecb9cb"},
         "complete filesystem continuation archive admitted")
    home=args.readback/"proof";fs_prep=read(home/"proof/PREPARATION.json")
    need(fs_prep["status"]=="COMPLETE_SEALED_INPUT_SUBSET_PASS"
         and fs_prep["source"]==str(SOURCE) and len(fs_prep["source_files"])==2877,"exact materialized original source")
    report_path=home/"filesystem-input/result.json";need(pin(report_path)==REPORT,"full failed original report")
    report=read(report_path);need(report["status"]=="FAIL","original failure remains")
    tables=[report["config_evidence"]["artifact_sha256"],
            report["original_rust_comparisons"]["runtime_config"]["configuration"]["artifact_sha256"],
            report["original_rust_comparisons"]["runtime_config"]["regex"]["artifact_sha256"]]
    selected={}
    for table in tables:
        need(type(table)is dict and table,"complete existing config/regex seal")
        for name,digest in table.items():
            need(safe(name)==name and name!="." and type(digest)is str and len(digest)==64,"ordinary sealed file")
            need(name not in selected or selected[name]==digest,"no conflicting source seals")
            selected[name]=digest
    need("result.json" not in selected,"failed report separately bound")
    selected["result.json"]=REPORT["sha256"]
    original_api=read(args.metadata)
    artifact(original_api,identity=ARTIFACT,run=RUN,head=HEAD,size=ZIP_BYTES,digest=ZIP_SHA)
    original_before=verify_zip(args.zip,ZIP_BYTES,ZIP_SHA)
    index_path=home/"proof/original-index.zip";index_before=verify_zip(index_path,INDEX_BYTES,INDEX_SHA)
    SOURCE.mkdir(mode=0o700);CAPTURE.mkdir(mode=0o700)
    hs=home/"historical-source"
    for path in sorted(hs.rglob("*"),key=lambda p:len(p.parts)):
        if path.is_dir():(SOURCE/path.relative_to(hs)).mkdir(mode=0o700,parents=True,exist_ok=True)
    source_rows=fs_prep["source_files"]
    for name,row in source_rows.items():
        need(safe(name)==name and name!=".","ordinary source")
        copy_file(home/"historical-source"/name,SOURCE/name,row)
    wanted_dirs={"."}
    for name in selected:
        wanted_dirs.update(p.as_posix() for p in Path(name).parents if p.as_posix()!=".")
    actual_selected={};directory_rows={};seen=set();files=logical=dirs=0;outer=[]
    with zipfile.ZipFile(index_path) as iz,zipfile.ZipFile(args.zip) as z:
        need(len(z.namelist())==len(set(z.namelist())) and "failure-evidence.tar" in z.namelist(),"unique complete original ZIP")
        with iz.open(INDEX_MEMBER) as f:
            need(hashlib.file_digest(f,"sha256").hexdigest()==INDEX_MEMBER_SHA,"whole original TAR index")
        manifest=json.loads(z.read("manifest.json"))
        need(manifest["status"]=="COMPLETE" and manifest["diagnostics_complete"] is True
             and manifest["archive"]["complete"] is True and manifest["archive"]["exit_code"]==0
             and manifest["archive"]["timed_out"] is False and {k:manifest["archive"]["archive"][k] for k in ("bytes","sha256")}==TAR
             and manifest["source"]==str(CAPTURE),"complete original archive custody")
        with iz.open(INDEX_MEMBER) as packed,gzip.GzipFile(fileobj=packed,mode="rb") as index:
            with z.open("failure-evidence.tar") as raw:
                whole=HashingReader(raw)
                with tarfile.open(fileobj=whole,mode="r|") as tar:
                    for item in tar:
                        line=index.readline();need(bool(line),"complete index length")
                        expected=json.loads(line);actual=header(item);name=actual["path"]
                        need(name not in seen and (item.isdir() or item.isfile()),"unique ordinary indexed member")
                        seen.add(name)
                        if item.isdir():
                            dirs+=1
                            if name in wanted_dirs:directory_rows[name]=actual
                        else:
                            reader=tar.extractfile(item);need(reader is not None,"regular member bytes")
                            target=None;path=None
                            if name in selected:
                                path=CAPTURE/name;path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
                                target=path.open("xb")
                            h=hashlib.sha256();count=0
                            try:
                                while block:=reader.read(CHUNK):
                                    h.update(block);count+=len(block)
                                    if target is not None:target.write(block)
                            finally:
                                if target is not None:target.close()
                            need(count==item.size,"complete file extent")
                            actual["data"]={"bytes":count,"sha256":h.hexdigest()}
                            files+=1;logical+=count
                            if name in selected:
                                need(h.hexdigest()==selected[name],"actual bytes match all original config/regex seals")
                                path.chmod(item.mode)
                                os.utime(path,ns=(seconds_ns(item,"atime"),seconds_ns(item,"mtime")),follow_symlinks=False)
                                actual_selected[name]={**actual["data"],"mode":item.mode}
                        need(actual==expected,"every complete original header/file equals sealed index: "+name)
                while whole.read(CHUNK):pass
                need({"bytes":whole.count,"sha256":whole.sha.hexdigest()}==TAR,"complete original TAR including padding")
            need(index.readline()==b"","all original indexed rows consumed")
        for item in z.infolist():
            if item.is_dir():continue
            if item.filename=="failure-evidence.tar":outer.append({"path":item.filename,**TAR});continue
            with z.open(item) as f:
                h=hashlib.sha256();count=0
                while block:=f.read(CHUNK):h.update(block);count+=len(block)
            need(count==item.file_size,"whole ZIP diagnostic extent")
            outer.append({"path":item.filename,"bytes":count,"sha256":h.hexdigest()})
    need(files==151622 and dirs==26653 and len(seen)==178275 and logical==26910012457,"whole original capture read")
    need(set(actual_selected)==set(selected) and set(directory_rows)==wanted_dirs,"no missing sealed input or parent directory")
    for name,row in sorted(directory_rows.items(),key=lambda pair:len(Path(pair[0]).parts),reverse=True):
        path=CAPTURE if name=="." else CAPTURE/name;path.chmod(row["mode"])
    # Source directory modes are preserved from the fully verified retained source.
    hs=home/"historical-source"
    for path in sorted([hs,*hs.rglob("*")],key=lambda p:len(p.parts),reverse=True):
        if path.is_dir():(SOURCE/path.relative_to(hs)).chmod(stat.S_IMODE(path.lstat().st_mode))
    need(metadata(args.zip)==original_before and metadata(index_path)==index_before,"original ZIP inputs unchanged")
    for name,row in actual_selected.items():
        need(pin(CAPTURE/name)=={k:row[k] for k in ("bytes","sha256")},"all actual restored subset bytes reopened")
    need({p.relative_to(CAPTURE).as_posix() for p in CAPTURE.rglob("*") if p.is_file()}==set(selected),"no extra restored input")
    value={"schema":"hepta.history.regex-control-input-continuation.v1","status":"COMPLETE_SEALED_INPUT_SUBSET_PASS",
      "source":str(SOURCE),"capture":str(CAPTURE),"source_files":source_rows,"output_files":actual_selected,
      "sealed_artifact_tables":tables,"original_report":REPORT,"original_api":original_api,
      "original_zip":{"bytes":ZIP_BYTES,"sha256":ZIP_SHA},"original_tar":TAR,
      "original_files":files,"original_directories":dirs,"original_logical_bytes":logical,
      "complete_zip_members":outer,"original_index":{"bytes":INDEX_BYTES,"sha256":INDEX_SHA},
      "complete_index_sha256":INDEX_MEMBER_SHA,"source_pins_rebound":False,
      "subset_only":True,"native_or_rust_executions":0,"full_aggregate_reexecuted":False,
      "original_failure_reclassified_as_pass":False,"elapsed_ns":time.monotonic_ns()-start}
    put(args.output,value)
    print(json.dumps({k:v for k,v in value.items() if k not in ("source_files","output_files","sealed_artifact_tables","complete_zip_members","original_api")},sort_keys=True))
if __name__=="__main__":main()
