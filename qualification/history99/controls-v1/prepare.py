#!/usr/bin/env python3
"""Read the whole immutable main99 failure and restore one sealed control subset."""
from __future__ import annotations
import argparse,decimal,gzip,hashlib,json,os,stat,sys,tarfile,time,zipfile
from pathlib import Path
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from index_archive import HashingReader,CHUNK,safe,need,encoded,sha_file,ARTIFACT,RUN,HEAD,ZIP_BYTES,ZIP_SHA
from read_recovered import SOURCE,CAPTURE,REPORT_SHA
INDEX_ZIP={"bytes":97817288,"sha256":"aa8d7e9daae8fa84365d88512780a9c6a45dd4a121fc8124693294da9626a908"}
INDEX={"bytes":13973301,"sha256":"db1f950694c06617428b9aead92b99f8646b32e918ebb442cdb8ec021c571c6e"}
INSPECT_ZIP={"bytes":14695399,"sha256":"17fdf989d82838c70a5bdb08a336b236d1a92ebd7891466395fba59ec7a7ebdd"}
INPUTS={"bytes":2591326,"sha256":"88764bad160c07f3d28a7325a6004e86bd1f9d014ab7c963fe6105e8a0a10569"}
REPORT={"bytes":94615186,"sha256":REPORT_SHA}
TAR={"bytes":27711549440,"sha256":"21ef4d99bc8ba887e6bb358a612c9cb7e9ded04c6a22eba6989d656042358ba8"}
COUNTS={"filesystem":(902,332938503),"regex":(626,624245309)}
def metadata(path):
    v=path.lstat();return [v.st_dev,v.st_ino,v.st_mode,v.st_size,v.st_mtime_ns,v.st_ctime_ns]
def pin(path):
    before=metadata(path);need(stat.S_ISREG(before[2]) and path.resolve()==path.absolute(),"ordinary stable complete input")
    result={"bytes":before[3],"sha256":sha_file(path)}
    need(metadata(path)==before,"input changed during complete hash");return result
def put(path,value):
    with path.open("xb") as f:f.write(encoded(value))
def read(path):return json.loads(path.read_bytes())
def header(item):
    return {"path":safe(item.name.rstrip("/")),"name":item.name,"type":item.type.decode("ascii"),
        "mode":item.mode,"uid":item.uid,"gid":item.gid,"size":item.size,"mtime":item.mtime,
        "linkname":item.linkname,"offset":item.offset,"offset_data":item.offset_data,"pax_headers":item.pax_headers}
def seconds_ns(item,name):
    raw=item.pax_headers.get(name,str(item.mtime))
    return int(decimal.Decimal(raw)*1000000000)
def complete_zip(path,expected):
    need(pin(path)==expected,"entire immutable ZIP")
    rows=[]
    with zipfile.ZipFile(path) as z:
        need(len(z.namelist())==len(set(z.namelist())),"unique ZIP members")
        for item in z.infolist():
            safe(item.filename.rstrip("/"));need(not item.flag_bits&1,"unencrypted member")
            mode=item.external_attr>>16;need(stat.S_IFMT(mode) in (0,stat.S_IFREG,stat.S_IFDIR),"ordinary ZIP member")
            with z.open(item) as f:
                h=hashlib.sha256();size=0
                while block:=f.read(CHUNK):h.update(block);size+=len(block)
            need(size==item.file_size,"complete ZIP member CRC/extent")
            rows.append({"path":item.filename,"bytes":size,"sha256":h.hexdigest(),"mode":mode,"directory":item.is_dir()})
    return rows
def one(z,suffix):
    matches=[n for n in z.namelist() if n.endswith("/"+suffix)]
    need(len(matches)==1,"one exact member "+suffix);return matches[0]
def table(root):
    result={}
    for base,dirs,files in os.walk(root,followlinks=False):
        for n in dirs:need(not (Path(base)/n).is_symlink(),"source directory symlink")
        for n in files:
            path=Path(base)/n
            result[path.relative_to(root).as_posix()]={**pin(path),"mode":stat.S_IMODE(path.stat().st_mode)}
    return result
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--kind",choices=COUNTS,required=True)
    for n in ("zip","metadata","index","inspection","output"):p.add_argument("--"+n,type=Path,required=True)
    a=p.parse_args();start=time.monotonic_ns()
    need(SOURCE.is_dir() and SOURCE.resolve()==SOURCE and not CAPTURE.exists(),"exact fresh historical source and absent capture")
    need(not a.output.exists(),"new preparation directory");a.output.mkdir(mode=0o700,parents=True)
    index_before=metadata(a.index);inspection_before=metadata(a.inspection)
    index_rows=complete_zip(a.index,INDEX_ZIP);inspect_rows=complete_zip(a.inspection,INSPECT_ZIP)
    with zipfile.ZipFile(a.inspection) as iz:
        raw=iz.read(one(iz,"result/CONTROL_INPUTS.json"))
    need({"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}==INPUTS,"frozen actual control input inspection")
    inputs=json.loads(raw)
    need(inputs["status"]=="EXACT_RETAINED_CONTROL_INPUTS_PASS" and inputs["head"]==HEAD
         and inputs["original_report"]==REPORT and inputs["report_status"]=="PASS" and inputs["report_phase"]=="complete"
         and inputs["actual_checks"]==405 and inputs["actual_original_recipes"]==81
         and inputs["native_or_rust_executions"]==0 and inputs["original_failure_reclassified_as_pass"] is False,
         "completed original aggregate and pending-only scope")
    with (a.output/"CONTROL_INPUTS.json").open("xb") as f:f.write(raw)
    source_rows=table(SOURCE);need(source_rows==inputs["materialized_source_files"] and len(source_rows)==2879,
                                  "all exact current99 materialized source bytes and modes")
    for name,digest in inputs["original_source_sha256"].items():
        need(source_rows[name]["sha256"]==digest,"all unchanged original source pins")
    selected=inputs["output_files"][a.kind]
    need(len(selected)==COUNTS[a.kind][0] and sum(x["bytes"] for x in selected.values())==COUNTS[a.kind][1],
         "entire original sealed control input domain")
    old_api=read(a.metadata)
    need(old_api["id"]==ARTIFACT and old_api["workflow_run"]["id"]==RUN and old_api["workflow_run"]["head_sha"]==HEAD
         and old_api["size_in_bytes"]==ZIP_BYTES and old_api["digest"]=="sha256:"+ZIP_SHA
         and old_api["expired"] is False,"immutable original API custody")
    original_before=metadata(a.zip);need(pin(a.zip)=={"bytes":ZIP_BYTES,"sha256":ZIP_SHA},"entire original failed ZIP")
    wanted_dirs={"."}
    for name in selected:
        need(safe(name)==name and name!=".","ordinary sealed capture path")
        wanted_dirs.update(x.as_posix() for x in Path(name).parents if x.as_posix()!=".")
    CAPTURE.mkdir(mode=0o700);directory_rows={};actual_selected={};seen=set();files=dirs=logical=0;outer=[]
    with zipfile.ZipFile(a.index) as iz,zipfile.ZipFile(a.zip) as z:
        index_name=one(iz,"index/tar-index.jsonl.gz")
        with iz.open(index_name) as f, (a.output/"tar-index.jsonl.gz").open("xb") as dst:
            h=hashlib.sha256();size=0
            while block:=f.read(CHUNK):h.update(block);size+=len(block);need(dst.write(block)==len(block),"complete index copy")
        need({"bytes":size,"sha256":h.hexdigest()}==INDEX,"complete original TAR index")
        for name in ("INDEX_PROOF.json","ZIP_INDEX.json","ARTIFACT.json"):
            data=iz.read(one(iz,"index/"+name))
            with (a.output/name).open("xb") as f:f.write(data)
        original_index=read(a.output/"INDEX_PROOF.json")
        need(original_index["status"]=="COMPLETE_BYTE_READBACK_PASS" and original_index["tar"]==TAR
             and original_index["zip"]=={"bytes":ZIP_BYTES,"sha256":ZIP_SHA}
             and original_index["original_artifact"]==ARTIFACT and original_index["original_run"]==RUN
             and original_index["original_head"]==HEAD,"entire original archive index custody")
        need(len(z.namelist())==len(set(z.namelist())) and "failure-evidence.tar" in z.namelist(),"unique original ZIP")
        manifest=json.loads(z.read("manifest.json"))
        need(manifest["status"]=="COMPLETE" and manifest["diagnostics_complete"] is True
             and manifest["archive"]["complete"] is True and manifest["archive"]["exit_code"]==0
             and manifest["archive"]["timed_out"] is False and {k:manifest["archive"]["archive"][k] for k in ("bytes","sha256")}==TAR
             and manifest["source"]==str(CAPTURE) and manifest["original_failure_reclassified_as_pass"] is False,
             "complete original failed archive producer")
        put(a.output/"ORIGINAL_ARCHIVE_MANIFEST.json",manifest)
        with gzip.open(a.output/"tar-index.jsonl.gz","rb") as index, z.open("failure-evidence.tar") as stream:
            whole=HashingReader(stream)
            with tarfile.open(fileobj=whole,mode="r|") as tar:
                for item in tar:
                    line=index.readline();need(bool(line),"index contains every TAR member")
                    expected=json.loads(line);actual=header(item);name=actual["path"]
                    need(name not in seen and (item.isfile() or item.isdir()),"unique ordinary original TAR member");seen.add(name)
                    if item.isdir():
                        dirs+=1
                        if name in wanted_dirs:directory_rows[name]=actual
                    else:
                        source=tar.extractfile(item);need(source is not None,"regular file bytes")
                        path=CAPTURE/name if name in selected else None
                        if path is not None:path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
                        writer=path.open("xb") if path is not None else None;h=hashlib.sha256();n=0
                        try:
                            while block:=source.read(CHUNK):
                                h.update(block);n+=len(block)
                                if writer is not None:need(writer.write(block)==len(block),"full physical capture copy")
                        finally:
                            if writer is not None:writer.close()
                        need(n==item.size,"complete original member extent")
                        actual["data"]={"bytes":n,"sha256":h.hexdigest()};files+=1;logical+=n
                        if path is not None:
                            identity={**actual["data"],"mode":item.mode}
                            need(identity=={k:selected[name][k] for k in ("bytes","sha256","mode")},"all selected actual bytes/modes match seals")
                            need(actual==inputs["original_tar_records"][name],"selected full header matches separate inspection")
                            path.chmod(item.mode)
                            os.utime(path,ns=(seconds_ns(item,"atime"),seconds_ns(item,"mtime")),follow_symlinks=False)
                            actual_selected[name]=identity
                    need(actual==expected,"every original header/full bytes equal fixed index: "+name)
            while whole.read(CHUNK):pass
            need({"bytes":whole.count,"sha256":whole.sha.hexdigest()}==TAR,"whole original TAR including padding")
            need(index.readline()==b"","all indexed rows consumed")
        expected_outer={r["path"]:r for r in read(a.output/"ZIP_INDEX.json")["entries"]}
        for item in z.infolist():
            need(item.filename in expected_outer,"all original ZIP members indexed")
            if item.is_dir():continue
            if item.filename=="failure-evidence.tar":v=TAR
            else:
                h=hashlib.sha256();n=0
                with z.open(item) as f:
                    while block:=f.read(CHUNK):h.update(block);n+=len(block)
                v={"bytes":n,"sha256":h.hexdigest()}
            need(v=={k:expected_outer[item.filename][k] for k in ("bytes","sha256")},"every complete outer ZIP byte")
            outer.append({"path":item.filename,**v})
        need(set(expected_outer)==set(z.namelist()),"exact complete outer ZIP member set")
    need(files==153488 and dirs==26800 and len(seen)==180288 and logical==27390413778,"complete original capture domain")
    need(set(actual_selected)==set(selected) and set(directory_rows)==wanted_dirs,"all complete sealed subset files and parents")
    for name,row in sorted(directory_rows.items(),key=lambda x:len(Path(x[0]).parts),reverse=True):
        path=CAPTURE if name=="." else CAPTURE/name;path.chmod(row["mode"])
    need(metadata(a.zip)==original_before and metadata(a.index)==index_before and metadata(a.inspection)==inspection_before,
         "all supplied archives unchanged")
    need(table(CAPTURE)==actual_selected and table(SOURCE)==source_rows,"every physical restored input reopened")
    need(pin(CAPTURE/"result.json")==REPORT,"all completed original report bytes preserved")
    original=read(CAPTURE/"result.json")
    need(original["status"]=="PASS" and original["phase"]=="complete" and len(original["checks"])==405
         and len(original["original_rust_comparisons"])==81,"original aggregate result remains unchanged")
    sealed={name:row["sha256"] for name,row in selected.items() if name!="result.json"}
    value={"schema":"hepta.history99.control-input-continuation.v1","status":"COMPLETE_SEALED_INPUT_SUBSET_PASS",
      "kind":a.kind,"source":str(SOURCE),"capture":str(CAPTURE),"source_files":source_rows,"output_files":actual_selected,
      "sealed_source_subset":inputs["filesystem_sources"] if a.kind=="filesystem" else None,
      "sealed_artifact_subset":sealed,"original_report":REPORT,"original_api":old_api,
      "original_zip":{"bytes":ZIP_BYTES,"sha256":ZIP_SHA},"original_tar":TAR,
      "original_files":files,"original_directories":dirs,"original_logical_bytes":logical,
      "complete_zip_members":outer,"index_zip":INDEX_ZIP,"index_members":index_rows,"index":INDEX,
      "inspection_zip":INSPECT_ZIP,"inspection_members":inspect_rows,"input_inspection":INPUTS,
      "source_pins_rebound":False,"subset_only":True,"native_or_rust_executions":0,"full_aggregate_reexecuted":False,
      "original_workflow_status":"FAILURE","completed_aggregate_status":"PASS",
      "original_failure_reclassified_as_pass":False,"elapsed_ns":time.monotonic_ns()-start}
    put(a.output/"PREPARATION.json",value)
    print(json.dumps({k:v for k,v in value.items() if k not in ("source_files","output_files","sealed_source_subset",
      "sealed_artifact_subset","original_api","complete_zip_members","index_members","inspection_members")},sort_keys=True))
if __name__=="__main__":main()
