#!/usr/bin/env python3
"""Admit the complete retained index and derive the exact two control input sets."""
from __future__ import annotations
import argparse,gzip,hashlib,json,os,stat,time,zipfile
from pathlib import Path,PurePosixPath
INDEX_ZIP={"bytes":97817288,"sha256":"aa8d7e9daae8fa84365d88512780a9c6a45dd4a121fc8124693294da9626a908"}
ORIGINAL_ZIP={"bytes":4393597000,"sha256":"7e7401e56dce43db85a904b1e4196922960f2fecc1ba3375b14b52a4b969f379"}
INDEX={"bytes":13973301,"sha256":"db1f950694c06617428b9aead92b99f8646b32e918ebb442cdb8ec021c571c6e"}
TAR={"bytes":27711549440,"sha256":"21ef4d99bc8ba887e6bb358a612c9cb7e9ded04c6a22eba6989d656042358ba8"}
HEAD="99d107c062a6eb3f226dd82b05283aeecbd3c495"
def need(v,s):
    if not v:raise ValueError(s)
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+"\n").encode()
def unique(items):
    v={}
    for k,x in items:need(k not in v,"duplicate JSON field");v[k]=x
    return v
def read_json(raw):return json.loads(raw,object_pairs_hook=unique)
def identity(stream,output=None):
    h=hashlib.sha256();n=0
    while raw:=stream.read(1<<20):
        h.update(raw);n+=len(raw)
        if output is not None:need(output.write(raw)==len(raw),"short complete copy")
    return {"bytes":n,"sha256":h.hexdigest()}
def pin(path):
    before=path.lstat();need(stat.S_ISREG(before.st_mode),"ordinary input")
    with path.open("rb") as f:v=identity(f)
    after=path.lstat()
    need(tuple(getattr(before,k) for k in ("st_dev","st_ino","st_mode","st_size","st_mtime_ns","st_ctime_ns"))==
         tuple(getattr(after,k) for k in ("st_dev","st_ino","st_mode","st_size","st_mtime_ns","st_ctime_ns")),"stable input")
    return v
def safe(s):
    p=PurePosixPath(s)
    need(type(s)is str and s and not p.is_absolute() and str(p)==s and all(x not in ("",".","..") for x in s.split("/")),"canonical relative path")
    return s
def put(path,v):
    with path.open("xb") as f:f.write(encoded(v))
def source_files(root):
    result={}
    for base,dirs,files in os.walk(root,followlinks=False):
        for name in dirs:need(not (Path(base)/name).is_symlink(),"source directory symlink")
        for name in files:
            path=Path(base)/name;need(not path.is_symlink(),"source file symlink")
            result[path.relative_to(root).as_posix()]={**pin(path),"mode":stat.S_IMODE(path.stat().st_mode)}
    return result
def main():
    p=argparse.ArgumentParser();p.add_argument("--zip",type=Path,required=True)
    p.add_argument("--source",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();start=time.monotonic_ns();a.output.mkdir(mode=0o700,parents=True,exist_ok=False)
    need(pin(a.zip)==INDEX_ZIP,"complete fixed index artifact ZIP")
    rows=[];saved={};original_report=None
    with zipfile.ZipFile(a.zip) as z:
        names=[x.filename for x in z.infolist()]
        need(len(names)==len(set(names)),"unique complete index ZIP")
        for item in z.infolist():
            name=safe(item.filename.rstrip("/"));mode=item.external_attr>>16
            need(not item.flag_bits&1 and stat.S_IFMT(mode) in (0,stat.S_IFREG,stat.S_IFDIR),"ordinary unencrypted ZIP entry")
            with z.open(item) as f:v=identity(f)
            need(v["bytes"]==item.file_size,"complete ZIP member")
            rows.append({"path":item.filename,"mode":mode,"directory":item.is_dir(),**v})
        def one(suffix):
            matches=[x for x in names if x.endswith("/"+suffix)]
            need(len(matches)==1,"one retained member "+suffix);return matches[0]
        proof=read_json(z.read(one("index/INDEX_PROOF.json")))
        need(proof["status"]=="COMPLETE_BYTE_READBACK_PASS" and proof["zip"]==ORIGINAL_ZIP and proof["tar"]==TAR
             and proof["original_head"]==HEAD and proof["original_artifact"]==14308317195
             and proof["original_run"]==44023379853 and proof["original_workflow_status"]=="FAILURE"
             and proof["completed_aggregate_status"]=="PASS" and proof["semantic_executions"]==0
             and proof["original_failure_reclassified_as_pass"] is False,"exact original full read receipt")
        need({k:proof["tar_index"][k] for k in ("bytes","sha256")}==INDEX and proof["tar_index"]["entries"]==180288,
             "exact complete original TAR index")
        name=one("index/selected/diagnostics/result.json")
        raw=z.read(name);report=read_json(raw)
        report_pin={"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
        matching=[x for x in proof["selected_json"] if x["path"]=="diagnostics/result.json"]
        need(len(matching)==1 and {k:matching[0][k] for k in ("bytes","sha256")}==report_pin,"diagnostic original report seal")
        need(report["status"]=="PASS" and len(report["checks"])==405 and len(report["original_rust_comparisons"])==81,
             "completed aggregate retained exactly")
        with (a.output/"original-result.json").open("xb") as f:f.write(raw)
        fs_parts=[report["filesystem_parity_evidence"],report["filesystem_parity_fixture_retirement"],
                  report["original_rust_comparisons"]["filesystem_parity"]]
        config=report["original_rust_comparisons"]["runtime_config"]
        regex_parts=[report["config_evidence"],config["configuration"],config["regex"]]
        tables={}
        for kind,parts in (("filesystem",fs_parts),("regex",regex_parts)):
            result={}
            for part in parts:
                for key,digest in part["artifact_sha256"].items():
                    safe(key);need(type(digest)is str and len(digest)==64,"artifact digest")
                    if key in result:need(result[key]==digest,"overlapping artifact seals differ")
                    result[key]=digest
            result["result.json"]=report_pin["sha256"];tables[kind]=result
        wanted=set().union(*(set(t) for t in tables.values()))
        records={};count=0;regular=0;directories=0;logical=0
        index_name=one("index/tar-index.jsonl.gz")
        raw_index=z.read(index_name)
        need({"bytes":len(raw_index),"sha256":hashlib.sha256(raw_index).hexdigest()}==INDEX,"whole compressed TAR index")
        with gzip.open(__import__("io").BytesIO(raw_index),"rb") as stream:
            for line in stream:
                row=read_json(line);count+=1
                if row["type"]=="0":regular+=1;logical+=row["size"]
                elif row["type"]=="5":directories+=1
                else:raise ValueError("unexpected original TAR member type")
                if row["path"] in wanted:need(row["path"] not in records,"unique selected index path");records[row["path"]]=row
        need(count==180288 and directories==26800 and logical==27390413778,"complete index member domain")
        need(set(records)==wanted,"all sealed control inputs retained")
        for kind,table in tables.items():
            for name,digest in table.items():
                row=records[name];need(row["type"]=="0" and row["data"]["sha256"]==digest and row["size"]==row["data"]["bytes"],
                                      "original complete artifact bytes "+name)
        need(records["result.json"]["data"]==report_pin,"TAR and diagnostic original report identical")
    source_root=a.source.resolve(strict=True)
    all_source=source_files(source_root)
    for name,digest in report["source_sha256"].items():
        safe(name);need(name in all_source and all_source[name]["sha256"]==digest,"complete original source pin "+name)
    fs_sources=report["filesystem_parity_evidence"]["source_sha256"]
    for name,digest in fs_sources.items():need(all_source[name]["sha256"]==digest,"filesystem original source")
    identities={kind:{name:{**records[name]["data"],"mode":records[name]["mode"],"mtime":records[name]["mtime"],
                           "pax_headers":records[name]["pax_headers"]} for name in sorted(table)}
                for kind,table in tables.items()}
    value={"schema":"hepta.history99.control-input-inspection.v1","status":"EXACT_RETAINED_CONTROL_INPUTS_PASS",
           "head":HEAD,"index_artifact":INDEX_ZIP,"original_zip":ORIGINAL_ZIP,"original_tar":TAR,
           "original_report":report_pin,"report_status":report["status"],"report_phase":report.get("phase"),
           "actual_checks":len(report["checks"]),"actual_original_recipes":len(report["original_rust_comparisons"]),
           "source_root":str(source_root),"original_source_sha256":report["source_sha256"],
           "materialized_source_files":all_source,"filesystem_sources":fs_sources,
           "output_files":identities,"original_tar_records":records,
           "complete_index_files":rows,"index_entries":count,"regular_files":regular,
           "directories":directories,"original_report_preserved":True,"native_or_rust_executions":0,
           "original_failure_reclassified_as_pass":False,"elapsed_ns":time.monotonic_ns()-start}
    put(a.output/"CONTROL_INPUTS.json",value)
    summary={k:v for k,v in value.items() if k not in ("original_source_sha256","materialized_source_files",
             "filesystem_sources","output_files","original_tar_records","complete_index_files")}
    summary["source_pin_count"]=len(report["source_sha256"]);summary["source_files"]=len(all_source)
    summary["filesystem_source_count"]=len(fs_sources)
    summary["subset_counts"]={k:len(v) for k,v in identities.items()}
    summary["subset_bytes"]={k:sum(x["bytes"] for x in v.values()) for k,v in identities.items()}
    summary["control_sources"]={name:all_source[name] for name in (
        "tests/hia_native/filesystem_parity/qualify_pipeline.py",
        "scripts/hia_native_filesystem_parity_qualification.py","tests/hia_native/check_regex_evidence.py")}
    summary["control_inputs_pin"]=pin(a.output/"CONTROL_INPUTS.json")
    put(a.output/"SUMMARY.json",summary);print(json.dumps(summary,sort_keys=True))
if __name__=="__main__":main()
