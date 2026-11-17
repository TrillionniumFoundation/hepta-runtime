"""Pure complete archive inspection of one immutable failed qualification."""
import argparse,hashlib,io,json,os,stat,tarfile,zipfile
from pathlib import Path
ZIP_SHA="e4155afc8e547b293a8a9a9e27d60500ad257f783fbe808edaf3440520c0720e"
ZIP_BYTES=37203922
TAR_SHA="c940b6d0cdd22e6c48b02173dc32ec9ea8ac259ba5988b046e6f9bd58c36912a"
TAR_BYTES=37203029
SOURCE_SHA="925dede1dfdd747371c7101ad3cb7a2075e59c57d6326312737c71098ff9ecbf"
HEAD="a30d3e93185e84ee2a0e8c4abbdcc0d23177676a"
def enc(x):return (json.dumps(x,sort_keys=True,indent=2,allow_nan=False)+"\n").encode()
def check(x,m):
    if not x:raise ValueError(m)
def pin(x):return {"bytes":len(x),"sha256":hashlib.sha256(x).hexdigest()}
def pairs(xs):
    d={}
    for k,v in xs:
        check(k not in d,"duplicate JSON key");d[k]=v
    return d
def loads(x):return json.loads(x,object_pairs_hook=pairs)
def run(archive,output):
    output.mkdir(parents=True,exist_ok=False)
    raw=archive.read_bytes();check(pin(raw)==dict(bytes=ZIP_BYTES,sha256=ZIP_SHA),"complete original ZIP")
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        check(len(z.infolist())==2,"ZIP exact two entries")
        names=z.namelist();check(len(names)==len(set(names)),"unique ZIP paths")
        check(set(names)=={"audit-pinned-anchor-v1.tar.gz","audit-pinned-anchor-v1.tar.gz.json"},"ZIP original names")
        tar=z.read("audit-pinned-anchor-v1.tar.gz");side=z.read("audit-pinned-anchor-v1.tar.gz.json")
    check(pin(tar)==dict(bytes=TAR_BYTES,sha256=TAR_SHA),"full TAR gzip identity")
    side_value=loads(side)
    check(side_value["sha256"]==TAR_SHA and side_value["bytes"]==TAR_BYTES and side_value["status"]=="NO_FINAL_GATE","original failure exporter report")
    objects={};members={};manifest_raw=None
    with tarfile.open(fileobj=io.BytesIO(tar),mode="r:gz") as tf:
        for m in tf:
            check(m.isfile() and m.name not in members and 0<=m.mode<=0o7777,"unique ordinary TAR member")
            body=tf.extractfile(m).read();check(len(body)==m.size,"full TAR member")
            members[m.name]=dict(**pin(body),mode=m.mode)
            if m.name=="artifact-manifest.json":manifest_raw=body
            else:
                check(m.name=="objects/"+members[m.name]["sha256"]+"-"+format(m.mode,"03o"),"content-addressed exact object path")
                objects[m.name]=body
    check(manifest_raw is not None,"complete artifact manifest")
    manifest=loads(manifest_raw);check(manifest["git_head"]==HEAD and str(manifest["run_id"])=="44074543111","exact original producer")
    check(manifest["source_manifest_sha256"]==SOURCE_SHA and manifest["gate"]=={"status":"NO_FINAL_GATE"},"source and failed gate remain")
    referenced=set();total=0
    for path,row in manifest["files"].items():
        p=Path(path);check(not p.is_absolute() and ".." not in p.parts and p.parts[0] in ("source","run"),"ordinary logical path")
        check(row["object"] in objects and members[row["object"]]=={k:row[k] for k in ("bytes","sha256","mode")},"every whole logical byte/mode")
        referenced.add(row["object"]);total+=row["bytes"]
    check(referenced==set(objects),"no unreferenced object")
    check(len(manifest["files"])==2771 and total==191105463 and len(objects)==2457,"complete failure totals")
    source_raw=objects[manifest["files"]["source/SOURCE.json"]["object"]]
    check(hashlib.sha256(source_raw).hexdigest()==SOURCE_SHA,"full frozen original source manifest")
    source=loads(source_raw)
    check({p[7:] for p in manifest["files"] if p.startswith("source/")}==set(source["files"])|{"SOURCE.json"},"all frozen source files")
    for p,row in source["files"].items():
        body=objects[manifest["files"]["source/"+p]["object"]]
        check(pin(body)=={k:row[k] for k in ("bytes","sha256")},"frozen source whole bytes")
        check(hashlib.sha1(b"blob "+str(len(body)).encode()+b"\0"+body).hexdigest()==row["git_blob"],"frozen source Git identity")
    (output/"artifact-manifest.json").write_bytes(manifest_raw)
    (output/"original-export.json").write_bytes(side)
    selected={}
    for path,row in manifest["files"].items():
        take=path in ("run/semantic.stderr","run/semantic.stdout","run/producer.stdout","run/producer.stderr")
        take=take or path.startswith("run/reader-processes/semantic/")
        take=take or (path.startswith("run/semantic/") and (path.endswith("/report.json") or path.endswith("/SUMMARY.json")) and row["bytes"]<200000)
        if take:
            body=objects[row["object"]];target=output/"selected"/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(body);os.chmod(target,row["mode"])
            selected[path]=dict(row)
            if row["bytes"]<80000:
                try:text=body.decode("utf-8")
                except UnicodeError:continue
                print("SELECTED_BEGIN "+path,flush=True);print(text,end="" if text.endswith("\n") else "\n",flush=True);print("SELECTED_END "+path,flush=True)
    report=dict(status="COMPLETE_FAILED_ARCHIVE_READ_PASS",producer_status="FAIL",zip=pin(raw),tar=pin(tar),logical_files=len(manifest["files"]),logical_bytes=total,
        unique_objects=len(objects),source_files=len(source["files"])+1,source_manifest_sha256=SOURCE_SHA,selected=selected,native_executions=0,rust_executions=0,
        original_evidence_mutated=False,physical_controls_executed=False)
    (output/"INSPECTION.json").write_bytes(enc(report));print(enc(report).decode())
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--archive",type=Path,required=True);p.add_argument("--output",type=Path,required=True);a=p.parse_args();run(a.archive,a.output)
