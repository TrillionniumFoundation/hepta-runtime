"""Pure complete archive inspection of one immutable actual fingerprint capture."""
import argparse,hashlib,io,json,os,stat,tarfile,zipfile
from pathlib import Path
ZIP_SHA="2a6ae5b85d69b233ef5e7a30b9dbef6ef844b84628ab1bbb48ff47e08737da3e"
ZIP_BYTES=44901777
TAR_SHA="66075963eed7f974cf851b3b07de8d5ed53f3fbb0e0d5ea386b8002a963ec971"
TAR_BYTES=44900853
SOURCE_SHA="d2f3509e90b4fed41e3769430ff54d143fc698c43598ac55ff2bd07a4c9c6762"
HEAD="71d087ba0d0fb2a085685c56b8c65aabb7c37a5f"
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
        check(set(names)=={"fingerprint-controls.tar.gz","fingerprint-controls.tar.gz.json"},"ZIP original names")
        tar=z.read("fingerprint-controls.tar.gz");side=z.read("fingerprint-controls.tar.gz.json")
    check(pin(tar)==dict(bytes=TAR_BYTES,sha256=TAR_SHA),"full TAR gzip identity")
    side_value=loads(side)
    check(side_value["sha256"]==TAR_SHA and side_value["bytes"]==TAR_BYTES and side_value["status"]=="FINGERPRINT_SEMANTIC_AND_ABI_CONTROLS_PASS","original pending-reader exporter report")
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
    manifest=loads(manifest_raw);check(manifest["git_head"]==HEAD and str(manifest["run_id"])=="44120921363","exact original producer")
    check(manifest["source_manifest_sha256"]==SOURCE_SHA and manifest["gate"]["status"]=="FINGERPRINT_SEMANTIC_AND_ABI_CONTROLS_PASS","source and pending-reader gate remain")
    referenced=set();total=0
    for path,row in manifest["files"].items():
        p=Path(path);check(not p.is_absolute() and ".." not in p.parts and p.parts[0] in ("control-source","restored","control-run"),"ordinary logical path")
        check(row["object"] in objects and members[row["object"]]=={k:row[k] for k in ("bytes","sha256","mode")},"every whole logical byte/mode")
        referenced.add(row["object"]);total+=row["bytes"]
    check(referenced==set(objects),"no unreferenced object")
    check(len(manifest["files"])==3046 and total==295742756 and len(objects)==2677,"whole original producer totals")
    source_raw=objects[manifest["files"]["control-source/SOURCE.json"]["object"]]
    check(hashlib.sha256(source_raw).hexdigest()==SOURCE_SHA,"full frozen original source manifest")
    source=loads(source_raw)
    check({p[len("control-source/"):] for p in manifest["files"] if p.startswith("control-source/")}==set(source["files"])|{"SOURCE.json"},"all frozen source files")
    for p,row in source["files"].items():
        body=objects[manifest["files"]["control-source/"+p]["object"]]
        check(pin(body)=={k:row[k] for k in ("bytes","sha256")},"frozen source whole bytes")
        check(hashlib.sha1(b"blob "+str(len(body)).encode()+b"\0"+body).hexdigest()==row["git_blob"],"frozen source Git identity")
    restored=output/"retained"
    restored.mkdir()
    for name,row in manifest["files"].items():
        target=restored/name;target.parent.mkdir(parents=True,exist_ok=True)
        with target.open("xb") as out:out.write(objects[row["object"]])
        target.chmod(row["mode"])
    reread={}
    for folder,dirs,names in os.walk(restored,followlinks=False):
        for name in dirs:check(stat.S_ISDIR((Path(folder)/name).lstat().st_mode),"restored ordinary directory")
        for name in names:
            path=Path(folder)/name;info=path.lstat();check(stat.S_ISREG(info.st_mode),"restored ordinary file")
            reread[path.relative_to(restored).as_posix()]=dict(**pin(path.read_bytes()),mode=stat.S_IMODE(info.st_mode))
    check(reread=={n:{k:r[k] for k in ("bytes","sha256","mode")} for n,r in manifest["files"].items()},"every restored logical byte and mode")
    (output/"artifact-manifest.json").write_bytes(manifest_raw)
    (output/"original-export.json").write_bytes(side)
    report=dict(status="COMPLETE_FINGERPRINT_CONTROL_ARCHIVE_RESTORE_PASS",producer_status="FINGERPRINT_SEMANTIC_AND_ABI_CONTROLS_PASS",zip=pin(raw),tar=pin(tar),
        logical_files=len(manifest["files"]),logical_bytes=total,unique_objects=len(objects),
        source_files=len(source["files"])+1,source_manifest_sha256=SOURCE_SHA,
        original_evidence_mutated=False,native_executions=0,rust_executions=0)
    (output/"RESTORE.json").write_bytes(enc(report))
    print(enc(report).decode(),end="")
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--archive",type=Path,required=True);p.add_argument("--output",type=Path,required=True);a=p.parse_args();run(a.archive,a.output)
