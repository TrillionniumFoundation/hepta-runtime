"""Pure complete archive inspection of one immutable actual publisher capture."""
import argparse,hashlib,io,json,os,stat,tarfile,zipfile
from pathlib import Path
ZIP_SHA="29830657b6ef987e2532452e9ef2738b0a7e2ec4fede7632314ac6ee85c4e2d8"
ZIP_BYTES=131469788
TAR_SHA="6123bf6139e32b4ab0723899f3807cc6e455fb9007593d176a5113eab6ec6368"
TAR_BYTES=131468889
SOURCE_SHA="5108ee26b26723f601207fe15fa849f6b4f07b80aa0b752574792062c49010a9"
HEAD="d4edc3afee461bf41b63ceb6938bb6be0bd074b1"
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
        check(set(names)=={"audit-anchor-publish-v1.tar.gz","audit-anchor-publish-v1.tar.gz.json"},"ZIP original names")
        tar=z.read("audit-anchor-publish-v1.tar.gz");side=z.read("audit-anchor-publish-v1.tar.gz.json")
    check(pin(tar)==dict(bytes=TAR_BYTES,sha256=TAR_SHA),"full TAR gzip identity")
    side_value=loads(side)
    check(side_value["sha256"]==TAR_SHA and side_value["bytes"]==TAR_BYTES and side_value["status"]=="NO_FINAL_GATE","original pending-reader exporter report")
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
    manifest=loads(manifest_raw);check(manifest["git_head"]==HEAD and str(manifest["run_id"])=="44083816910","exact original producer")
    check(manifest["source_manifest_sha256"]==SOURCE_SHA and manifest["gate"]=={"status":"NO_FINAL_GATE"},"source and pending-reader gate remain")
    referenced=set();total=0
    for path,row in manifest["files"].items():
        p=Path(path);check(not p.is_absolute() and ".." not in p.parts and p.parts[0] in ("source","run"),"ordinary logical path")
        check(row["object"] in objects and members[row["object"]]=={k:row[k] for k in ("bytes","sha256","mode")},"every whole logical byte/mode")
        referenced.add(row["object"]);total+=row["bytes"]
    check(referenced==set(objects),"no unreferenced object")
    check(len(manifest["files"])==3969 and total==723566982 and len(objects)==3523,"whole original producer totals")
    source_raw=objects[manifest["files"]["source/SOURCE.json"]["object"]]
    check(hashlib.sha256(source_raw).hexdigest()==SOURCE_SHA,"full frozen original source manifest")
    source=loads(source_raw)
    check({p[7:] for p in manifest["files"] if p.startswith("source/")}==set(source["files"])|{"SOURCE.json"},"all frozen source files")
    for p,row in source["files"].items():
        body=objects[manifest["files"]["source/"+p]["object"]]
        check(pin(body)=={k:row[k] for k in ("bytes","sha256")},"frozen source whole bytes")
        check(hashlib.sha1(b"blob "+str(len(body)).encode()+b"\0"+body).hexdigest()==row["git_blob"],"frozen source Git identity")
    restored=output/"prior"
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
    report=dict(status="COMPLETE_PRODUCER_ARCHIVE_RESTORE_PASS",producer_status="PRODUCERS_PASS_READBACK_PENDING",zip=pin(raw),tar=pin(tar),
        logical_files=len(manifest["files"]),logical_bytes=total,unique_objects=len(objects),
        source_files=len(source["files"])+1,source_manifest_sha256=SOURCE_SHA,
        original_evidence_mutated=False,native_executions=0,rust_executions=0)
    (output/"RESTORE.json").write_bytes(enc(report))
    print(enc(report).decode(),end="")
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--archive",type=Path,required=True);p.add_argument("--output",type=Path,required=True);a=p.parse_args();run(a.archive,a.output)
