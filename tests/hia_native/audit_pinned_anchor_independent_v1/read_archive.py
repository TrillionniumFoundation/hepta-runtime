"""Complete immutable uploaded ZIP/TAR restoration, never invoke a native image."""
from pathlib import Path
import argparse,hashlib,io,json,os,stat,tarfile,zipfile
ROOT=Path(__file__).resolve().parent
def check(x,m):
    if not x:raise ValueError(m)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def enc(x):return (json.dumps(x,sort_keys=True,indent=2,allow_nan=False)+"\n").encode()
def pairs(xs):
    d={}
    for k,v in xs:check(k not in d,"duplicate JSON key");d[k]=v
    return d
def loads(b):return json.loads(b,object_pairs_hook=pairs)
def regular(path):
    info=path.lstat();check(stat.S_ISREG(info.st_mode),"ordinary complete retained file")
    with path.open("rb") as s:
        before=os.fstat(s.fileno());raw=s.read();after=os.fstat(s.fileno())
    check((info.st_dev,info.st_ino)==(before.st_dev,before.st_ino) and
          (before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_size,after.st_mtime_ns,after.st_ctime_ns) and len(raw)==after.st_size,"stable full read")
    return raw
def files(root):
    result={}
    for folder,dirs,names in os.walk(root,followlinks=False):
        for n in dirs:check(stat.S_ISDIR((Path(folder)/n).lstat().st_mode),"no aliased directory")
        for n in names:
            p=Path(folder)/n;result[p.relative_to(root).as_posix()]=dict(**pin(regular(p)),mode=stat.S_IMODE(p.lstat().st_mode))
    return result
def source_files(root,expected):
    raw=regular(root/"SOURCE.json");check(pin(raw)["sha256"]==expected,"exact frozen source manifest")
    m=loads(raw);check(set(files(root))==set(m["files"])|{"SOURCE.json"},"exact source file set")
    for name,row in m["files"].items():
        body=regular(root/name);check(pin(body)=={k:row[k] for k in ("bytes","sha256")} and
            hashlib.sha1(b"blob "+str(len(body)).encode()+b"\0"+body).hexdigest()==row["git_blob"],"full source SHA and Git blob")
    return len(m["files"])+1
def restore(archive,destination,receipt):
    fixed=loads(regular(ROOT/"TARGET.json"));raw=regular(archive);check(pin(raw)==fixed["zip"],"whole immutable uploaded ZIP")
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        check(len(z.infolist())==2 and set(z.namelist())=={fixed["tar_name"],fixed["tar_name"]+".json"},"exact uploaded file set")
        body=z.read(fixed["tar_name"]);side=z.read(fixed["tar_name"]+".json")
    exported=loads(side);check(pin(body)=={k:exported[k] for k in ("bytes","sha256")} and exported["status"]=="PASS","complete uploaded TAR gzip and success exporter")
    objects={};members={};manifest_raw=None
    with tarfile.open(fileobj=io.BytesIO(body),mode="r:gz") as tar:
        for member in tar:
            check(member.isfile() and member.name not in members and 0<=member.mode<=0o7777,"unique regular TAR object")
            data=tar.extractfile(member).read();check(len(data)==member.size,"whole TAR member")
            members[member.name]=dict(**pin(data),mode=member.mode)
            if member.name=="artifact-manifest.json":manifest_raw=data
            else:
                check(member.name=="objects/"+pin(data)["sha256"]+"-"+format(member.mode,"03o"),"exact content-addressed path")
                objects[member.name]=data
    check(manifest_raw is not None,"complete logical manifest")
    manifest=loads(manifest_raw)
    check(manifest["schema"]=="hepta.audit-pinned-anchor.recovery-archive.v1" and manifest["git_head"]==fixed["head"] and
        str(manifest["run_id"])==str(fixed["run"]) and manifest["source_manifest_sha256"]==fixed["recovery_source_sha256"] and
        manifest["gate"]["status"]=="PASS" and manifest["gate"]["prior_status"]=="FAIL","exact source/producer/successor qualification")
    used=set()
    destination.mkdir(parents=True,exist_ok=False)
    for name,row in manifest["files"].items():
        p=Path(name);check(not p.is_absolute() and ".." not in p.parts and p.parts[0] in ("recovery-source","restored","recovery-run"),"ordinary complete logical path")
        check(members.get(row["object"])=={k:row[k] for k in ("bytes","sha256","mode")},"every logical object and mode")
        used.add(row["object"]);target=destination/name;target.parent.mkdir(parents=True,exist_ok=True)
        with target.open("xb") as out:out.write(objects[row["object"]])
        target.chmod(row["mode"])
    check(used==set(objects),"complete object closure")
    check(files(destination)=={n:{k:r[k] for k in ("bytes","sha256","mode")} for n,r in manifest["files"].items()},"every restored logical byte and mode")
    old=loads(regular(destination/"restored/artifact-manifest.json"))
    old_expected={n:{k:r[k] for k in ("bytes","sha256","mode")} for n,r in old["files"].items()}
    check(files(destination/"restored/prior")==old_expected and len(old_expected)==2771 and sum(r["bytes"] for r in old_expected.values())==191105463,"all original failed evidence preserved")
    source_count=source_files(destination/"restored/prior/source",fixed["original_source_sha256"])+source_files(destination/"recovery-source",fixed["recovery_source_sha256"])
    logical_bytes=sum(r["bytes"] for r in manifest["files"].values())
    check(len(manifest["files"])==exported["logical_files"] and logical_bytes==exported["logical_bytes"] and len(objects)==exported["unique_objects"],"complete exporter totals independently re-read")
    result=dict(status="COMPLETE_UPLOADED_ANCHOR_ARCHIVE_READ_PASS",zip=pin(raw),tar=pin(body),logical_files=len(manifest["files"]),
        logical_bytes=logical_bytes,unique_objects=len(objects),exact_original_files=len(old_expected),source_files=source_count,
        manifest=pin(manifest_raw),source_manifest_sha256=fixed["recovery_source_sha256"],native_executions=0,rust_executions=0)
    receipt.write_bytes(enc(result));receipt.with_name("uploaded-manifest.json").write_bytes(manifest_raw)
    print(enc(result).decode(),end="")
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--archive",type=Path,required=True);p.add_argument("--destination",type=Path,required=True);p.add_argument("--receipt",type=Path,required=True);a=p.parse_args();restore(a.archive,a.destination,a.receipt)
