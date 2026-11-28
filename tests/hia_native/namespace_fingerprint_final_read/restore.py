"""Complete immutable ZIP/TAR restoration with full logical readback, no code execution."""
from pathlib import Path
import argparse,hashlib,io,json,os,stat,tarfile,zipfile
def enc(x):return (json.dumps(x,sort_keys=True,indent=2,allow_nan=False)+"\n").encode()
def require(x,m):
    if not x:raise ValueError(m)
def pin(x):return dict(bytes=len(x),sha256=hashlib.sha256(x).hexdigest())
def pairs(rows):
    out={}
    for k,v in rows:
        require(k not in out,"duplicate JSON field");out[k]=v
    return out
def loads(raw):return json.loads(raw,object_pairs_hook=pairs)
def read(path):
    st=path.lstat();require(stat.S_ISREG(st.st_mode),"whole ordinary file")
    with path.open("rb") as stream:
        opened=os.fstat(stream.fileno());require((st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns)==
            (opened.st_dev,opened.st_ino,opened.st_size,opened.st_mtime_ns,opened.st_ctime_ns),"same opened whole file")
        raw=stream.read();after=os.fstat(stream.fileno())
        require((opened.st_size,opened.st_mtime_ns,opened.st_ctime_ns)==(after.st_size,after.st_mtime_ns,after.st_ctime_ns)
            and len(raw)==st.st_size,"stable complete file")
    return raw
def run(archive,output,pins):
    binding=loads(read(pins));raw=read(archive);require(pin(raw)==binding["zip"],"complete immutable uploaded ZIP bytes")
    output.mkdir(parents=True,exist_ok=False);name=binding["tar_name"]
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        require(len(z.infolist())==2 and set(z.namelist())=={name,name+".json"},"exact complete uploaded ZIP members")
        tar=z.read(name);side=z.read(name+".json")
    require(pin(tar)==binding["tar"],"complete immutable uploaded TAR bytes")
    s=loads(side);require(s["sha256"]==binding["tar"]["sha256"] and s["bytes"]==binding["tar"]["bytes"] and s["status"]==binding["status"],"whole exporter receipt")
    objects={};members={};meta=None
    with tarfile.open(fileobj=io.BytesIO(tar),mode="r:gz") as tf:
        for entry in tf:
            require(entry.isfile() and entry.name not in members and 0<=entry.mode<=0o7777,"unique ordinary retained object")
            with tf.extractfile(entry) as stream:body=stream.read()
            require(len(body)==entry.size,"complete TAR member")
            row=dict(**pin(body),mode=entry.mode);members[entry.name]=row
            if entry.name=="artifact-manifest.json":meta=body
            else:
                require(entry.name=="objects/"+row["sha256"]+"-"+format(row["mode"],"03o"),"content-addressed exact object")
                objects[entry.name]=body
    require(meta is not None,"entire frozen archive manifest")
    m=loads(meta);require(m["schema"]==binding["archive_schema"] and m["git_head"]==binding["head"] and
                         str(m["run_id"])==str(binding["run"]) and m["source_manifest_sha256"]==binding["source_sha256"] and
                         m["gate"]["status"]==binding["status"],"same exact source/run and original gate")
    selected=set();total=0;seen=set()
    root=output/"complete";root.mkdir()
    for name,row in m["files"].items():
        path=Path(name)
        require(type(name) is str and not path.is_absolute() and ".." not in path.parts and path.parts and path.parts[0] in binding["roots"] and path.as_posix()==name and
                set(row)=={"bytes","sha256","mode","object"} and row["object"] in objects and
                members[row["object"]]=={k:row[k] for k in ("bytes","sha256","mode")},"every complete logical path/byte/mode")
        selected.add(row["object"]);total+=row["bytes"];target=root/path;target.parent.mkdir(parents=True,exist_ok=True)
        with target.open("xb") as stream:stream.write(objects[row["object"]])
        target.chmod(row["mode"])
    require(selected==set(objects) and len(m["files"])==binding["logical_files"] and total==binding["logical_bytes"] and
            len(objects)==binding["unique_objects"],"entire frozen logical domain without omission")
    reread={}
    for folder,dirs,names in os.walk(root,followlinks=False):
        for n in dirs:require(stat.S_ISDIR((Path(folder)/n).lstat().st_mode),"ordinary restored directories")
        for n in names:
            p=Path(folder)/n;reread[p.relative_to(root).as_posix()]=dict(**pin(read(p)),mode=stat.S_IMODE(p.lstat().st_mode))
    require(reread=={n:{k:r[k] for k in ("bytes","sha256","mode")} for n,r in m["files"].items()},"every restored logical byte and mode reread")
    for path,expected in binding["source_manifests"].items():
        b=read(root/path);require(pin(b)==expected,"whole retained source manifest")
        sm=loads(b);folder=(root/path).parent
        actual={n[len(str(folder.relative_to(root)))+1:]:v for n,v in reread.items() if n.startswith(str(folder.relative_to(root))+"/")}
        require(set(actual)==set(sm["files"])|{"SOURCE.json"},"whole retained source domain")
        for n,r in sm["files"].items():
            b=read(folder/n);require(pin(b)=={k:r[k] for k in ("bytes","sha256")} and
                hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest()==r["git_blob"],"every retained source Git byte")
    (output/"artifact-manifest.json").write_bytes(meta);(output/"exporter.json").write_bytes(side)
    report=dict(status="FULL_UPLOADED_FINGERPRINT_ARCHIVE_READ_PASS",zip=pin(raw),tar=pin(tar),logical_files=len(reread),logical_bytes=total,
                unique_objects=len(objects),all_bytes_and_modes=True,all_git_source_members=True,native_executions=0,rust_executions=0)
    (output/"RESTORE.json").write_bytes(enc(report));print(enc(report).decode(),end="")
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--archive",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    p.add_argument("--pins",type=Path,required=True);a=p.parse_args();run(a.archive,a.output,a.pins)
