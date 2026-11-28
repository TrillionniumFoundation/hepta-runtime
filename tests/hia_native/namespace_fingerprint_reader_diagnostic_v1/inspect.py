"""Inspect every immutable producer archive byte, then expose exact retained diagnostics."""
from pathlib import Path
import argparse,hashlib,io,json,tarfile,zipfile
ZIP={"bytes":42043704,"sha256":"056d39e25b64afea10ec6908d5e95b36302cafe42adb623bea3afb6f1017386c"}
TAR={"bytes":42042801,"sha256":"1b7598baa8efbdbf56c99a0e0bab2ea548992e8cfc3b7c753a0b611c81925fba"}
HEAD="f5faf5d8b772d94ca877e4c89b10a542de7e9eaa"
SOURCE="682909fbec91ce42d145ebe8ee55c6943d385f1113b9ad25f03d9c3f694bf320"
def require(v,m):
    if not v:raise ValueError(m)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+"\n").encode()
def load(raw):
    def pairs(xs):
        result={}
        for k,v in xs:require(k not in result,"unique JSON member");result[k]=v
        return result
    return json.loads(raw,object_pairs_hook=pairs)
def run(path,out):
    out.mkdir(parents=True,exist_ok=False);raw=path.read_bytes();require(pin(raw)==ZIP,"entire exact failed ZIP")
    with zipfile.ZipFile(io.BytesIO(raw))as z:
        require(z.namelist()==list(dict.fromkeys(z.namelist())) and set(z.namelist())==
            {"namespace-fingerprint-v2.tar.gz","namespace-fingerprint-v2.tar.gz.json"},"two exact original ZIP names")
        tar=z.read("namespace-fingerprint-v2.tar.gz");side=z.read("namespace-fingerprint-v2.tar.gz.json")
    require(pin(tar)==TAR,"complete failed TAR");sidevalue=load(side)
    require({k:sidevalue[k]for k in("bytes","sha256")}==TAR and sidevalue["all_objects_and_modes_reread"]is True,"actual retained exporter")
    members={};bodies={}
    with tarfile.open(fileobj=io.BytesIO(tar),mode="r:gz")as tf:
        for m in tf:
            require(m.isfile()and m.name not in members,"unique complete ordinary member")
            body=tf.extractfile(m).read();require(len(body)==m.size,"complete member extent")
            members[m.name]=dict(**pin(body),mode=m.mode);bodies[m.name]=body
            if m.name!="artifact-manifest.json":
                require(m.name=="objects/"+pin(body)["sha256"]+"-"+format(m.mode,"03o"),"exact content-addressed object")
    manifest=load(bodies["artifact-manifest.json"])
    require(manifest["git_head"]==HEAD and str(manifest["run_id"])=="44113846570"and manifest["source_manifest_sha256"]==SOURCE,"exact failed source and producer")
    referenced=set();logical={}
    for name,row in manifest["files"].items():
        p=Path(name);require(not p.is_absolute()and".."not in p.parts and p.parts[0]in("source","run"),"safe exact logical path")
        require(members[row["object"]]=={k:row[k]for k in("bytes","sha256","mode")},"every original file/mode")
        logical[name]=bodies[row["object"]];referenced.add(row["object"])
    require(referenced==set(members)-{"artifact-manifest.json"}and len(logical)==2987 and sum(map(len,logical.values()))==281537377,"whole failed logical closure")
    require(pin(logical["source/SOURCE.json"])["sha256"]==SOURCE,"entire producer source manifest")
    src=load(logical["source/SOURCE.json"])
    require({n[7:]for n in logical if n.startswith("source/")}==set(src["files"])|{"SOURCE.json"},"complete frozen source set")
    for name,row in src["files"].items():
        body=logical["source/"+name]
        require(pin(body)=={k:row[k]for k in("bytes","sha256")}and hashlib.sha1(b"blob "+str(len(body)).encode()+b"\0"+body).hexdigest()==row["git_blob"],"complete source Git blob")
    for name in ("artifact-manifest.json",):(out/name).write_bytes(bodies[name])
    (out/"original-export.json").write_bytes(side)
    selected={n:body for n,body in logical.items()if n in("run/producer.stdout","run/producer.stderr",
        "run/semantic/processes/processes.json","run/semantic/paired-ordinary/PAIRED.json",
        "run/semantic/paired-ordinary/roles/native-observed/capture/NATIVE.json",
        "run/semantic/paired-ordinary/roles/native-observed/capture/CONTEXTS.json",
        "run/semantic/paired-ordinary/roles/original/PROCESS.json")}
    m=load(logical["run/semantic/CAPTURE.json"]);m.pop("files",None)
    selected["derived/CAPTURE-METADATA.json"]=encoded(m)
    trace=logical["run/semantic/paired-ordinary.strace"].decode();segments=[]
    lines=trace.splitlines();active=None
    begins=tuple("".join("\\x%02x"%x for x in tag)for tag in(b"NFNATB01",b"NFORGB01"))
    ends=tuple("".join("\\x%02x"%x for x in tag)for tag in(b"NFNATE01",b"NFORGE01"))
    for line in lines:
        if active is None and any(x in line for x in begins)and len(segments)<3:active=[line]
        elif active is not None:
            active.append(line)
            if any(x in line for x in ends):segments.append(active);active=None
    selected["derived/FIRST-THREE-OPERATIONS.json"]=encoded(segments)
    selected["derived/ORDINARY-NEGATIVE-GETDENTS.json"]=encoded([
        line for line in trace.splitlines() if "getdents64("in line and "= -1 "in line])
    failed_turns=[];by_pid={}
    for line in trace.splitlines():
        pid,body=line.split(None,1)
        if any(x in body for x in begins):by_pid[pid]=[line]
        elif pid in by_pid:
            by_pid[pid].append(line)
            if any(x in body for x in ends):
                segment=by_pid.pop(pid)
                if any("getdents64("in s and "= -1 "in s for s in segment):failed_turns.append(segment)
    selected["derived/NEGATIVE-GETDENTS-COMPLETE-TURNS.json"]=encoded(failed_turns)
    for role in ("native-observed","native-off"):
        name="run/semantic/paired-ordinary/roles/"+role+"/capture/OBSERVATIONS.json"
        selected["derived/"+role+"-case10.json"]=encoded([r for r in load(logical[name])if r["case"]==10])
    selected["derived/original.stdout"]=logical["run/semantic/paired-ordinary/roles/original/stdout"]
    registry=[]
    plan=load(logical["source/reference/REGISTRY_PLAN.json"])
    for package in plan["crates"]:
        name=package["name"]+"-"+package["version"];archive=logical["run/semantic/crates/"+name+".crate"]
        require(pin(archive)==package["archive"],"complete target crate archive")
        members={}
        with tarfile.open(fileobj=io.BytesIO(archive),mode="r:gz")as tf:
            for entry in tf:
                if entry.isdir():continue
                require(entry.isfile()and entry.name.startswith(name+"/"),"ordinary complete crate implementation")
                rel=entry.name[len(name)+1:];require(rel not in members,"unique crate member")
                members[rel]=tf.extractfile(entry).read()
        prefix="run/semantic/vendor/"+name+"/"
        vendor={n[len(prefix):]:b for n,b in logical.items()if n.startswith(prefix)}
        different={n:dict(archive=pin(b),vendor=pin(vendor[n]))for n,b in members.items()if n in vendor and b!=vendor[n]}
        registry.append(dict(name=name,archive=pin(archive),members=len(members),vendor=len(vendor),
            omitted={n:pin(b)for n,b in members.items()if n not in vendor},
            added={n:pin(b)for n,b in vendor.items()if n not in members},different=different))
    selected["derived/REGISTRY-DIFFERENCES.json"]=encoded(registry)
    for name,body in selected.items():
        target=out/"selected"/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(body)
        print("RETAINED_FILE_BEGIN "+name);print(body.decode("utf-8"),end=""if body.endswith(b"\n")else"\n");print("RETAINED_FILE_END "+name)
    report=dict(status="COMPLETE_PRODUCER_ARCHIVE_INSPECTED",original_status="PRODUCERS_PASS_READBACK_PENDING",zip=ZIP,tar=TAR,logical_files=len(logical),
        logical_bytes=sum(map(len,logical.values())),source_manifest_sha256=SOURCE,source_files=len(src["files"])+1,
        selected={n:pin(b)for n,b in selected.items()},native_executions=0,rust_executions=0)
    (out/"INSPECT.json").write_bytes(encoded(report));print(encoded(report).decode(),end="")
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--archive",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();run(a.archive,a.output)
