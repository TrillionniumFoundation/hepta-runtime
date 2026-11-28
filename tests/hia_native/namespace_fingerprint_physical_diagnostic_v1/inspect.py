"""Inspect every immutable producer archive byte, then expose exact retained diagnostics."""
from pathlib import Path
import argparse,hashlib,io,json,tarfile,zipfile
ZIP={"bytes":60729530,"sha256":"67cf8bebb8d36080389c28aeaff0c74a0e046224abba91f8f965edce674665ba"}
TAR={"bytes":60728620,"sha256":"040459308e91221df5e9f69cc41e69e3d8f55417bff540b8f16d98e294981f17"}
HEAD="f2116d7ed40b082c170cf22dd9bc8ac22b65355d"
SOURCE="7c1a877b495f140a31da41006b0e782a128d8d32093187b0a375a680806d1ce3"
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
            {"fingerprint-physical-v1.tar.gz","fingerprint-physical-v1.tar.gz.json"},"two exact original ZIP names")
        tar=z.read("fingerprint-physical-v1.tar.gz");side=z.read("fingerprint-physical-v1.tar.gz.json")
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
    require(manifest["git_head"]==HEAD and str(manifest["run_id"])=="44123154988"and manifest["source_manifest_sha256"]==SOURCE,"exact failed source and producer")
    referenced=set();logical={}
    for name,row in manifest["files"].items():
        p=Path(name);require(not p.is_absolute()and".."not in p.parts and p.parts[0]in("source","run","retained","restoration"),"safe exact logical path")
        require(members[row["object"]]=={k:row[k]for k in("bytes","sha256","mode")},"every original file/mode")
        logical[name]=bodies[row["object"]];referenced.add(row["object"])
    require(referenced==set(members)-{"artifact-manifest.json"}and len(logical)==44268 and sum(map(len,logical.values()))==4409781463,"whole failed logical closure")
    require(pin(logical["source/SOURCE.json"])["sha256"]==SOURCE,"entire producer source manifest")
    src=load(logical["source/SOURCE.json"])
    require({n[7:]for n in logical if n.startswith("source/")}==set(src["files"])|{"SOURCE.json"},"complete frozen source set")
    for name,row in src["files"].items():
        body=logical["source/"+name]
        require(pin(body)=={k:row[k]for k in("bytes","sha256")}and hashlib.sha1(b"blob "+str(len(body)).encode()+b"\0"+body).hexdigest()==row["git_blob"],"complete source Git blob")
    for name in ("artifact-manifest.json",):(out/name).write_bytes(bodies[name])
    (out/"original-export.json").write_bytes(side)
    names={"run/physical/PARENT.json","run/physical/BASELINE.json","run/physical/workers/processes.json",
           "run/processes/physical/fingerprint-physical.stderr","run/processes/physical/fingerprint-physical.stdout",
           "run/processes/physical/processes.json"}
    names|={"run/physical/workers/"+str(i)+"/"+leaf for i in(0,1)for leaf in("stderr","stdout","process.json","REPORT.json")}
    selected={n:body for n,body in logical.items()if n in names}
    copies={}
    for name,body in logical.items():
        if name.startswith("run/physical/")and name.endswith("/BUNDLE.json"):
            value=load(body);copies[name]=dict(files=len(value["files"]),bytes=sum(r["bytes"]for r in value["files"].values()),pin=pin(body))
    proofs={}
    for name,body in logical.items():
        if name.startswith("run/physical/")and name.count("/")==2 and name.endswith(".json"):
            value=load(body)
            if "probes"in value:
                proofs[name]={k:v for k,v in value.items()if k not in("before","after")}
                require(value["before"]==value["after"],"retained completed proof unchanged")
                proofs[name]["whole_snapshot_entries"]=len(value["before"])
    selected["derived/COMPLETED-COPIES.json"]=encoded(copies)
    selected["derived/COMPLETED-PROOFS.json"]=encoded(proofs)
    for name,body in selected.items():
        target=out/"selected"/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(body)
        print("RETAINED_FILE_BEGIN "+name);print(body.decode("utf-8"),end=""if body.endswith(b"\n")else"\n");print("RETAINED_FILE_END "+name)
    report=dict(status="COMPLETE_FAILED_PHYSICAL_ARCHIVE_INSPECTED",original_status="NO_FINAL_GATE",zip=ZIP,tar=TAR,logical_files=len(logical),
        logical_bytes=sum(map(len,logical.values())),source_manifest_sha256=SOURCE,source_files=len(src["files"])+1,
        selected={n:pin(b)for n,b in selected.items()},native_executions=0,rust_executions=0)
    (out/"INSPECT.json").write_bytes(encoded(report));print(encoded(report).decode(),end="")
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--archive",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();run(a.archive,a.output)
