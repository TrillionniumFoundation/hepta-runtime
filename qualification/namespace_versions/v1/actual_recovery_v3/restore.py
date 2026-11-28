"""Restore every byte of the exact previously uploaded native/original build artifacts."""
import argparse,gzip,hashlib,io,os,sys,tarfile,time,urllib.request,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
from common import source,read,loads,encoded,pin,require,files
def one(row,retained,prior):
    artifact=row["artifact"];label=row["label"];destination=retained/label;destination.mkdir()
    request=urllib.request.Request(artifact["archive_download_url"],headers={"Accept":"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28"})
    request.add_unredirected_header("Authorization","Bearer "+os.environ["GH_TOKEN"])
    started=time.monotonic();zip_path=prior/(label+".zip")
    with urllib.request.urlopen(request,timeout=30)as response,zip_path.open("xb")as stream:
        while block:=response.read(1<<20):
            require(time.monotonic()-started<180,"whole dependency download deadline");stream.write(block)
    raw=read(zip_path);require(len(raw)==artifact["size_in_bytes"]and"sha256:"+pin(raw)["sha256"]==artifact["digest"],"whole uploaded dependency ZIP")
    filename=artifact["name"]+".tar.gz";expected={filename,filename+".json"}
    with zipfile.ZipFile(io.BytesIO(raw))as z:
        entries=z.infolist();require(len(entries)==2 and {x.filename for x in entries}==expected,"all actual dependency ZIP members")
        for member in entries:
            require(not member.is_dir()and not(member.flag_bits&1),"regular unencrypted original member")
            body=z.read(member);require(len(body)==member.file_size,"complete ZIP member with CRC")
            (prior/member.filename).write_bytes(body)
    tarraw=read(prior/filename);require(pin(tarraw)=={k:row["tar"][k]for k in("bytes","sha256")}
        and loads(read(prior/(filename+".json")))==row["tar"],"whole dependency TAR and exact exporter report")
    objects={};manifest=None
    with tarfile.open(fileobj=io.BytesIO(tarraw),mode="r:gz")as t:
        for member in t:
            require(member.isfile()and member.name not in objects and not Path(member.name).is_absolute()
                and".."not in Path(member.name).parts,"whole bounded ordinary TAR object")
            body=t.extractfile(member).read();require(len(body)==member.size,"complete actual object byte stream")
            if member.name=="artifact-manifest.json":
                require(manifest is None and member.mode==0o644,"one exact artifact manifest")
                manifest=loads(body);(prior/(label+"-artifact-manifest.json")).write_bytes(body)
            else:objects[member.name]=(body,member.mode)
    require(manifest is not None and manifest["git_head"]==row["head"]and manifest["run_id"]==str(row["run"])
        and manifest["source_manifest_sha256"]==row["source_manifest_sha256"]and manifest["gate"]==row["gate"],
        "whole original dependency producer identity, including retained FAIL")
    wanted=set();count=0
    for name,entry in manifest["files"].items():
        p=Path(name);require(not p.is_absolute()and".."not in p.parts and p.parts[0]in("source","run","outer","prior"),"owned dependency logical root")
        key=entry["object"];require(key in objects,"complete original logical object")
        body,mode=objects[key];require(pin(body)=={k:entry[k]for k in("bytes","sha256")}and mode==entry["mode"]
            and key=="objects/"+entry["sha256"]+"-"+format(mode,"03o"),"whole actual logical bytes and mode")
        output=destination/p;output.parent.mkdir(parents=True,exist_ok=True)
        with output.open("xb")as stream:stream.write(body)
        output.chmod(mode);wanted.add(key);count+=len(body)
    require(wanted==set(objects)and len(manifest["files"])==row["tar"]["logical_files"]
        and count==row["tar"]["logical_bytes"]and len(objects)==row["tar"]["unique_objects"],"no dropped dependency object or source file")
    require(files(destination)=={k:{x:v[x]for x in("bytes","sha256","mode")}for k,v in manifest["files"].items()},
        "all original expanded logical bytes and modes reread")
    return dict(label=label,artifact=artifact,tar=row["tar"],head=row["head"],run=row["run"],
        source_manifest_sha256=row["source_manifest_sha256"],logical_files=len(manifest["files"]),logical_bytes=count,
        original_gate=manifest["gate"]["status"],full_zip_tar_logical_read=True,files_deleted=0)
def run(workspace):
    identity=source();dependencies=loads(read(ROOT/"DEPENDENCIES.json"));retained=workspace/"retained";retained.mkdir()
    prior=workspace/"prior";prior.mkdir();results=[one(row,retained,prior)for row in dependencies["artifacts"]]
    require(source()==identity,"complete frozen actual sources unchanged")
    report=dict(schema="hepta.namespace-versions.dependency-restore.v1",status="PASS",source_manifest_sha256=identity,rows=results,
        native_compiles=0,original_compiles=0,native_applications=0,original_applications=0,application_replays=0)
    (workspace/"run/RESTORE.json").write_bytes(encoded(report));print(encoded(report).decode(),end="")
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--workspace",type=Path,required=True);a=p.parse_args();run(a.workspace.resolve(strict=True))
