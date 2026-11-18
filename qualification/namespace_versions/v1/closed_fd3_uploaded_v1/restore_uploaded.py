"""Restore and completely reread the already-completed actual group; never execute its programs."""
import argparse,gzip,hashlib,io,os,stat,sys,tarfile,time,urllib.request,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
from common import source,read,loads,encoded,pin,require,files
from export import directories
def run(workspace,group):
    identity=source();row=loads(read(ROOT/"UPLOAD_DEPENDENCIES.json"))["groups"][group];artifact=row["artifact"]
    prior=workspace/"prior";prior.mkdir();destination=workspace/"retained";destination.mkdir()
    request=urllib.request.Request(artifact["archive_download_url"],headers={"Accept":"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28"})
    request.add_unredirected_header("Authorization","Bearer "+os.environ["GH_TOKEN"])
    started=time.monotonic();zip_path=prior/"actual.zip"
    with urllib.request.urlopen(request,timeout=30)as response,zip_path.open("xb")as stream:
        while block:=response.read(1<<20):
            require(time.monotonic()-started<180,"complete actual archive download deadline");stream.write(block)
    raw=read(zip_path);require(len(raw)==artifact["size_in_bytes"]and"sha256:"+pin(raw)["sha256"]==artifact["digest"],"whole uploaded actual ZIP bytes")
    filename=artifact["name"]+".tar.gz"
    with zipfile.ZipFile(io.BytesIO(raw))as z:
        entries=z.infolist();require(len(entries)==2 and {x.filename for x in entries}=={filename,filename+".json"},"all original actual ZIP members")
        for member in entries:
            require(not member.is_dir()and not(member.flag_bits&1),"regular unencrypted actual ZIP member")
            body=z.read(member);require(len(body)==member.file_size,"complete ZIP member and CRC")
            (prior/member.filename).write_bytes(body)
    del raw
    tarraw=read(prior/filename);require(pin(tarraw)=={k:row["tar"][k]for k in("bytes","sha256")}
        and loads(read(prior/(filename+".json")))==row["tar"],"complete actual TAR and original exporter report")
    objects={};manifest=None;manifest_raw=None
    with tarfile.open(fileobj=io.BytesIO(tarraw),mode="r:gz")as tar:
        for member in tar:
            require(member.isfile()and member.name not in objects and not Path(member.name).is_absolute()
                and".."not in Path(member.name).parts,"regular complete actual TAR member")
            body=tar.extractfile(member).read();require(len(body)==member.size,"all actual object bytes")
            if member.name=="artifact-manifest.json":
                require(manifest is None and member.mode==0o644,"one whole actual archive manifest")
                manifest=loads(body);manifest_raw=body
            else:objects[member.name]=(body,member.mode)
    del tarraw
    require(manifest is not None and manifest["schema"]=="hepta.namespace-versions.actual-archive.v1"
        and manifest["git_head"]==row["head"]and manifest["run_id"]==str(row["run"])
        and manifest["source_manifest_sha256"]==row["source_manifest_sha256"]
        and manifest["gate"]==row["gate"],"exact already successful application artifact")
    (prior/"artifact-manifest.json").write_bytes(manifest_raw)
    wanted=set();count=0
    for name,mode in sorted(manifest["directories"].items(),key=lambda item:(len(Path(item[0]).parts),item[0])):
        p=Path(name);require(not p.is_absolute()and".."not in p.parts and p.parts[0]in("source","run","outer","prior","retained"),
            "whole ordinary actual directory tree")
        path=destination/p;path.mkdir();path.chmod(mode)
    for name,entry in manifest["files"].items():
        p=Path(name);require(not p.is_absolute()and".."not in p.parts and p.parts[0]in("source","run","outer","prior","retained"),
            "owned original actual logical root")
        key=entry["object"];require(key in objects,"all original actual logical objects retained")
        body,mode=objects[key];require(pin(body)=={k:entry[k]for k in("bytes","sha256")}and mode==entry["mode"]
            and key=="objects/"+entry["sha256"]+"-"+format(mode,"03o"),"whole actual file bytes and mode")
        output=destination/p;require(output.parent.is_dir(),"all actual original directory parents present")
        with output.open("xb")as stream:stream.write(body)
        output.chmod(mode);wanted.add(key);count+=len(body)
    require(wanted==set(objects)and len(manifest["files"])==row["tar"]["logical_files"]
        and count==row["tar"]["logical_bytes"]and len(objects)==row["tar"]["unique_objects"],"complete actual archive logical/object inventory")
    require(files(destination)=={k:{x:v[x]for x in("bytes","sha256","mode")}for k,v in manifest["files"].items()},
        "every actual expanded logical byte and mode independently reread")
    current=directories(destination);current.pop(".")
    require(current==manifest["directories"]and len(current)==row["tar"]["directories"],"every original directory and mode independently reread")
    require(source(destination/"source")==row["source_manifest_sha256"]and source()==identity,"both complete source freezes unchanged")
    report=dict(schema="hepta.namespace-versions.actual-recovery-restore.v1",status="PASS",dependency=row,
        full_zip_tar_logical_directories_modes_read=True,files_deleted=0,native_applications=0,original_applications=0,
        application_replays=0,source_manifest_sha256=identity)
    (workspace/"run/RESTORE.json").write_bytes(encoded(report));print(encoded(report).decode(),end="")
    for role in("native-observed","native-off","original"):
        examples=[x for x in read(destination/"run/group/roles"/role/"syscalls.strace").decode().splitlines()if x.lstrip().startswith("|")or __import__("re").match(r"^\d+\s+\|",x)][:4]
        print("ACTUAL_HEXDUMP_"+role+" "+repr(examples))
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--workspace",type=Path,required=True);p.add_argument("--group",required=True);a=p.parse_args();run(a.workspace.resolve(strict=True),a.group)
