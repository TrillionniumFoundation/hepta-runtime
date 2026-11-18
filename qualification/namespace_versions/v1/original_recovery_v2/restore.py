"""Read the exact uploaded failed artifact and restore all logical bytes without execution."""
import argparse,hashlib,io,os,stat,sys,tarfile,time,urllib.request,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
from common import source,read,loads,encoded,pin,require,files
def run(workspace):
    identity=source();dep=loads(read(ROOT/"dependencies/ORIGINAL_V2_FAIL.json"))
    artifact=dep["uploaded_artifact"];prior=workspace/"prior";prior.mkdir()
    target=workspace/"original";target.mkdir()
    url="https://api.github.com/repos/TrillionniumFoundation/hepta-runtime/actions/artifacts/"+str(artifact["id"])+"/zip"
    request=urllib.request.Request(url,headers={"Accept":"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28"})
    request.add_unredirected_header("Authorization","Bearer "+os.environ["GH_TOKEN"])
    started=time.monotonic()
    with urllib.request.urlopen(request,timeout=30)as response, (prior/"original-v2.zip").open("xb")as stream:
        while block:=response.read(1<<20):
            require(time.monotonic()-started<180,"whole original upload download deadline");stream.write(block)
    raw=read(prior/"original-v2.zip")
    require(len(raw)==artifact["size_in_bytes"]and"sha256:"+pin(raw)["sha256"]==artifact["digest"],"entire original ZIP bytes")
    expected_names={"namespace-versions-original-v2.tar.gz","namespace-versions-original-v2.tar.gz.json"}
    with zipfile.ZipFile(io.BytesIO(raw))as z:
        infos=z.infolist();require(len(infos)==2 and {x.filename for x in infos}==expected_names,"exact complete original ZIP members")
        for entry in infos:
            require(not entry.is_dir()and not(entry.flag_bits&1),"regular unencrypted uploaded member")
            body=z.read(entry);require(len(body)==entry.file_size,"whole uploaded member and CRC")
            (prior/entry.filename).write_bytes(body)
    tarpath=prior/"namespace-versions-original-v2.tar.gz";tarraw=read(tarpath)
    require(pin(tarraw)=={k:dep["tar"][k]for k in("bytes","sha256")}and
        loads(read(prior/"namespace-versions-original-v2.tar.gz.json"))==dep["tar"],"exact whole original TAR and exporter report")
    objects={};manifest=None
    with tarfile.open(fileobj=io.BytesIO(tarraw),mode="r:gz")as t:
        for entry in t:
            require(entry.isfile()and entry.name not in objects and not Path(entry.name).is_absolute()
                and".."not in Path(entry.name).parts,"complete regular unique uploaded TAR members")
            body=t.extractfile(entry).read();require(len(body)==entry.size,"complete original TAR object")
            if entry.name=="artifact-manifest.json":
                require(manifest is None and entry.mode==0o644,"one complete original archive manifest")
                manifest=loads(body);(prior/"original-artifact-manifest.json").write_bytes(body)
            else:objects[entry.name]=(body,entry.mode)
    require(manifest is not None and manifest["git_head"]==dep["freeze"]["commit"]
        and manifest["run_id"]==str(dep["run"])and manifest["source_manifest_sha256"]==dep["freeze"]["manifest_sha256"]
        and manifest["gate"]=={"status":"NO_FINAL_GATE"},"exact failed producer custody remains unchanged")
    wanted=set();logical=manifest["files"];count=0
    for name,row in logical.items():
        p=Path(name);require(not p.is_absolute()and".."not in p.parts and p.parts[0]in("source","run","outer","prior"),"bounded original logical root")
        key=row["object"];require(key in objects,"all original logical objects retained")
        body,mode=objects[key];require(pin(body)=={k:row[k]for k in("bytes","sha256")}and mode==row["mode"]
            and key=="objects/"+row["sha256"]+"-"+format(mode,"03o"),"all complete uploaded logical bytes and exact modes")
        wanted.add(key);out=target/p;out.parent.mkdir(parents=True,exist_ok=True)
        with out.open("xb")as f:f.write(body)
        out.chmod(mode);count+=len(body)
    require(wanted==set(objects)and len(logical)==dep["tar"]["logical_files"]and count==dep["tar"]["logical_bytes"]
        and len(objects)==dep["tar"]["unique_objects"],"no omitted or orphan original archive objects")
    require(files(target)=={name:{k:row[k]for k in("bytes","sha256","mode")}for name,row in logical.items()},
        "whole expanded original bytes and modes reread")
    require(source()==identity,"frozen recovery sources unchanged")
    report=dict(schema="hepta.namespace-versions.original-v2-upload-read.v1",status="ORIGINAL_V2_FULL_UPLOAD_READ_PASS",
        artifact=artifact,tar=dep["tar"],source_manifest_sha256=identity,original_source_manifest_sha256=manifest["source_manifest_sha256"],
        original_head=manifest["git_head"],original_run=manifest["run_id"],original_gate=manifest["gate"],logical_files=len(logical),
        logical_bytes=count,all_zip_members_reread=True,all_tar_objects_reread=True,all_logical_bytes_and_modes_reread=True,
        original_directory_metadata_claimed=False,files_deleted=0,original_compile_replays=0,original_application_calls=0,native_application_calls=0)
    (workspace/"run/RESTORE.json").write_bytes(encoded(report));print(encoded(report).decode(),end="")
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--workspace",type=Path,required=True);a=p.parse_args();run(a.workspace.resolve(strict=True))
