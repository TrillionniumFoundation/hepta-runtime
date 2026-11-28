"""Archive and reread all complete current source, evidence, files, directories and modes."""
import argparse,hashlib,io,os,stat,sys,tarfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
from common import source,read,loads,encoded,pin,require,files
def directories(root):
    result={".":stat.S_IMODE(root.lstat().st_mode)}
    for folder,names,_ in os.walk(root,followlinks=False):
        for name in names:
            p=Path(folder)/name;require(stat.S_ISDIR(p.lstat().st_mode),"ordinary complete archive directory")
            result[p.relative_to(root).as_posix()]=stat.S_IMODE(p.lstat().st_mode)
    return result
def run(workspace,archive):
    identity=source();roots=[(name,workspace/name)for name in("source","run","outer","prior","retained")if(workspace/name).exists()]
    logical={};objects={};dirs={}
    for label,root in roots:
        dirs.update({label+("/"+name if name!="."else""):mode for name,mode in directories(root).items()})
        for name,row in files(root).items():
            key="objects/"+row["sha256"]+"-"+format(row["mode"],"03o")
            logical[label+"/"+name]=dict(row,object=key)
            if key in objects:require(objects[key][0]==row,"complete repeated object bytes and mode")
            else:objects[key]=(row,root/name)
    gate=loads(read(workspace/"run/GATE.json"))if(workspace/"run/GATE.json").is_file()else dict(status="NO_FINAL_GATE")
    manifest=dict(schema="hepta.namespace-versions.actual-archive.v1",git_head=os.environ["GITHUB_SHA"],run_id=os.environ["GITHUB_RUN_ID"],
        source_manifest_sha256=identity,files=logical,directories=dirs,gate=gate,
        exporter_native_executions=0,exporter_original_executions=0,application_replays=0,files_deleted=0,
        namespace_version_qualified=False,public_handler_qualified=False,whole_runtime_replaced=False)
    body=encoded(manifest)
    with tarfile.open(archive,"w:gz",compresslevel=1)as tar:
        for name,(row,path)in sorted(objects.items()):
            raw=read(path);require(pin(raw)=={k:row[k]for k in("bytes","sha256")},"every complete unchanged source/evidence object")
            info=tarfile.TarInfo(name);info.size=len(raw);info.mode=row["mode"];tar.addfile(info,io.BytesIO(raw))
        info=tarfile.TarInfo("artifact-manifest.json");info.size=len(body);info.mode=0o644;tar.addfile(info,io.BytesIO(body))
    seen={}
    with tarfile.open(archive,"r|gz")as tar:
        while entry:=tar.next():
            require(entry.isfile()and entry.name not in seen,"every actual exported object is unique and regular")
            with tar.extractfile(entry)as stream:digest=hashlib.file_digest(stream,"sha256").hexdigest()
            seen[entry.name]=dict(bytes=entry.size,sha256=digest,mode=entry.mode);tar.members.clear()
    expected={key:row for key,(row,_)in objects.items()};expected["artifact-manifest.json"]=dict(**pin(body),mode=0o644)
    require(seen==expected,"every complete exported TAR byte and object mode independently reread")
    for label,root in roots:
        require(files(root)=={k[len(label)+1:]:{a:r[a]for a in("bytes","sha256","mode")}for k,r in logical.items()if k.startswith(label+"/")},
            "all current logical source/evidence bytes and file modes reread")
        require(directories(root)=={("."if k==label else k[len(label)+1:]):v for k,v in dirs.items()if k==label or k.startswith(label+"/")},
            "every current complete directory and exact mode reread")
    require(source()==identity,"complete actual source freeze unchanged")
    with archive.open("rb")as stream:digest=hashlib.file_digest(stream,"sha256").hexdigest()
    report=dict(schema="hepta.namespace-versions.actual-archive-read.v1",status=gate["status"],source_manifest_sha256=identity,
        bytes=archive.stat().st_size,sha256=digest,logical_files=len(logical),logical_bytes=sum(r["bytes"]for r in logical.values()),
        unique_objects=len(objects),directories=len(dirs),all_zip_independent_dependency_reads_retained=True,
        all_tar_objects_reread=True,all_logical_files_reread=True,all_directories_and_modes_reread=True,
        native_executions=0,original_executions=0,application_replays=0,files_deleted=0)
    archive.with_suffix(archive.suffix+".json").write_bytes(encoded(report));print(encoded(report).decode(),end="")
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--workspace",type=Path,required=True);p.add_argument("--archive",type=Path,required=True)
    a=p.parse_args();run(a.workspace.resolve(strict=True),a.archive.absolute())
