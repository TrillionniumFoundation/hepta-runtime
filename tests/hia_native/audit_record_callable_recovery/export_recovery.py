"""Lossless recovery archive; preserves every producer byte and mode, including failure."""
from pathlib import Path
import argparse,hashlib,io,os,sys,tarfile
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT))
from recovery_common import source,read,loads,pin,encoded,need,files,BASE_SOURCE

def export(workspace,archive):
    identity=source()
    original=workspace/"original"
    previous=loads(read(workspace/"admission/ORIGINAL_ARCHIVE_MANIFEST.json"))
    original_expected={p:{k:r[k] for k in ("bytes","sha256","mode")} for p,r in previous["files"].items()}
    need(files(original)==original_expected,"all 44786 original files and modes remain unchanged")
    need(len(original_expected)==44786 and sum(r["bytes"] for r in original_expected.values())==2581124108,
         "whole preserved original capture")
    roots=[("recovery-source",ROOT),("original",original),("recovery",workspace/"recovery"),
           ("admission",workspace/"admission")]
    logical={};objects={}
    for label,root in roots:
        if not root.exists():continue
        for name,row in files(root).items():
            key="objects/"+row["sha256"]+"-"+format(row["mode"],"03o")
            logical[label+"/"+name]=dict(row,object=key)
            if key in objects:need(objects[key][0]==row,"full duplicate content/mode identity")
            else:objects[key]=(row,root/name)
    path=workspace/"recovery/GATE.json"
    gate=loads(read(path)) if path.is_file() else dict(status="NO_FINAL_GATE")
    manifest=dict(schema="hepta.audit-record-callable.recovery-archive.v1",
        git_head=os.environ.get("GITHUB_SHA"),run_id=os.environ.get("GITHUB_RUN_ID"),
        reader_adapter_source_sha256=identity,original_source_manifest_sha256=BASE_SOURCE,
        original_head="f7273eb417e1f90c4e11b0556f7d6c7d2758bd33",original_run=44061230103,
        original_status="FAIL",original_all_files_unchanged=True,
        original_zip=dict(bytes=156028150,sha256="50dea39e1347a4d3bc18ca6534f872fc5ede0c3d9ddca271b54dfa32442aa9ff"),
        original_tar=dict(bytes=156027265,sha256="ac3b4ecb8d3233138f7327bcc3ca7c7dfd02c1cb6c98112abf4be97ef0599b3b"),
        files=logical,gate=gate,native_or_rust_executions=0,original_rust_replay=0,
        archive_and_hot_cache_qualified=False,begin_finish_caller_qualified=False,
        public_handler_qualified=False,whole_runtime_replaced=False)
    manifest_raw=encoded(manifest)
    with tarfile.open(archive,"w:gz",compresslevel=1) as tar:
        for key,(row,path) in sorted(objects.items()):
            raw=read(path);need(pin(raw)=={k:row[k] for k in ("bytes","sha256")},"unchanged full export input")
            item=tarfile.TarInfo(key);item.size=len(raw);item.mode=row["mode"];tar.addfile(item,io.BytesIO(raw))
        item=tarfile.TarInfo("artifact-manifest.json");item.size=len(manifest_raw);item.mode=0o644
        tar.addfile(item,io.BytesIO(manifest_raw))
    actual={}
    with tarfile.open(archive,"r|gz") as tar:
        while item:=tar.next():
            need(item.isfile() and item.name not in actual,"unique ordinary complete exported member")
            with tar.extractfile(item) as f:digest=hashlib.file_digest(f,"sha256").hexdigest()
            actual[item.name]=dict(bytes=item.size,sha256=digest,mode=item.mode);tar.members.clear()
    expected={key:row for key,(row,_) in objects.items()}
    expected["artifact-manifest.json"]=dict(**pin(manifest_raw),mode=0o644)
    need(actual==expected,"complete exported physical objects and modes reread")
    for label,root in roots:
        if root.exists():
            wanted={p[len(label)+1:]:{k:r[k] for k in ("bytes","sha256","mode")}
                    for p,r in logical.items() if p.startswith(label+"/")}
            need(files(root)==wanted,"every complete logical export input reread: "+label)
    need(files(original)==original_expected and source()==identity,"complete producer and recovery source unchanged")
    with archive.open("rb") as f:digest=hashlib.file_digest(f,"sha256").hexdigest()
    result=dict(schema="hepta.audit-record-callable.recovery-archive-read.v1",status=gate["status"],
        bytes=archive.stat().st_size,sha256=digest,logical_files=len(logical),
        logical_bytes=sum(r["bytes"] for r in logical.values()),unique_objects=len(objects),
        reader_adapter_source_sha256=identity,original_source_manifest_sha256=BASE_SOURCE,
        original_files=44786,original_bytes=2581124108,original_all_files_unchanged=True,
        original_status="FAIL",all_objects_and_modes_reread=True,all_logical_files_reread=True,
        native_or_rust_executions=0,original_rust_replay=0,public_handler_qualified=False)
    archive.with_suffix(archive.suffix+".json").write_bytes(encoded(result))
    print(encoded(result).decode(),end="")
if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--workspace",type=Path,required=True);p.add_argument("--archive",type=Path,required=True)
    a=p.parse_args();export(a.workspace.resolve(strict=True),a.archive.absolute())
