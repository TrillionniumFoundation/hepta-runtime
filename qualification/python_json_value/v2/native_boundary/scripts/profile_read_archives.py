"""Read every byte, file and mode of reused ZIP/TAR/object/logical archives."""
from pathlib import Path
import hashlib,stat,tarfile,zipfile
from common import decode,owned,pin,require,sha
from reuse import same
def verify(source,work,group):
    binding=decode(owned(source,"PROFILE_INPUTS.json").read_bytes())["groups"][group]
    archive=owned(work,"download/complete.zip");original=work/"original";zipped=original/"zip"
    require(pin(archive)=={k:binding["artifact"][k]for k in("bytes","sha256")},"frozen upstream complete ZIP")
    zip_rows={}
    with zipfile.ZipFile(archive)as stream:
        for member in stream.infolist():
            require(not member.is_dir()and member.filename not in zip_rows,"upstream ZIP complete member set")
            target=owned(zipped,member.filename)
            with stream.open(member)as data:digest=hashlib.file_digest(data,"sha256").hexdigest()
            item=dict(bytes=member.file_size,sha256=digest)
            require(pin(target)==item,"upstream complete ZIP member differs")
            zip_rows[member.filename]=item
    require({p.relative_to(zipped).as_posix()for p in zipped.rglob("*")if p.is_file()}==set(zip_rows),
        "upstream complete extracted ZIP file set")
    tar=owned(zipped,"evidence.tar.gz");require(pin(tar)=={k:binding["tar"][k]for k in("bytes","sha256")},
        "frozen upstream complete TAR")
    rows={};manifest=None;manifest_raw=None
    with tarfile.open(tar,"r|gz")as stream:
        while member:=stream.next():
            require(member.isfile()and member.name not in rows,"upstream complete TAR member kind/set")
            if member.name=="artifact-manifest.json":
                manifest_raw=stream.extractfile(member).read()
                require(len(manifest_raw)==member.size,"whole upstream archive index")
                digest=sha(manifest_raw);manifest=decode(manifest_raw)
            else:
                with stream.extractfile(member)as data:digest=hashlib.file_digest(data,"sha256").hexdigest()
                physical=owned(original,member.name)
                require(pin(physical)==dict(bytes=member.size,sha256=digest)
                    and physical.stat().st_mode&0o777==member.mode,"whole upstream retained object")
            rows[member.name]=dict(bytes=member.size,sha256=digest,mode=member.mode);stream.members.clear()
    require(manifest_raw==owned(original,"ARTIFACT_MANIFEST.json").read_bytes()
        and manifest["schema"]==binding["archive_schema"]and manifest["git_head"]==binding["commit"]
        and manifest["gate_status"]==binding["gate_status"]and manifest["source_manifest"]["sha256"]==binding["manifest_sha256"],
        "exact upstream archive identity")
    files=manifest["files"];dirs=manifest["directories"];objects={}
    restored=original/"restored"
    for path,row in files.items():
        require(row["object"]=="objects/"+row["sha256"]+"-"+format(row["mode"],"03o"),"canonical upstream object name")
        value={k:row[k]for k in("bytes","sha256","mode")};require(rows[row["object"]]==value,"full logical object binding")
        target=owned(restored,path)
        require(dict(**pin(target),mode=target.stat().st_mode&0o777)==value,"full restored logical bytes/modes")
        objects[row["object"]]=value
    require(set(rows)==set(objects)|{"artifact-manifest.json"}
        and {p.relative_to(original/"objects").as_posix()for p in(original/"objects").rglob("*")if p.is_file()}
            =={p.removeprefix("objects/")for p in objects},"exact all unique object file sets")
    require({p.relative_to(restored).as_posix()for p in restored.rglob("*")if p.is_file()}==set(files)
        and {p.relative_to(restored).as_posix():p.stat().st_mode&0o777 for p in restored.rglob("*")if p.is_dir()}==dirs,
        "whole logical archive file/directory set and modes")
    require(len(files)==binding["tar"]["logical_files"]and sum(r["bytes"]for r in files.values())==binding["tar"]["logical_bytes"]
        and len(dirs)==binding["tar"]["directories"]and len(objects)==binding["tar"]["unique_objects"]
        and sum(r["bytes"]for r in objects.values())==binding["tar"]["unique_bytes"],"complete frozen upstream archive totals")
    same(source/"trusted-profiles"/binding["family"],restored/"source")
    result=dict(status="PASS",original_status=manifest["gate_status"],zip=pin(archive),zip_members=zip_rows,tar=pin(tar),
        logical_files=len(files),logical_bytes=sum(r["bytes"]for r in files.values()),directories=len(dirs),
        unique_objects=len(objects),unique_bytes=sum(r["bytes"]for r in objects.values()),all_objects_fully_read=True,
        all_logical_files_and_directories_restored=True,native_or_rust_executions=0)
    require(result==decode(owned(original,"UNPACK.json").read_bytes()),"saved complete upstream restoration proof")
    return result
