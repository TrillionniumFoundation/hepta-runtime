#!/usr/bin/env python3
"""Copy and reverify only the retained actual HIA B3; never create a seed."""
from pathlib import Path
import encodings.cp437,gzip,hashlib,json,os,shutil,stat,tarfile,zipfile,zlib
from callable_common import B3,HEPTA,decode,encoded,owned,pin,require
from archive_input import Hashing,download,flat_archive,safe

def inventory(root):
    root=Path(root);files={};dirs={}
    for p in [root,*sorted(root.rglob("*"))]:
        require(not p.is_symlink(),"bootstrap symlink")
        name="." if p==root else p.relative_to(root).as_posix()
        m=p.stat().st_mode
        if stat.S_ISDIR(m):dirs[name]=stat.S_IMODE(m)
        else:
            require(stat.S_ISREG(m),"ordinary bootstrap file")
            files[name]=dict(**pin(p),mode=stat.S_IMODE(m))
    return dict(files=files,directories=dirs)

def retained_receipt(restored,dependency):
    origin=owned(restored,"capture/build-public/bootstrap/bootstrap.json")
    value=decode(origin.read_bytes())
    require(value["schema"]=="hepta.runtime.native-bootstrap.v1"
        and value["qualification"]=="development_fixed_point"
        and value["generation_sha256"]==B3 and value["dependency"]==dependency
        and dependency["commit"]==HEPTA
        and dependency["tree"]=="8d8b0fb8d015fb7edab302498bb9ed4c74ab6f49",
        "retained actual B3 source dependency")
    parent=origin.parent
    for label in("B1","B2","B3"):
        require(pin(owned(parent,label+".image.bin"))["sha256"]==B3,"retained fixed point image")
    return parent

def prepare(source,output,dependency):
    source,output=Path(source),Path(output)
    identity=decode(owned(source,"BOOTSTRAP_INPUT.json").read_bytes())
    path=output/"bootstrap-input.zip";restored=output/"retained-bootstrap"
    download(path,identity["artifact"]);proof=flat_archive(path,identity,restored)
    parent=retained_receipt(restored,dependency)
    target=output/"build/bootstrap"
    require(not target.exists(),"fresh copied B3 directory")
    shutil.copytree(parent,target,copy_function=shutil.copy2)
    before=inventory(parent);require(inventory(target)==before,"complete copied B3 bytes and modes")
    result=dict(schema="hepta.runtime.file-metadata.retained-b3.v1",status="COPIED_REVERIFIED_ACTUAL_B3_ONLY",
        producer=identity,complete_input=proof,retained_path=parent.relative_to(output).as_posix(),
        copied_path=target.relative_to(output).as_posix(),complete_inventory=before,dependency=dependency,
        new_seed_executions=0,new_bootstrap_generations=0,application_executions=0)
    (output/"BOOTSTRAP_REUSE.json").write_bytes(encoded(result))
    return result

def verify(source,output,dependency):
    source,output=Path(source),Path(output)
    identity=decode(owned(source,"BOOTSTRAP_INPUT.json").read_bytes())
    path=owned(output,"bootstrap-input.zip");restored=output/"retained-bootstrap"
    require(pin(path)==identity["zip"],"whole retained bootstrap ZIP")
    with zipfile.ZipFile(path) as z:
        require(len(z.infolist())==3 and set(z.namelist())=={"ARCHIVE.json","FILES.json","evidence.tar.gz"},
            "complete retained B3 archive members")
        index=decode(z.read("FILES.json"));wanted={r["path"]:r for r in index["files"]}
        require(len(wanted)==len(index["files"])==identity["files"],"complete B3 input file inventory")
        seen=set()
        with z.open("evidence.tar.gz") as src:
            h=Hashing(src)
            with tarfile.open(fileobj=h,mode="r|gz") as tar:
                for m in tar:
                    safe(m.name);require(m.isfile() and m.name in wanted and m.name not in seen,"B3 ordinary unique member")
                    row=wanted[m.name]
                    require(m.size==row["bytes"] and m.mode==row["mode"],"complete B3 member extent/mode")
                    with tar.extractfile(m) as f:
                        digest=hashlib.file_digest(f,"sha256").hexdigest()
                    require(digest==row["sha256"],"whole retained B3 member bytes")
                    physical=owned(restored,m.name)
                    require(pin(physical)=={k:row[k] for k in("bytes","sha256")}
                        and stat.S_IMODE(physical.stat().st_mode)==row["mode"],"all restored bootstrap evidence bytes")
                    seen.add(m.name);tar.members.clear()
            while h.read(1<<20):pass
            require(h.pin()==identity["archive"],"whole retained bootstrap compressed TAR")
        expected=dict(status="COMPLETE_ARCHIVE_BYTES_PASS",files=identity["files"],
            logical_bytes=identity["logical_bytes"],archive=identity["archive"])
        require(decode(z.read("ARCHIVE.json"))==expected and seen==set(wanted)
            and sum(r["bytes"] for r in wanted.values())==identity["logical_bytes"],
            "retained actual build archive completeness")
    require(set(inventory(restored)["files"])==set(wanted),"no extra restored bootstrap evidence")
    parent=retained_receipt(restored,dependency);target=output/"build/bootstrap"
    value=decode(owned(output,"BOOTSTRAP_REUSE.json").read_bytes())
    actual=inventory(parent);require(inventory(target)==actual,"complete copied B3 after compile")
    require(value==dict(schema="hepta.runtime.file-metadata.retained-b3.v1",status="COPIED_REVERIFIED_ACTUAL_B3_ONLY",
        producer=identity,complete_input=expected,retained_path=parent.relative_to(output).as_posix(),
        copied_path=target.relative_to(output).as_posix(),complete_inventory=actual,dependency=dependency,
        new_seed_executions=0,new_bootstrap_generations=0,application_executions=0),
        "copied B3 complete immutable receipt")
    return value
