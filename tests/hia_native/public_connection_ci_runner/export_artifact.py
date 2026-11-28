"""Archive complete portable sources and evidence, including empty process directories."""
from pathlib import Path
import argparse,hashlib,io,json,stat,subprocess,sys,tarfile
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
EXCLUDE=("transport-reference/rust-build","handshake-reference/rust-build")
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+"\n").encode()
def digest(path):
    with path.open("rb") as f:return hashlib.file_digest(f,"sha256").hexdigest()
def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("source","run","catalog-input","output"):p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args();source=a.source.resolve(strict=True);run=a.run.absolute();catalog=a.catalog_input.absolute()
    prefix=a.output.absolute();archive_path=Path(str(prefix)+".tar.gz");index_path=Path(str(prefix)+".archive.json")
    assert not archive_path.exists() and not index_path.exists();archive_path.parent.mkdir(parents=True,exist_ok=True)
    files={};directories={};objects={}
    def collect(root,label,exclude=()):
        if not root.is_dir():return
        for path in [root,*sorted(root.rglob("*"))]:
            rel=path.relative_to(root).as_posix()
            if any(rel==name or rel.startswith(name+"/") for name in exclude):continue
            assert not path.is_symlink();st=path.stat()
            key=label if rel=="." else label+"/"+rel
            if stat.S_ISDIR(st.st_mode):directories[key]=st.st_mode&0o777
            else:
                assert stat.S_ISREG(st.st_mode) and key not in files;files[key]=path
    collect(source,"recipe-source");collect(HERE,"runner-source");collect(run,"run",EXCLUDE);collect(catalog,"catalog-input")
    mapping={};manifest=run/"public/build/public-connection/manifest.json"
    if manifest.is_file():
        md=json.loads(manifest.read_bytes())
        for row in [*md["members"],md["link"],md["pack"]]:
            path=Path(row["manifest"]).resolve(strict=True);key="run/"+path.relative_to(run).as_posix()
            assert key in files;mapping[str(path)]=key
    objects["module-map.json"]=encoded(dict(schema="hepta.public83.portable-module-map.v1",modules=mapping))
    status="NOT_QUALIFIED";error=None;recipe=run/"RECIPE.json"
    if recipe.is_file() and json.loads(recipe.read_bytes()).get("status")=="PASS":
        command=[sys.executable,"-I","-B",str(HERE/"verify_complete.py"),"--source",str(source),
            "--run",str(run),"--require-fresh","--require-recipe-pass"]
        result=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        objects["EXPORT_READER.stdout"]=result.stdout;objects["EXPORT_READER.stderr"]=result.stderr
        objects["EXPORT_READER.json"]=encoded(dict(command=command,exit_code=result.returncode,
            stdout_sha256=SHA(result.stdout),stderr_sha256=SHA(result.stderr),native_or_rust_executed=False))
        if result.returncode==0:
            verification=json.loads(result.stdout);status=verification["status"]
            objects["EXPORT_READBACK.json"]=encoded(verification)
        else:error="complete readonly reader exit "+str(result.returncode)
    objects["ARTIFACT.json"]=encoded(dict(schema="hepta.public83.artifact.v1",status=status,
        complete_source_and_captures=True,excluded_rebuildable_only=["run/"+name for name in EXCLUDE],
        empty_directories_retained=True,readonly_export_reader_error=error,
        full_sdk_qualified=False,full_async_runtime_qualified=False,full_136_route_qualified=False,
        production_activated=False,old_path_removed=False))
    rows={key:dict(bytes=path.stat().st_size,sha256=digest(path)) for key,path in sorted(files.items())}
    for key,raw in objects.items():rows[key]=dict(bytes=len(raw),sha256=SHA(raw))
    objects["artifact-manifest.json"]=encoded(dict(schema="hepta.public83.artifact-manifest.v1",files=rows,
        directories=sorted(directories),complete_source_and_captures=True,existing_binary_inputs=False))
    with tarfile.open(archive_path,"w:gz",format=tarfile.PAX_FORMAT) as tar:
        for key,mode in sorted(directories.items()):
            info=tarfile.TarInfo(key);info.type=tarfile.DIRTYPE;info.mode=mode;info.mtime=0;tar.addfile(info)
        for key in sorted(set(files)|set(objects)):
            info=tarfile.TarInfo(key);info.mtime=0
            if key in files:
                path=files[key];info.size=path.stat().st_size;info.mode=path.stat().st_mode&0o777
                with path.open("rb") as f:tar.addfile(info,f)
            else:
                raw=objects[key];info.size=len(raw);info.mode=0o444;tar.addfile(info,io.BytesIO(raw))
    actual={};dirs=set();manifest_raw=None
    with tarfile.open(archive_path,"r:gz") as tar:
        for item in tar:
            if item.isdir():assert item.name not in dirs;dirs.add(item.name);continue
            assert item.isfile() and item.name not in actual
            with tar.extractfile(item) as f:
                raw=f.read() if item.name=="artifact-manifest.json" else None
                if raw is not None:manifest_raw=raw;size=len(raw);value=SHA(raw)
                else:
                    h=hashlib.sha256();size=0
                    for block in iter(lambda:f.read(1024*1024),b""):h.update(block);size+=len(block)
                    value=h.hexdigest()
            assert size==item.size;actual[item.name]=dict(bytes=size,sha256=value)
    assert manifest_raw==objects["artifact-manifest.json"] and dirs==set(directories)
    assert {key:value for key,value in actual.items() if key!="artifact-manifest.json"}==rows
    index=dict(schema="hepta.public83.archive.v1",archive=archive_path.name,bytes=archive_path.stat().st_size,
        sha256=digest(archive_path),files=len(actual),directories=len(dirs),
        uncompressed_bytes=sum(row["bytes"] for row in actual.values()),complete_archive_reread=True,
        status=status,readonly_export_reader_error=error)
    index_path.write_bytes(encoded(index));print(json.dumps(index,sort_keys=True))
    if error:raise SystemExit(2)
if __name__=="__main__":main()
