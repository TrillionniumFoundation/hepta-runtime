"""Archive all retained source/build/capture bytes and reread every member."""
from pathlib import Path
import argparse,hashlib,io,json,os,sys,tarfile
sys.dont_write_bytecode=True
SHA=lambda b:hashlib.sha256(b).hexdigest()
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+"\n").encode()
def digest(path):
    with path.open("rb") as f:return hashlib.file_digest(f,"sha256").hexdigest()
def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("source","run","output"):p.add_argument("--"+name,required=True,type=Path)
    a=p.parse_args();source=a.source.resolve(strict=True);run=a.run.absolute();prefix=a.output.absolute()
    assert not prefix.exists()
    archive_path=Path(str(prefix)+".tar.gz");index_path=Path(str(prefix)+".archive.json")
    assert not archive_path.exists() and not index_path.exists();archive_path.parent.mkdir(parents=True,exist_ok=True)
    objects={};files={}
    def collect(root,name,exclude_rust=False):
        for path in sorted(root.rglob("*")):
            rel=path.relative_to(root)
            if exclude_rust and rel.parts[:2]==("reference","rust-build"):continue
            if path.is_dir():continue
            assert path.resolve(strict=True)==path and path.is_file(),"only regular retained inputs"
            key=name+"/"+rel.as_posix();assert key not in files
            files[key]=path
    collect(source,"recipe-source")
    if run.is_dir():collect(run,"run",True)
    mapping={}
    manifest=run/"public/build/public-nine-serial-transport/manifest.json"
    if manifest.is_file():
        md=json.loads(manifest.read_bytes())
        for row in [*md["members"],md["link"],md["pack"]]:
            original=str(Path(row["manifest"]).resolve(strict=True))
            relative=Path(original).relative_to(run)
            key="run/"+relative.as_posix()
            assert key in files
            mapping[original]=key
    objects["module-map.json"]=encoded(dict(schema="hepta.public-serial81.portable-module-map.v1",modules=mapping))
    status="NOT_QUALIFIED";reader_error=None;verification=None
    recipe=run/"RECIPE.json"
    if recipe.is_file() and json.loads(recipe.read_bytes()).get("status")=="PASS":
        try:
            sys.path.insert(0,str(source/"drivers"))
            from verify_complete import verify
            verification=verify(source,run,require_recipe_pass=True)
            status=verification["status"]
        except BaseException as exc:reader_error=repr(exc)
    if verification is not None:objects["EXPORT_READBACK.json"]=encoded(verification)
    objects["ARTIFACT.json"]=encoded(dict(schema="hepta.public-serial81.artifact.v1",status=status,
        complete_source_and_captures=True,excluded_rebuildable_only=["run/reference/rust-build"],
        readonly_export_reader_error=reader_error,full_sdk_qualified=False,full_async_runtime_qualified=False,
        full_136_route_qualified=False,production_activated=False,old_path_removed=False))
    rows={key:dict(bytes=path.stat().st_size,sha256=digest(path)) for key,path in sorted(files.items())}
    for key,raw in objects.items():rows[key]=dict(bytes=len(raw),sha256=SHA(raw))
    objects["artifact-manifest.json"]=encoded(dict(schema="hepta.public-serial81.artifact-manifest.v1",files=rows,
        complete_source_and_captures=True,existing_binary_inputs=False))
    with tarfile.open(archive_path,"w:gz",format=tarfile.PAX_FORMAT) as archive:
        for key in sorted(set(files)|set(objects)):
            if key in files:
                archive.add(files[key],arcname=key,recursive=False)
            else:
                raw=objects[key];info=tarfile.TarInfo(key);info.size=len(raw);info.mode=0o444;info.mtime=0
                archive.addfile(info,io.BytesIO(raw))
    actual={};manifest_raw=None
    with tarfile.open(archive_path,"r:gz") as archive:
        for member in archive:
            assert member.isfile() and member.name not in actual
            h=hashlib.sha256();size=0;small=[]
            with archive.extractfile(member) as f:
                for block in iter(lambda:f.read(1024*1024),b""):
                    h.update(block);size+=len(block)
                    if member.name=="artifact-manifest.json":small.append(block)
            assert size==member.size
            actual[member.name]=dict(bytes=size,sha256=h.hexdigest())
            if small:manifest_raw=b"".join(small)
    assert manifest_raw==objects["artifact-manifest.json"]
    assert {k:v for k,v in actual.items() if k!="artifact-manifest.json"}==rows
    index=dict(schema="hepta.public-serial81.archive.v1",archive=archive_path.name,bytes=archive_path.stat().st_size,
        sha256=digest(archive_path),files=len(actual),uncompressed_bytes=sum(v["bytes"] for v in actual.values()),
        complete_archive_reread=True,status=status,readonly_export_reader_error=reader_error)
    index_path.write_bytes(encoded(index));print(json.dumps(index,sort_keys=True))
    if reader_error:raise SystemExit(2)
if __name__=="__main__":main()
