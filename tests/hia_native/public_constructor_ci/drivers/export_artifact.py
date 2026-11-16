"""Archive portable source and full retained evidence; never execute native/Rust."""
from pathlib import Path
import argparse, gzip, hashlib, importlib.util, json, shutil, tarfile, traceback
SHA=lambda raw:hashlib.sha256(raw).hexdigest()

def digest(path):
    h=hashlib.sha256();count=0
    with path.open("rb") as handle:
        while block:=handle.read(1<<20):h.update(block);count+=len(block)
    return dict(bytes=count,sha256=h.hexdigest())

def put(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")

def no_links(root):
    assert not root.is_symlink()
    for path in root.rglob("*"):assert not path.is_symlink(),str(path)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("source","run","output"):parser.add_argument("--"+name,type=Path,required=True)
    args=parser.parse_args()
    source=args.source.resolve(strict=True);run=args.run.resolve()
    output=args.output.resolve()
    assert not output.exists() and not output.is_relative_to(source) and not output.is_relative_to(run)
    output.mkdir(parents=True)
    closure=json.loads((source/"source-manifest.json").read_bytes())
    package=output/"recipe-source";package.mkdir()
    for relative,pin in closure["files"].items():
        path=Path(relative);assert not path.is_absolute() and ".." not in path.parts
        original=source/path
        assert not original.is_symlink() and digest(original)==pin,relative
        target=package/path;target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(original,target)
    shutil.copyfile(source/"source-manifest.json",package/"source-manifest.json")
    retained=output/"run";retained.mkdir()
    if run.is_dir():
        for path in sorted(run.iterdir()):
            assert not path.is_symlink()
            if path.is_file():shutil.copyfile(path,retained/path.name)
            elif path.is_dir():
                if path.name=="original":
                    target=retained/path.name;target.mkdir()
                    for child in sorted(path.iterdir()):
                        if child.name=="rust-build":continue
                        assert not child.is_symlink()
                        if child.is_dir():no_links(child);shutil.copytree(child,target/child.name)
                        elif child.is_file():shutil.copyfile(child,target/child.name)
                else:
                    no_links(path);shutil.copytree(path,retained/path.name)
    mappings={}
    manifest=run/"public/build/public-nine-constructor/manifest.json"
    if manifest.is_file():
        graph=json.loads(manifest.read_bytes())
        for row in [*graph["members"],graph["link"],graph["pack"]]:
            original=Path(row["manifest"]).resolve(strict=True)
            assert digest(original)["sha256"]==row["manifest_sha256"]
            if original.is_relative_to(run):
                target=retained/original.relative_to(run)
            else:
                target=output/"retained-modules"/row["manifest_sha256"]/"manifest.json"
                if not target.parent.exists():
                    no_links(original.parent);shutil.copytree(original.parent,target.parent)
            assert digest(target)["sha256"]==row["manifest_sha256"]
            mappings[row["manifest"]]=str(target.relative_to(output))
    put(output/"module-map.json",dict(schema="hepta.runtime.public-constructor-retained-modules.v1",modules=mappings))
    verified=dict(status="NOT_QUALIFIED",reason="A completed successful recipe is required; partial evidence is retained.")
    recipe=retained/"RECIPE.json"
    if recipe.is_file() and json.loads(recipe.read_bytes()).get("status")=="PASS":
        try:
            spec=importlib.util.spec_from_file_location("_retained_constructor_reader",package/"drivers/verify_complete.py")
            reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(reader)
            verified=reader.verify(package,retained,output/"module-map.json",True)
        except BaseException:
            verified=dict(status="READONLY_FAIL",failure=traceback.format_exc())
    put(output/"retained-verification.json",verified)
    files={}
    for path in sorted(output.rglob("*")):
        assert not path.is_symlink()
        if path.is_file():files[str(path.relative_to(output))]=digest(path)
    doc=dict(schema="hepta.runtime.public-constructor-artifact-closure.v1",files=files,
        qualification_status=verified["status"],archiving_is_not_qualification=True,
        omitted_rebuildable_directories=["run/original/rust-build"],
        original_executable_retained_at="run/original/reference-bin")
    put(output/"artifact-manifest.json",doc)
    archive=output.with_suffix(".tar.gz");assert not archive.exists()
    with archive.open("xb") as handle, gzip.GzipFile(fileobj=handle,mode="wb",filename="",mtime=0) as compressed:
        with tarfile.open(fileobj=compressed,mode="w") as tar:
            for path in sorted(output.rglob("*")):
                if path.is_file():tar.add(path,arcname=str(path.relative_to(output)),recursive=False)
    expected=set(files)|{"artifact-manifest.json"}
    with tarfile.open(archive,"r:gz") as tar:
        members=tar.getmembers()
        assert len(members)==len(expected) and {m.name for m in members}==expected
        for member in members:
            assert member.isfile()
            h=hashlib.sha256();count=0
            with tar.extractfile(member) as handle:
                while block:=handle.read(1<<20):h.update(block);count+=len(block)
            pin=dict(bytes=count,sha256=h.hexdigest())
            if member.name=="artifact-manifest.json":assert pin==digest(output/member.name)
            else:assert pin==files[member.name]
    result=dict(archive=str(archive),archive_bytes=archive.stat().st_size,
        archive_sha256=digest(archive)["sha256"],members=len(expected),
        artifact_manifest_sha256=digest(output/"artifact-manifest.json")["sha256"],
        qualification_status=verified["status"],archive_readback_pass=True)
    put(output.with_suffix(".archive.json"),result)
    print(json.dumps(result,sort_keys=True),flush=True)
    if verified["status"]=="READONLY_FAIL":
        raise SystemExit(2)

if __name__=="__main__":main()

