"""Preserve complete source, native captures and the exact retained reference ZIP."""
from pathlib import Path
import argparse, hashlib, json, shutil, sys, tarfile
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from check_source import check
def pin(path):
    with path.open("rb") as stream:return dict(bytes=path.stat().st_size,
        sha256=hashlib.file_digest(stream,"sha256").hexdigest())
def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("source","run","reference-zip","output"):p.add_argument("--"+name,required=True,type=Path)
    p.add_argument("--readonly-report",type=Path);a=p.parse_args()
    source=a.source.resolve(strict=True);check(source)
    output=a.output.absolute();output.mkdir(parents=True,exist_ok=False)
    shutil.copytree(source,output/"recipe-source")
    if a.run.exists():shutil.copytree(a.run.resolve(strict=True),output/"run")
    if a.reference_zip.exists():shutil.copyfile(a.reference_zip.resolve(strict=True),output/"reference.zip")
    if a.readonly_report and a.readonly_report.exists():
        shutil.copyfile(a.readonly_report.resolve(strict=True),output/"ci-readback.json")
    result=dict(schema="hepta.current-get-info.artifact.v1",status="NOT_QUALIFIED",
        full_sdk_qualified=False,full_async_runtime_qualified=False,production_activated=False,
        old_path_removed=False,public_frontend_registered=False)
    failed_reader=False
    if (output/"run/RECIPE.json").exists():
        recipe=json.loads((output/"run/RECIPE.json").read_bytes())
        if recipe["status"]=="PASS":
            try:
                from verify import verify
                observed=verify(output/"recipe-source",output/"run",output/"reference.zip",require_pass=True)
                if (output/"ci-readback.json").exists():
                    assert json.loads((output/"ci-readback.json").read_bytes())==observed
                result.update(status="GET_INFO_CURRENT_TARGET_PASS",readonly=observed)
            except BaseException as error:
                result.update(status="READBACK_FAIL",error=repr(error));failed_reader=True
    (output/"ARTIFACT.json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    files={}
    for path in sorted(output.rglob("*")):
        if path.is_dir():continue
        assert path.is_file() and not path.is_symlink()
        files[path.relative_to(output).as_posix()]=pin(path)
    manifest=dict(schema="hepta.current-get-info.artifact-manifest.v1",files=files,
                  complete_source_and_process_streams=True)
    (output/"artifact-manifest.json").write_text(json.dumps(manifest,sort_keys=True,indent=2)+"\n")
    archive=output.with_suffix(".tar.gz")
    assert not archive.exists()
    with tarfile.open(archive,"w:gz",compresslevel=6) as tar:
        for path in sorted(output.rglob("*")):
            tar.add(path,arcname=path.relative_to(output).as_posix(),recursive=False)
    expected=dict(files,**{"artifact-manifest.json":pin(output/"artifact-manifest.json")})
    actual={}
    with tarfile.open(archive,"r:gz") as tar:
        for member in tar:
            if member.isdir():continue
            assert member.isfile() and member.name not in actual
            stream=tar.extractfile(member);digest=hashlib.sha256();count=0
            while True:
                block=stream.read(1<<20)
                if not block:break
                count+=len(block);digest.update(block)
            actual[member.name]=dict(bytes=count,sha256=digest.hexdigest())
    assert actual==expected
    receipt=dict(archive=archive.name,**pin(archive),files=len(expected),status=result["status"],
                 complete_archive_reread=True)
    output.with_suffix(".archive.json").write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")
    print(json.dumps(receipt,sort_keys=True))
    if failed_reader:raise SystemExit(2)
if __name__=="__main__":main()
