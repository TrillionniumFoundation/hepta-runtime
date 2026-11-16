#!/usr/bin/env python3
"""Retain portable source, exact build artifacts, modules and public streams."""
from pathlib import Path
import argparse, gzip, hashlib, importlib.util, json, shutil, tarfile, traceback
SHA=lambda data:hashlib.sha256(data).hexdigest()

def put(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('source','build','loop','output'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--recipe-root',type=Path)
    args=parser.parse_args();source=args.source.resolve(strict=True);output=args.output.resolve()
    assert not output.exists() and not output.is_relative_to(source);output.mkdir(parents=True)
    closure=json.loads((source/'source-manifest.json').read_bytes())
    package=output/'recipe-source';package.mkdir()
    for relative,pin in closure['files'].items():
        name=Path(relative);assert not name.is_absolute() and '..' not in name.parts
        raw=(source/name).read_bytes();assert pin=={'bytes':len(raw),'sha256':SHA(raw)},relative
        target=package/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
    shutil.copyfile(source/'source-manifest.json',package/'source-manifest.json')
    run=output/'run';run.mkdir()
    for path,name in ((args.build,'public-nine'),(args.loop,'public-loop')):
        if path.is_dir():shutil.copytree(path,run/name)
    if args.recipe_root is not None:
        root=args.recipe_root.resolve(strict=True)
        for name in ('RECIPE.json','verification.json'):
            if (root/name).is_file():shutil.copyfile(root/name,run/name)
        for name in ('processes','retained-eight'):
            if (root/name).is_dir():shutil.copytree(root/name,run/name)
    modules={};original_root=args.build.resolve();manifest=original_root/'build/public-nine/manifest.json'
    if manifest.is_file():
        md=json.loads(manifest.read_bytes())
        for row in [*md['members'],md['link'],md['pack']]:
            original=Path(row['manifest']).resolve(strict=True)
            if original.is_relative_to(original_root):
                retained=run/'public-nine'/original.relative_to(original_root)
            else:
                retained=output/'retained-modules'/original.parent.name/'manifest.json'
                if not retained.parent.exists():shutil.copytree(original.parent,retained.parent)
            assert SHA(retained.read_bytes())==row['manifest_sha256']
            modules[str(original)]=str(retained.relative_to(output))
    put(output/'module-map.json',{'schema':'hepta.runtime.public-nine-retained-modules.v1','modules':modules})
    verification={'status':'NOT_RUN','reason':'complete successful build and loop are required'}
    if manifest.is_file() and (args.loop/'summary.json').is_file():
        try:
            spec=importlib.util.spec_from_file_location('_retained_nine_reader',package/'scripts/verify_native_nine.py')
            reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(reader)
            verification=reader.verify(package/'source',run/'public-nine',run/'public-loop',output/'module-map.json')
        except BaseException:verification={'status':'READONLY_FAIL','failure':traceback.format_exc()}
    put(output/'retained-verification.json',verification)
    files={}
    for path in sorted(output.rglob('*')):
        assert not path.is_symlink(),path
        if path.is_file():
            raw=path.read_bytes();files[str(path.relative_to(output))]={'bytes':len(raw),'sha256':SHA(raw)}
    manifest_doc={'schema':'hepta.runtime.public-nine-native-artifact-closure.v1','files':files,
        'qualification_status':verification['status'],'archiving_is_not_qualification':True}
    put(output/'artifact-manifest.json',manifest_doc)
    archive=output.with_suffix('.tar.gz');assert not archive.exists()
    with archive.open('xb') as stream, gzip.GzipFile(fileobj=stream,mode='wb',mtime=0) as compressed:
        with tarfile.open(fileobj=compressed,mode='w') as tar:
            for path in sorted(output.rglob('*')):
                if path.is_file():tar.add(path,arcname=str(path.relative_to(output)),recursive=False)
    wanted=set(files)|{'artifact-manifest.json'}
    with tarfile.open(archive,'r:gz') as tar:
        assert {m.name for m in tar.getmembers()}==wanted
        for member in tar:
            assert member.isfile();data=tar.extractfile(member).read()
            if member.name=='artifact-manifest.json':assert data==(output/member.name).read_bytes()
            else:assert files[member.name]=={'bytes':len(data),'sha256':SHA(data)}
    result={'archive':str(archive),'archive_bytes':archive.stat().st_size,'archive_sha256':SHA(archive.read_bytes()),
        'members':len(wanted),'artifact_manifest_sha256':SHA((output/'artifact-manifest.json').read_bytes()),
        'qualification_status':verification['status'],'archive_readback_pass':True}
    put(output.with_suffix('.archive.json'),result);print(json.dumps(result,sort_keys=True),flush=True)

if __name__=='__main__':main()
