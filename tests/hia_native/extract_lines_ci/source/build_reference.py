"""Fresh Rust 1.95 dev-profile build of the byte-exact Local target excerpts."""
from pathlib import Path
import argparse
import io
import os
import shutil
import sys
import tarfile
import tomllib
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
from common import encoded, files, loads, pin, read, require, sha, source
from process import Recorder, environment
from verify_reference import verify


PROFILE={'opt-level':1,'debug':2,'debug-assertions':True,'overflow-checks':True,
         'codegen-units':256,'lto':False,'incremental':False}


def build(output,rust_bin):
    frozen=source();original=verify()
    output.mkdir(parents=True,exist_ok=False)
    project=output/'project';shutil.copytree(ROOT/'reference',project)
    target=output/'target';require(not target.exists(),'fresh reference target directory')
    env,binding=environment(os.environ,rust_bin,target)
    rec=Recorder(ROOT,output/'processes',env)
    rustc=rust_bin/'rustc';cargo=rust_bin/'cargo';rustfmt=rust_bin/'rustfmt'
    versions={name:pin(read(path)) for name,path in [('rustc',rustc),('cargo',cargo),('rustfmt',rustfmt)]}
    config=['--config','build.rustc='+__import__('json').dumps(str(rustc))]
    for name,value in PROFILE.items():
        config+=['--config','profile.dev.'+name+'='+__import__('json').dumps(value)]
    rec.run('format',[rustfmt,'--check','--edition','2021','--config','hard_tabs=true,max_width=100',project/'src/main.rs'],timeout=60)
    raw,_=rec.run('rust-version',[rustc,'--version','--verbose'],timeout=60)
    require('\nrelease: 1.95.0\n' in raw.decode() and '\nhost: x86_64-unknown-linux-gnu\n' in raw.decode(),'exact reference toolchain')
    rec.run('cargo-version',[cargo,'--version','--verbose'],timeout=60)
    metadata_raw,_=rec.run('metadata',[cargo,*config,'metadata','--locked','--format-version=1',
        '--filter-platform','x86_64-unknown-linux-gnu','--manifest-path',project/'Cargo.toml'],timeout=180)
    metadata=loads(metadata_raw);packages=metadata['packages']
    require(len(packages)==16,'exact locked package count')
    target_packages={(p['name'],p['version'],p.get('source')):p.get('checksum')
        for p in tomllib.loads(read(project/'target/Cargo.lock').decode())['package']}
    records=[]
    for package in packages:
        if not package.get('source'):
            require(package['name']=='hepta-extract-lines-original-oracle','one exact root package');continue
        expected=target_packages[(package['name'],package['version'],package['source'])]
        crate=Path(package['manifest_path']).parent
        archive=crate.parent.parent.parent/'cache'/crate.parent.name/(crate.name+'.crate')
        archive_raw=read(archive);require(sha(archive_raw)==expected,'target registry archive checksum')
        retained=output/'registry'/crate.name;retained.mkdir(parents=True)
        (retained/'source.crate').write_bytes(archive_raw)
        rows={}
        with tarfile.open(fileobj=io.BytesIO(archive_raw),mode='r:gz') as stream:
            for entry in stream.getmembers():
                parts=Path(entry.name).parts
                require(parts and parts[0]==crate.name and '..' not in parts,'registry archive path')
                if entry.isdir():continue
                require(entry.isfile() and len(parts)>1,'registry regular source file')
                name=Path(*parts[1:]);raw=stream.extractfile(entry).read()
                require(read(crate/name)==raw,'actual compiled registry source equals full archive')
                destination=retained/'source'/name;destination.parent.mkdir(parents=True,exist_ok=True)
                destination.write_bytes(raw);destination.chmod(entry.mode&0o777)
                rows[name.as_posix()]=dict(**pin(raw),mode=entry.mode&0o777)
        records.append(dict(name=package['name'],version=package['version'],source=package['source'],
            checksum=expected,archive=str((retained/'source.crate').relative_to(output)),files=rows,
            compiled_root=str(crate)))
    require(len(records)==15 and not target.exists(),'all registry packages retained before fresh build')
    rec.run('rust-build',[cargo,*config,'build','--locked','--offline','--target','x86_64-unknown-linux-gnu',
        '--manifest-path',project/'Cargo.toml','--target-dir',target],timeout=900)
    binary=target/'x86_64-unknown-linux-gnu/debug/hepta-extract-lines-original-oracle'
    # Re-read the actual registry compilation inputs after the completed build.
    for row in records:
        for name,wanted in row['files'].items():
            require(pin(read(Path(row['compiled_root'])/name))=={k:wanted[k] for k in ('bytes','sha256')},
                    'registry input remains unchanged through actual compilation')
    require(files(project)==files(ROOT/'reference') and source()==frozen and verify()==original,
            'unchanged complete original source during fresh build')
    require(versions=={name:pin(read(path)) for name,path in [('rustc',rustc),('cargo',cargo),('rustfmt',rustfmt)]},
            'toolchain custody through actual build')
    executable=output/'original-extract-lines';shutil.copyfile(binary,executable);executable.chmod(0o500)
    result=dict(schema='hepta.extract-lines.original-build.v1',status='PASS',source_manifest_sha256=frozen,
        original_source=original,registry=records,toolchain=versions,profile=PROFILE,environment=binding,
        rust_bin=str(rust_bin),producer_root=str(output),executable=dict(path=executable.name,**pin(read(executable))),
        fresh_target_directory=True,fresh_locked_builds=1,exact_target_registry_packages=15,
        public_handler_qualified=False,whole_runtime_replaced=False)
    (output/'BUILD.json').write_bytes(encoded(result));print(encoded({k:result[k] for k in ('status','executable','fresh_locked_builds')}).decode(),end='')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--rust-bin',type=Path,required=True);a=p.parse_args()
    build(a.output.absolute(),a.rust_bin.resolve(strict=True))
