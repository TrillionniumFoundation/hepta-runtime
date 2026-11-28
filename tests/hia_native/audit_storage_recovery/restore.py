"""Restore and inspect every byte of the completed record-I/O failure; no semantic execution."""
from pathlib import Path
import argparse
import hashlib
import io
import json
import os
import shutil
import stat
import tarfile
import tomllib
import zipfile

ZIP_SHA='30b0ab0030e4706360dd1ea24bbebd2e8a27380d0b57b930e38fc72c55277cf4'
ZIP_SIZE=29880685
TAR_SHA='65b9f6d62c521c12d74c455c85aa3ab770f7559392ba071a57028d122b7d3257'
TAR_SIZE=30010406

def require(value,message):
    if not value:raise ValueError(message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
def restore(zip_path,destination):
    raw=zip_path.read_bytes();require(len(raw)==ZIP_SIZE and sha(raw)==ZIP_SHA,'complete original failure ZIP')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        require(archive.testzip() is None,'all ZIP CRC bytes')
        require(set(archive.namelist())=={'audit-record-io-complete.tar.gz','audit-record-io-complete.tar.gz.json'},
                'exact two retained export members')
        packed=archive.read('audit-record-io-complete.tar.gz')
        producer=json.loads(archive.read('audit-record-io-complete.tar.gz.json'))
    require(len(packed)==TAR_SIZE and sha(packed)==TAR_SHA,'complete retained TAR')
    objects={}
    with tarfile.open(fileobj=io.BytesIO(packed),mode='r:gz') as archive:
        for entry in archive:
            require(entry.isfile() and entry.name not in objects,'unique regular exported object')
            stream=archive.extractfile(entry)
            body=stream.read();require(len(body)==entry.size,'complete export object')
            objects[entry.name]=(body,entry.mode)
    manifest_raw,manifest_mode=objects.pop('artifact-manifest.json')
    manifest=json.loads(manifest_raw)
    require(manifest['git_head']=='c4a4857148765d214ad3760dde9e127ebcabfada'
        and manifest['run_id']=='44036845015','original exact failed source/run binding')
    wanted=set()
    destination.mkdir(parents=True,exist_ok=False)
    for name,row in manifest['files'].items():
        rel=Path(name)
        require(not rel.is_absolute() and '..' not in rel.parts and rel.parts[0] in ('source','run'),
                'complete relative logical path')
        body,mode=objects[row['object']];wanted.add(row['object'])
        require(len(body)==row['bytes'] and sha(body)==row['sha256'] and mode==row['mode'],
                'every complete logical object pin and mode')
        path=destination/rel;path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(body);path.chmod(mode)
        require(path.read_bytes()==body and stat.S_IMODE(path.stat().st_mode)==mode,
                'every restored logical file independently reread')
    require(wanted==set(objects),'no absent or unreferenced export object')
    result=dict(status='COMPLETE_FAILED_CAPTURE_RESTORED',zip=dict(bytes=len(raw),sha256=sha(raw)),
        tar=dict(bytes=len(packed),sha256=sha(packed)),producer=producer,
        logical_files=len(manifest['files']),logical_bytes=sum(x['bytes'] for x in manifest['files'].values()),
        all_object_bytes_and_modes_read=True,all_logical_files_reread=True,
        native_or_rust_executions=0,original_failure_preserved=True)
    return result

def inspect(destination):
    root=destination/'run/semantic'
    omissions=[];mismatches=[];counts={}
    for archive in sorted((root/'crates').iterdir()):
        package=archive.name[:-6]
        folder=root/'vendor'/package
        checksum=json.loads((folder/'.cargo-checksum.json').read_bytes())
        members={}
        with tarfile.open(archive,'r:gz') as source:
            for member in source:
                if member.isdir():continue
                require(member.isfile() and member.name.startswith(package+'/'),'regular registry member')
                name=member.name[len(package)+1:]
                with source.extractfile(member) as stream:raw=stream.read()
                members[name]=dict(bytes=len(raw),sha256=sha(raw),mode=member.mode)
                path=folder/name
                if not path.is_file():
                    omissions.append(dict(package=package,path=name,**members[name]))
                elif path.read_bytes()!=raw:mismatches.append(dict(package=package,path=name))
        actual={p.relative_to(folder).as_posix() for p in folder.rglob('*') if p.is_file()}
        require(actual==set(checksum['files'])|{'.cargo-checksum.json'},'complete Cargo vendor file set')
        require(set(checksum['files'])<=set(members),'every compiled registry source exists in exact archive')
        counts[package]=dict(archive_members=len(members),vendor_members=len(checksum['files']))
    result=dict(status='READ_ONLY_REGISTRY_DIAGNOSIS',omissions=omissions,mismatches=mismatches,packages=counts,
        native=json.loads((root/'native/NATIVE.json').read_bytes()),
        original=json.loads((root/'original/ORIGINAL.json').read_bytes()),
        build=json.loads((root/'build/BUILD.json').read_bytes())['modules'],
        native_or_rust_executions=0)
    return result

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--zip',type=Path,required=True);p.add_argument('--destination',type=Path,required=True)
    p.add_argument('--report',type=Path,required=True)
    a=p.parse_args();proof=restore(a.zip,a.destination);proof['diagnosis']=inspect(a.destination)
    a.report.write_bytes(encoded(proof));print(encoded(proof).decode(),end='')
