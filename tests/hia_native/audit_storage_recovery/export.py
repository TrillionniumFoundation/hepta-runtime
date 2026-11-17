"""Losslessly retain the old failed capture and every new read/control artifact; zero semantic execution."""
from pathlib import Path
import argparse
import hashlib
import io
import json
import os
import stat
import sys
import tarfile
import zipfile
ADAPTER=Path(__file__).resolve().parent
sys.path.insert(0,str(ADAPTER))
import restore

def encoded(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def sha(b):return hashlib.sha256(b).hexdigest()
def inventory(root):
    rows={}
    for folder,dirs,names in os.walk(root,followlinks=False):
        for n in dirs:
            if not stat.S_ISDIR((Path(folder)/n).lstat().st_mode):raise ValueError('ordinary retained directory')
        for n in names:
            path=Path(folder)/n;before=path.lstat()
            if not stat.S_ISREG(before.st_mode):raise ValueError('ordinary retained file')
            raw=path.read_bytes();after=path.lstat()
            if (before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_size,after.st_mtime_ns,after.st_ctime_ns):
                raise ValueError('stable full retained file')
            rows[path.relative_to(root).as_posix()]=dict(bytes=len(raw),sha256=sha(raw),mode=stat.S_IMODE(before.st_mode))
    return rows

def run(restored,recovery,archive,original_zip):
    raw_zip=original_zip.read_bytes()
    if len(raw_zip)!=restore.ZIP_SIZE or sha(raw_zip)!=restore.ZIP_SHA:raise ValueError('complete original ZIP before final export')
    with zipfile.ZipFile(io.BytesIO(raw_zip)) as z:
        if z.testzip() is not None:raise ValueError('original full ZIP CRC')
        packed=z.read('audit-record-io-complete.tar.gz')
    if len(packed)!=restore.TAR_SIZE or sha(packed)!=restore.TAR_SHA:raise ValueError('complete original TAR before final export')
    with tarfile.open(fileobj=io.BytesIO(packed),mode='r:gz') as t:
        original=json.load(t.extractfile('artifact-manifest.json'))
    expected={name:{k:row[k] for k in ('bytes','sha256','mode')} for name,row in original['files'].items()}
    if inventory(restored)!=expected:raise ValueError('every original failed or successful captured file remains unchanged')
    files={};objects={};paths={}
    for label,root in (('recovery-source',ADAPTER),('retained',restored),('recovery',recovery)):
        for name,row in inventory(root).items():
            key='objects/'+row['sha256']+'-'+format(row['mode'],'03o')
            path=root/name;files[label+'/'+name]=dict(**row,object=key);paths[label+'/'+name]=path
            if key in objects:
                if objects[key][0]!=row:raise ValueError('identical object identity')
            else:objects[key]=(row,path)
    gate={'status':'NO_FINAL_READ'}
    final=recovery/'final-read.json'
    if final.is_file():gate=json.loads(final.read_bytes())['evidence']
    manifest=dict(schema='hepta.audit-record-io.recovery-archive.v1',git_head=os.environ.get('GITHUB_SHA'),
        run_id=os.environ.get('GITHUB_RUN_ID'),files=files,gate=gate,
        original_producer_run=44036845015,original_producer_status='FAIL',
        original_zip=dict(bytes=len(raw_zip),sha256=sha(raw_zip)),original_all_files_unchanged=True,
        native_or_rust_executions=0,public_handler_qualified=False,whole_runtime_replaced=False)
    raw=encoded(manifest)
    with tarfile.open(archive,'w:gz',compresslevel=1,dereference=True) as target:
        for name,(row,path) in sorted(objects.items()):
            data=path.read_bytes()
            if len(data)!=row['bytes'] or sha(data)!=row['sha256']:raise ValueError('object changed')
            info=tarfile.TarInfo(name);info.size=len(data);info.mode=row['mode'];target.addfile(info,io.BytesIO(data))
        info=tarfile.TarInfo('artifact-manifest.json');info.size=len(raw);info.mode=0o644;target.addfile(info,io.BytesIO(raw))
    observed={}
    with tarfile.open(archive,'r|gz') as source:
        while m:=source.next():
            if not m.isfile() or m.name in observed:raise ValueError('exact unique archived object')
            with source.extractfile(m) as stream:
                digest=hashlib.file_digest(stream,'sha256').hexdigest()
            observed[m.name]=dict(bytes=m.size,sha256=digest,mode=m.mode);source.members.clear()
    expected={name:row for name,(row,path) in objects.items()}
    expected['artifact-manifest.json']=dict(bytes=len(raw),sha256=sha(raw),mode=0o644)
    if observed!=expected:raise ValueError('every completed archived byte and mode')
    for name,row in files.items():
        path=paths[name];data=path.read_bytes()
        if len(data)!=row['bytes'] or sha(data)!=row['sha256'] or stat.S_IMODE(path.lstat().st_mode)!=row['mode']:
            raise ValueError('final logical member re-read')
    with archive.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
    result=dict(schema='hepta.audit-record-io.recovery-archive-read.v1',status=gate['status'],
        bytes=archive.stat().st_size,sha256=digest,logical_files=len(files),
        logical_bytes=sum(row['bytes'] for row in files.values()),unique_objects=len(objects),
        original_producer_status='FAIL',all_objects_and_modes_reread=True,all_logical_files_reread=True,
        native_or_rust_executions=0,public_handler_qualified=False)
    archive.with_suffix(archive.suffix+'.json').write_bytes(encoded(result))
    print(encoded(result).decode(),end='')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--restored',type=Path,required=True);p.add_argument('--recovery',type=Path,required=True)
    p.add_argument('--archive',type=Path,required=True);p.add_argument('--original-zip',type=Path,required=True)
    a=p.parse_args();a.recovery.mkdir(parents=True,exist_ok=True)
    run(a.restored.resolve(strict=True),a.recovery.resolve(strict=True),a.archive.absolute(),a.original_zip.resolve(strict=True))
