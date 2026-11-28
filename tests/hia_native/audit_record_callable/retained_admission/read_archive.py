"""Read every byte and mode of the complete fixed recovery archive, then relocate its files."""
from pathlib import Path, PurePosixPath
import argparse,hashlib,io,json,os,shutil,stat,tarfile,zipfile
ROOT=Path(__file__).resolve().parent
ZIP_SIZE=64906591
ZIP_SHA='3971b6fb20eb43d6f858934c687d80ce933399d59dc9900b14e9d1b2d295f364'
TAR_SIZE=65202915
TAR_SHA='29c7cc3c799bb37b19c1a400fa89b5dc92dc136216f75394ed69ac4a780fb6a6'
ADAPTER_SHA='b15f253b6fd6a0ae306c1844cef269df1c5477f9fcaac09b8f9cec6581129e8d'
BASE_SHA='35b5d7c107e0583ac3a25cdcabf5ec9f547fbb31840079c49b5486230b8281e6'
def need(value,message):
    if not value:raise ValueError(message)
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def file_pin(path):
    with path.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
    return dict(bytes=path.stat().st_size,sha256=digest,mode=stat.S_IMODE(path.stat().st_mode))
def relative(name):
    p=PurePosixPath(name)
    need(isinstance(name,str) and name and not p.is_absolute() and p.as_posix()==name
         and all(v not in ('','.', '..') for v in p.parts),'exact contained archive path')
    return p
def source():
    raw=(ROOT/'SOURCE.json').read_bytes();m=json.loads(raw)
    need({p.name for p in ROOT.iterdir()}==set(m['files'])|{'SOURCE.json'},'exact independent source set')
    for name,row in m['files'].items():
        body=(ROOT/relative(name)).read_bytes()
        need(len(body)==row['bytes'] and sha(body)==row['sha256']
             and hashlib.sha1(b'blob '+str(len(body)).encode()+b'\0'+body).hexdigest()==row['git_blob'],
             'complete independent source and Git identity')
    return sha(raw)
def restore(path,destination,report):
    own=source()
    need(not destination.exists(),'fresh independent relocation')
    raw=path.read_bytes()
    need(len(raw)==ZIP_SIZE and sha(raw)==ZIP_SHA,'complete uploaded ZIP identity')
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        need(set(z.namelist())=={'audit-record-io-recovery.tar.gz','audit-record-io-recovery.tar.gz.json'}
             and len(z.infolist())==2 and z.testzip() is None,'complete exact ZIP members and CRC')
        packed=z.read('audit-record-io-recovery.tar.gz')
        producer=json.loads(z.read('audit-record-io-recovery.tar.gz.json'))
    need(len(packed)==TAR_SIZE and sha(packed)==TAR_SHA,'complete inner recovery TAR identity')
    need(producer['status']=='PASS' and producer['bytes']==TAR_SIZE and producer['sha256']==TAR_SHA
         and producer['logical_files']==43411 and producer['logical_bytes']==2322155047
         and producer['unique_objects']==2458 and producer['original_producer_status']=='FAIL'
         and producer['all_objects_and_modes_reread'] is True
         and producer['all_logical_files_reread'] is True
         and producer['native_or_rust_executions']==0,'actual completed exporter receipt')
    destination.mkdir(parents=True)
    objects=destination.parent/(destination.name+'-objects');objects.mkdir(exist_ok=False)
    members={};manifest=None
    with tarfile.open(fileobj=io.BytesIO(packed),mode='r:gz') as tar:
        for item in tar:
            relative(item.name)
            need(item.isfile() and item.name not in members,'unique ordinary exact TAR member')
            with tar.extractfile(item) as stream:body=stream.read()
            need(len(body)==item.size,'complete TAR member')
            row=dict(bytes=len(body),sha256=sha(body),mode=item.mode);members[item.name]=row
            if item.name=='artifact-manifest.json':
                need(item.mode==0o644,'manifest mode');manifest=json.loads(body)
            else:
                need(item.name=='objects/'+row['sha256']+'-'+format(item.mode,'03o'),'complete content and mode address')
                out=objects/item.name;out.parent.mkdir(parents=True,exist_ok=True)
                with out.open('xb') as stream:stream.write(body)
                out.chmod(item.mode)
    need(isinstance(manifest,dict) and manifest['schema']=='hepta.audit-record-io.recovery-archive.v1'
         and manifest['git_head']=='baef371fa267e2d830788a1f504c6a48e382496b'
         and manifest['run_id']=='44039146687'
         and manifest['original_producer_run']==44036845015
         and manifest['original_producer_status']=='FAIL'
         and manifest['original_all_files_unchanged'] is True
         and manifest['native_or_rust_executions']==0
         and manifest['public_handler_qualified'] is False
         and manifest['whole_runtime_replaced'] is False,'fixed completed recovery identity')
    need(manifest['original_zip']==dict(bytes=29880685,sha256='30b0ab0030e4706360dd1ea24bbebd2e8a27380d0b57b930e38fc72c55277cf4'),'original FAIL retained')
    expected={};files=manifest['files']
    need(len(files)==43411 and sum(v['bytes'] for v in files.values())==2322155047,'all logical files and bytes')
    for name,row in files.items():
        target=destination/relative(name)
        need(set(row)=={'bytes','sha256','mode','object'} and type(row['mode']) is int
             and row['object']=='objects/'+row['sha256']+'-'+format(row['mode'],'03o'),'complete logical object binding')
        pin={k:row[k] for k in ('bytes','sha256','mode')}
        need(members.get(row['object'])==pin,'each logical file binds complete physical object')
        expected[row['object']]=pin;target.parent.mkdir(parents=True,exist_ok=True)
        with (objects/row['object']).open('rb') as src,target.open('xb') as dst:shutil.copyfileobj(src,dst,1<<20)
        target.chmod(row['mode'])
        need(file_pin(target)==pin,'every restored full logical file and mode')
    expected['artifact-manifest.json']=members['artifact-manifest.json']
    need(members==expected and len(expected)==2459,'complete exact object set')
    need(sha((destination/'recovery-source/RECOVERY_SOURCE.json').read_bytes())==ADAPTER_SHA
         and sha((destination/'retained/source/SOURCE.json').read_bytes())==BASE_SHA,'both complete frozen source roots')
    (destination/'ARCHIVE_MANIFEST.json').write_bytes(encoded(manifest))
    result=dict(schema='hepta.audit-record-io.independent-archive.v1',status='PASS',source_sha256=own,
        zip=dict(bytes=ZIP_SIZE,sha256=ZIP_SHA),tar=dict(bytes=TAR_SIZE,sha256=TAR_SHA),
        logical_files=len(files),logical_bytes=sum(v['bytes'] for v in files.values()),unique_objects=2458,
        all_uploaded_bytes_and_modes_read=True,all_logical_files_read=True,original_producer_status='FAIL',
        previous_recovery_export_status='FAIL',native_or_rust_executions=0,public_handler_qualified=False,
        whole_runtime_replaced=False)
    report.parent.mkdir(parents=True,exist_ok=True);report.write_bytes(encoded(result))
    print(encoded(result).decode(),end='')
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--zip',type=Path,required=True);p.add_argument('--destination',type=Path,required=True)
    p.add_argument('--report',type=Path,required=True)
    a=p.parse_args();restore(a.zip.resolve(strict=True),a.destination.absolute(),a.report.absolute())
