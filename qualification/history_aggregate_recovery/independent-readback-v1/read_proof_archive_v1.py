#!/usr/bin/env python3
"""Independently read every byte of a retained history-recovery proof archive.

This program imports no qualification, HIA loader or Rust reference code.
It writes only new readback outputs and verified copies of the proof members.
It never mutates the supplied ZIP or executes captured programs.
"""
from __future__ import annotations
import argparse,gzip,hashlib,json,os,stat,sys,tarfile,time,zipfile
from pathlib import Path,PurePosixPath

def need(value,label):
    if not value:raise ValueError(label)
def digest(data):return hashlib.sha256(data).hexdigest()
def file_pin(path):
    with path.open('rb') as f:return {'bytes':path.stat().st_size,'sha256':hashlib.file_digest(f,'sha256').hexdigest()}
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def stable_meta(value):
    return (value.st_mode,value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
def put(path,value):
    with path.open('xb') as f:f.write(encoded(value))
def ordinary(name):
    p=PurePosixPath(name)
    need(p.as_posix()==name and not p.is_absolute() and name and all(x not in ('','..','.') for x in p.parts),'ordinary relative archive member')
    return p
def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--zip',type=Path,required=True)
    parser.add_argument('--zip-bytes',type=int,required=True)
    parser.add_argument('--zip-sha256',required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--source-manifest-sha256',required=True)
    args=parser.parse_args();started=time.monotonic_ns()
    source=args.zip.absolute();out=args.output.absolute()
    need(not out.exists(),'new readback directory required')
    out.mkdir(mode=0o700,parents=True)
    before=source.stat();expected={'bytes':args.zip_bytes,'sha256':args.zip_sha256}
    need(file_pin(source)==expected,'entire GitHub ZIP size/digest')
    archive_path=out/'recovery-evidence.tar.gz'
    with zipfile.ZipFile(source) as z:
        need(z.namelist()==['manifest.json','recovery-evidence.tar.gz'],'exact ZIP member set and order')
        raw=z.read('manifest.json');manifest=json.loads(raw)
        need(manifest['schema']=='hepta.history.recovery-export.v1' and manifest['status']=='COMPLETE','complete exporter schema')
        need(manifest['original_artifact']==14274528318 and manifest['original_zip_sha256']=='9bb775eccc8fdb92a0eaf5c38021373c76a71ea7430ff43dfdd3636c42bc19b4','unchanged original artifact identity')
        need(manifest['native_or_rust_executions']==0 and manifest['original_failure_reclassified_as_pass'] is False,'no semantic replay/relabel scope')
        with (out/'manifest.json').open('xb') as f:f.write(raw)
        h=hashlib.sha256();size=0
        with z.open('recovery-evidence.tar.gz') as src,archive_path.open('xb') as dst:
            while block:=src.read(1024*1024):
                h.update(block);size+=len(block);dst.write(block)
        need({'bytes':size,'sha256':h.hexdigest()}==manifest['archive'],'complete compressed TAR identity')
    rows=manifest['members'];need(type(rows)is list and rows,'complete member manifest')
    need(len({r['path'] for r in rows})==len(rows),'no duplicate member paths')
    selected=out/'proof';selected.mkdir(mode=0o700)
    actual=[];files=logical=0
    with tarfile.open(archive_path,'r:gz') as tar:
        for index,member in enumerate(tar):
            need(index<len(rows),'unmanifested TAR member')
            row=rows[index];name=member.name;ordinary(name)
            need(name==row['path'] and member.mode==row['mode'],'TAR path/order/mode')
            need(member.isfile() or member.isdir(),'no link or special TAR member')
            need((member.isfile() and row['type']=='file') or (member.isdir() and row['type']=='directory'),'TAR exact type')
            target=selected.joinpath(*PurePosixPath(name).parts)
            if member.isdir():
                need(member.size==0,'directory TAR payload is empty')
                target.mkdir(mode=0o700,parents=True,exist_ok=False)
                actual.append({'path':name,'type':'directory','mode':member.mode})
                continue
            need(member.size==row['bytes'],'complete member extent')
            h=hashlib.sha256();count=0
            # Proof artifacts may contain a failed source copy. It is small and
            # is retained with every actual byte; never omit a failure member.
            with tar.extractfile(member) as src,target.open('xb') as dst:
                while block:=src.read(1024*1024):
                    count+=len(block);h.update(block);dst.write(block)
            need(count==row['bytes'] and h.hexdigest()==row['sha256'],'complete member digest: '+name)
            target.chmod(member.mode);files+=1;logical+=count
            actual.append({'path':name,'type':'file','mode':member.mode,'bytes':count,'sha256':h.hexdigest()})
    need(len(actual)==len(rows),'all manifested members present')
    for row in reversed(rows):
        if row['type']=='directory':selected.joinpath(*PurePosixPath(row['path']).parts).chmod(row['mode'])
    root=selected/'recovery';source_root=root/'recovery-source'
    source_raw=(source_root/'SOURCE_MANIFEST.json').read_bytes()
    need(digest(source_raw)==args.source_manifest_sha256,'frozen whole source-manifest bytes')
    closure=json.loads(source_raw);expected_sources=set(closure['files'])|{'SOURCE_MANIFEST.json'}
    real_sources={p.relative_to(source_root).as_posix() for p in source_root.rglob('*') if p.is_file()}
    need(real_sources==expected_sources,'complete recovery source file set')
    source_pins={}
    for name,row in closure['files'].items():
        path=source_root/name;raw=path.read_bytes()
        pin={'bytes':len(raw),'sha256':digest(raw)}
        blob=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
        need(pin=={k:row[k] for k in ('bytes','sha256')} and blob==row['git_blob'],'complete Git source byte identity: '+name)
        need(stat.S_IMODE(path.stat().st_mode)==0o644 and row['mode']=='100644','source mode')
        source_pins[name]={**pin,'git_blob':blob}
    source_pins['SOURCE_MANIFEST.json']={**file_pin(source_root/'SOURCE_MANIFEST.json'),
        'git_blob':hashlib.sha1(b'blob '+str(len(source_raw)).encode()+b'\0'+source_raw).hexdigest()}
    need(stable_meta(source.stat())==stable_meta(before),'input ZIP metadata changed')
    result={'schema':'hepta.history.recovery-independent-archive-readback.v1',
        'status':'COMPLETE_ARCHIVE_BYTES_AND_GIT_SOURCES_PASS','zip':expected,'inner_archive':manifest['archive'],
        'members':len(actual),'files':files,'logical_bytes':logical,'source_files':source_pins,
        'aggregate_recovery_pass':manifest['aggregate_recovery_pass'],
        'original_aggregate_failure_reclassified_as_pass':False,'native_or_rust_executions':0,
        'input_zip_unchanged':True,'elapsed_ns':time.monotonic_ns()-started,
        'reader_source':file_pin(Path(__file__))}
    put(out/'COMPLETE_READBACK.json',result)
    put(out/'COMPLETE_MEMBER_PINS.json',actual)
    print(json.dumps({k:v for k,v in result.items() if k!='source_files'},sort_keys=True))
if __name__=='__main__':main()
