"""Actual mutations of physical evidence copies; no native or Rust replay."""
from __future__ import annotations
import argparse
import gzip
import json
import os
from pathlib import Path
import shutil
import sys

sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import BASE,ORACLE,document,encoded,put,read,require,sha,tree_files
from reader import lines,read_capture

NAMES=('native-input-buffer','native-output-buffer','native-workspace-buffer','native-output-tail',
    'omitted-native-case','private-binding','original-result','source-owner','module-image',
    'packed-executable','compile-output-tail','original-source','registry-archive',
    'native-process-pid','native-process-deadline','original-process-pid')


def copy_capture(capture,destination):
    index=document(capture/'CAPTURE.json')
    destination.mkdir(parents=True,exist_ok=False)
    for name,row in index['files'].items():
        raw=read(capture/name)
        require(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'producer changed before physical copy')
        target=destination/name;put(target,raw);target.chmod(row['mode'])
        require((target.stat().st_dev,target.stat().st_ino)!=(
            (capture/name).stat().st_dev,(capture/name).stat().st_ino),'physical reader copy shares an inode')
    put(destination/'CAPTURE.json',read(capture/'CAPTURE.json'))
    (destination/'CAPTURE.json').chmod((capture/'CAPTURE.json').stat().st_mode&0o777)


def replace_owned(path,raw,mode):
    # These are our independent mutation copies, never producer files. A fixed
    # ELF is intentionally 0555; permit the fixture write only temporarily, and
    # restore its exact admitted mode before the read-only verifier sees it.
    require(path.is_file() and not path.is_symlink() and path.resolve()==path.absolute(),'owned mutation file kind')
    path.chmod(mode|0o200)
    try:
        with path.open('wb') as stream:stream.write(raw)
    finally:
        path.chmod(mode)


def compact_lines(rows):
    return b''.join((json.dumps(row,sort_keys=True,separators=(',',':'))+'\n').encode() for row in rows)


def mutation_data(capture):
    calls=lines(capture/'native/calls.jsonl')
    success=next(row for row in calls if row['module']==0 and row['code']==168)
    for label,field,offset in [('native-input-buffer','input',0),('native-output-buffer','output',0),
        ('native-workspace-buffer','workspace',352),('native-output-tail','output',-1)]:
        ref=success['after'][field]
        path='native/buffers/'+ref['sha256']+'.gz'
        raw=bytearray(gzip.decompress(read(capture/path)));raw[offset]^=1
        yield label,path,gzip.compress(bytes(raw),compresslevel=1,mtime=0)
    rows=lines(capture/'native/rows.jsonl')
    yield 'omitted-native-case','native/rows.jsonl',compact_lines(rows[:-1])
    bound=next(row for row in rows if row['binding'] is not None)
    owner=bound['binding']['owner'];bound['binding']=dict(bound['binding'],owner=('1' if owner[0]=='0' else '0')+owner[1:])
    yield 'private-binding','native/rows.jsonl',compact_lines(rows)
    build=document(capture/'native-build.json')
    module=Path(build['modules']['native/caller_authority.hepta']).parent
    graph=Path(build['manifest']).parent
    fixed=[('original-result','processes/original-replay.stdout',1),
        ('source-owner','source/native/caller_authority.hepta',1),
        ('module-image',(module/'module.image.bin').as_posix(),0),
        ('packed-executable',(graph/'native-authority.elf').as_posix(),-1),
        ('compile-output-tail',(module/'module.output.bin').as_posix(),-1),
        ('original-source','source/'+ORACLE+'/original_access.rs',1)]
    for label,path,offset in fixed:
        raw=bytearray(read(capture/path));raw[offset]^=1
        yield label,path,bytes(raw)
    crate=sorted(document(capture/'registry.json')['packages'])[0]
    path='registry/'+crate+'.crate';raw=bytearray(read(capture/path));raw[-1]^=1
    yield 'registry-archive',path,bytes(raw)
    for label,path,field in [('native-process-pid','processes/native-replay.json','pid'),
        ('native-process-deadline','processes/native-replay.json','timeout_seconds'),
        ('original-process-pid','processes/original-replay.json','pid')]:
        row=document(capture/path);row[field]+=1
        if field=='pid':row['pgid']=row['pid']
        yield label,path,encoded(row)


def run(capture,output,pins_sha):
    baseline=read_capture(capture,capture/'source',pins_sha)
    before=tree_files(capture)
    output.mkdir(parents=True,exist_ok=False)
    clone=output/'temporary-reader-copy';copy_capture(capture,clone)
    sealed=read(clone/'CAPTURE.json');rows=[]
    for name,relative,changed in mutation_data(capture):
        original=read(clone/relative)
        put(output/'mutations'/name/'bytes.bin',changed)
        mode=document(clone/'CAPTURE.json')['files'][relative]['mode']
        replace_owned(clone/relative,changed,mode)
        index=json.loads(sealed);index['files'][relative].update(bytes=len(changed),sha256=sha(changed))
        # Rebind only the container hash. Inner native/source/build/original
        # custody must independently reject the retained changed bytes.
        (clone/'CAPTURE.json').write_bytes(encoded(index))
        try:
            read_capture(clone,capture/'source',pins_sha)
        except (ValueError,KeyError,EOFError,OSError,json.JSONDecodeError) as exc:
            rows.append({'name':name,'path':relative,'original_sha256':sha(original),
                'mutated_sha256':sha(changed),'mutated_bytes':len(changed),
                'base_capture_sha256':baseline['capture_sha256'],'rebound_index_sha256':sha(encoded(index)),
                'refusal_type':type(exc).__name__,'refusal':str(exc)})
        else:raise ValueError('strict reader admitted mutation '+name)
        finally:
            replace_owned(clone/relative,original,mode)
            (clone/'CAPTURE.json').write_bytes(sealed)
    require(tuple(row['name'] for row in rows)==NAMES,'fixed reader refusal inventory')
    require(read_capture(clone,clone/'source',pins_sha)==baseline,'restored physical reader copy differs')
    require(tree_files(capture)==before,'reader controls changed producer evidence')
    shutil.rmtree(clone)
    put(output/'report.json',{'schema':'hepta.runtime.owner-export-reader-controls.v1',
        'pid':os.getpid(),'ppid':os.getppid(),'pgid':os.getpgrp(),'rows':rows,
        'native_or_rust_executions':0,'base_capture_sha256':baseline['capture_sha256'],
        'producer_unchanged':True,'restored_physical_copy_pass':True})
    print('OWNER_EXPORT_READER_CONTROLS_PASS',len(rows),flush=True)


if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--capture',required=True,type=Path)
    p.add_argument('--output',required=True,type=Path)
    p.add_argument('--source-pins-sha256',required=True)
    args=p.parse_args();run(args.capture.absolute(),args.output.absolute(),args.source_pins_sha256)
