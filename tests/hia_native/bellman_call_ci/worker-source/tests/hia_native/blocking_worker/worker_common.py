"""Strict finite source and evidence files; verification helpers never write."""
from __future__ import annotations
import hashlib,json,os,stat
from pathlib import Path,PurePosixPath

BASE='tests/hia_native/blocking_worker'
COMPILER_COMMIT='d3e2c90173cf733e42b299d0c4274df4b593a12f'
COMPILER_TREE='8d8b0fb8d015fb7edab302498bb9ed4c74ab6f49'
COMPILER_IMAGE='bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'
SOURCE_PINS=BASE+'/worker-source-pins.json'
TARGET='d3d75c30719db966b004756f610007a7c723729e'
ORIGINAL_SHA='254de61b7a169ab0a01583feb9562051fa9d477d89d98683263c52ea5545a4a7'

def require(condition,message):
    if not condition:raise AssertionError(message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def git_blob(raw):return hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
def encoded(value):return (json.dumps(value,indent=2,sort_keys=True)+'\n').encode()
def read(path):
    info=path.lstat();require(stat.S_ISREG(info.st_mode),'evidence is not a regular file: '+str(path))
    return path.read_bytes()
def document(path):return json.loads(read(path))
def put(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_bytes(value if isinstance(value,bytes) else encoded(value))
def safe_relative(name):
    p=PurePosixPath(name)
    require(type(name) is str and name and not p.is_absolute() and p.as_posix()==name and all(x not in ('','.','..') for x in p.parts),'noncanonical relative path')
    return name
def tree_files(root):
    require(stat.S_ISDIR(root.lstat().st_mode),'root is not an actual directory')
    rows={}
    def walk(folder):
        with os.scandir(folder) as entries:
            for entry in sorted(entries,key=lambda e:e.name):
                path=Path(entry.path);mode=entry.stat(follow_symlinks=False).st_mode
                if stat.S_ISDIR(mode):walk(path)
                else:
                    require(stat.S_ISREG(mode),'unadmitted evidence object: '+str(path))
                    raw=read(path);rows[path.relative_to(root).as_posix()]={'bytes':len(raw),'sha256':sha(raw)}
    walk(root);return rows
def source_evidence(root,expected):
    raw=read(root/SOURCE_PINS);require(sha(raw)==expected,'source pin document changed')
    proof=json.loads(raw)
    require(proof['schema']=='hepta.runtime.bellman-worker-source.v1' and proof['target_commit']==TARGET,'source target changed')
    require(proof['compiler_commit']==COMPILER_COMMIT and proof['compiler_image_sha256']==COMPILER_IMAGE,'compiler source profile changed')
    actual=tree_files(root);require(set(actual)==set(proof['files'])|{SOURCE_PINS},'source inventory changed')
    for name,pin in proof['files'].items():
        safe_relative(name);b=read(root/name)
        require(actual[name]=={'bytes':pin['bytes'],'sha256':pin['sha256']} and git_blob(b)==pin['git_blob'],'source bytes changed: '+name)
    require(sha(read(root/(BASE+'/reference/weight_bellman.rs')))==ORIGINAL_SHA,'original target identity changed')
    return {'source_pins_sha256':expected,'files':proof['files'],'target_commit':TARGET}

def process_evidence(root,label,command,limit,*,stdin=None):
    r=document(root/'processes'/(label+'.json'))
    require(r['label']==label and r['command']==list(map(str,command)),'actual command differs: '+label)
    require(r['started'] is True and r['timed_out'] is False and r['returncode']==0 and 'failure' not in r,'process did not succeed: '+label)
    require(r['timeout_seconds']==limit and 0<=r['elapsed_ns']<=limit*1000000000,'process deadline differs: '+label)
    require(type(r['pid']) is int and r['pid']==r['pgid'] and r['pid']>0 and r['parent_pid']>0,'process custody differs: '+label)
    require(r['stdin_sha256']==(sha(stdin) if stdin is not None else None),'actual process input differs: '+label)
    for channel in ['stdout','stderr']:
        relative='processes/'+label+'.'+channel;b=read(root/relative)
        require(r[channel]=={'path':relative,'bytes':len(b),'sha256':sha(b)},'complete process stream differs: '+label)
    return r
