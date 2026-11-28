"""Rebuild exact original payload bytes in an external cache, never in adapter state.

No provider call, launch, evaluation, state write, reservation change or token read.
The adapter separately obtains a fresh original-version manifest before import.
"""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import resource
import tarfile
import time

BASE = Path('/home/qian-qi/ndu-work/ndu-runtime-close-20261120-c2c548b7')
CACHE = BASE/'recovered_payload_cache'
RECORD = Path('/home/qian-qi/.local/state/hepta-kaggle-accounts/qiqian/batch/requests/hc-301097a07c1fb980f74152da554a52be6339c371/request.json')
STAGE = RECORD.parent/'.download-dz9ip7r7'
MANIFEST = STAGE/'hepta-execution-manifest.json'
ARCHIVE = STAGE/'mastery_complete.tar.xz'
SUMMARY = Path('/home/qian-qi/ndu-work/ndu-repair-mastery-20261120-aa42a9-v1/declared_summary_read_recovery_01/mastery_summary.json')
EXPECTED = {
 'request_id':'hc-301097a07c1fb980f74152da554a52be6339c371',
 'kernel_id':146145883,'notebook_version':1,
 'input_digest':'46d55a369a08fa3f2b61afa90b1e9c16de97778ed4fb7f00ddae8943e4de35bc',
 'notebook_ref':'alexqipku/hepta-hc-301097a07c1fb98-74fa89c23f4383d76acd1c0d',
 'submission_state':'ACCEPTED','remote_state':'COMPLETE'}
PINS = {
 'manifest':(MANIFEST,367127,'b435c98be3f1dfcb9d16b7127b5034d34390d55cce55a73f9c334679faad4397'),
 'archive':(ARCHIVE,731068,'93c13cfb9290f380fe7cc3593d20457f3d407d106099bbf041bd17f102791c33'),
 'summary':(SUMMARY,12033,'afa590134225eb742b14a0a235f1b6875af74baf43098b2d39b77a32e2f8b6a3')}
CAP = 8388608

def sha(raw):return hashlib.sha256(raw).hexdigest()
def raw_regular(path, maximum):
    import stat
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        s=os.fstat(fd)
        assert stat.S_ISREG(s.st_mode) and s.st_size<=maximum
        with os.fdopen(fd,'rb',closefd=False) as f:raw=f.read(maximum+1)
        assert len(raw)<=maximum
        return raw
    finally:os.close(fd)
def safe(name):
    assert isinstance(name,str) and name and not name.startswith('/') and '\\' not in name and '\x00' not in name
    assert all(p not in ('','.','..') and ':' not in p for p in name.split('/'))
    return name

def main():
    os.umask(0o077);t=time.monotonic();a=resource.getrusage(resource.RUSAGE_SELF)
    before=raw_regular(RECORD,16*1024*1024);record=json.loads(before)
    assert all(record.get(k)==v for k,v in EXPECTED.items())
    assert not record.get('artifacts'), 'already imported; inspect original state, do not repeat'
    bodies={}
    for key,(path,size,digest) in PINS.items():
        raw=raw_regular(path,size);assert len(raw)==size and sha(raw)==digest;bodies[key]=raw
    manifest=json.loads(bodies['manifest']);assert manifest['schema']=='hepta-artifact-manifest-v1' and manifest['request_id']==EXPECTED['request_id']
    declared={}
    for item in manifest['files']:
        name=safe(item['path']);assert name not in declared
        assert type(item['bytes']) is int and 0<=item['bytes']<=CAP
        assert isinstance(item['sha256'],str) and len(item['sha256'])==64
        declared[name]={'bytes':item['bytes'],'sha256':item['sha256']}
    assert len(declared)==2336
    assert sum(x['bytes'] for x in declared.values())==6635423
    assert sum(x['bytes'] for x in declared.values())+len(bodies['manifest'])==7002550<=CAP
    content={}
    for key in ('archive','summary'):
        raw=bodies[key];content[(len(raw),sha(raw))]=(raw,{'kind':'original_direct_file','name':key,'source':str(PINS[key][0])})
    members=0;expanded=0
    with tarfile.open(ARCHIVE,'r:xz') as archive:
        for member in archive:
            members+=1;assert members<=3000
            safe(member.name)
            if member.isdir():continue
            assert member.isfile() and not member.issym() and not member.islnk()
            expanded+=member.size;assert expanded<=16*1024*1024
            raw=archive.extractfile(member).read(member.size+1);assert len(raw)==member.size
            signature=(len(raw),sha(raw))
            # The exact immutable manifest, not member-name matching, determines output bytes.
            content.setdefault(signature,(raw,{'kind':'original_archive_member','name':member.name}))
    missing=[name for name,x in declared.items() if (x['bytes'],x['sha256']) not in content]
    assert not missing, {'missing_original_payloads':missing}
    assert sha(raw_regular(RECORD,16*1024*1024))==sha(before), 'original record changed during read; reconcile'
    assert not CACHE.exists() and not CACHE.is_symlink(), 'create-only external cache already exists; inspect same attempt'
    CACHE.mkdir(mode=0o700)
    mapping=[]
    for name,expected in sorted(declared.items()):
        raw,origin=content[(expected['bytes'],expected['sha256'])]
        p=CACHE/name;p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
        actual=raw_regular(p,expected['bytes']);assert len(actual)==expected['bytes'] and sha(actual)==expected['sha256']
        mapping.append({'path':name,**expected,'origin':origin})
    # This retained copy is input provenance only; importing adapter ignores it and fetches a fresh manifest.
    fd=os.open(CACHE/'hepta-execution-manifest.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(bodies['manifest']);f.flush();os.fsync(f.fileno())
    after=raw_regular(RECORD,16*1024*1024);assert sha(after)==sha(before)
    for key,(p,size,digest) in PINS.items():assert sha(raw_regular(p,size))==digest
    b=resource.getrusage(resource.RUSAGE_SELF)
    result={'schema':'ndu-original-external-cache-preparation-v1','status':'COMPLETE_EXACT_EXTERNAL_CACHE',
        'original_identity':EXPECTED,'cache_root':str(CACHE),'manifest_sha256':PINS['manifest'][2],
        'payload_files':len(mapping),'payload_bytes':sum(x['bytes'] for x in mapping),'payload_plus_manifest_bytes':7002550,
        'archive_members_examined':members,'archive_uncompressed_bytes':expanded,'files':mapping,
        'request_file_sha256_before':sha(before),'request_file_sha256_after':sha(after),
        'original_inputs_unchanged':True,'provider_calls':0,'adapter_state_writes':0,'router_state_writes':0,
        'new_science':False,'cost_prefix':{'wall_seconds':time.monotonic()-t,'self_cpu_seconds':b.ru_utime+b.ru_stime-a.ru_utime-a.ru_stime},
        'cost_scope':'through exact payload copies and original-input recheck; final receipt write/output/exit and orchestration excluded'}
    out=BASE/'external_cache_preparation.json';assert not out.exists()
    out.write_text(json.dumps(result,sort_keys=True,indent=2)+'\n');os.chmod(out,0o600)
    print(json.dumps({k:v for k,v in result.items() if k!='files'},sort_keys=True))
if __name__=='__main__':main()
