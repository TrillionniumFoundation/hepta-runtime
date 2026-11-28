"""Prepare an immutable reviewed adapter release and a proposed reversible entry switch.

This script does not switch the live launcher, call a provider, or write an
adapter/router ledger. Activation is a separate exact-version binary_write.
"""
import ast
import hashlib
import json
import os
from pathlib import Path
import resource
import stat
import subprocess
import time

TASK = Path('/home/qian-qi/ndu-work/ndu-runtime-close-20261120-c2c548b7')
INPUT = TASK/'candidate/tools/cloud-compute/kaggle'
OLD_RELEASE = Path('/home/qian-qi/.local/share/hepta-kaggle/releases/batch-0.1.12-gpuimage-4920')
NEW_RELEASE = Path('/home/qian-qi/.local/share/hepta-kaggle/releases/batch-0.1.13-cache-import-c2c548b7')
OLD_LAUNCHER = Path('/home/qian-qi/.local/share/hepta-kaggle/multiaccount-v7-gpuimage-4920/account_launcher.py')
NEW_LAUNCHER = Path('/home/qian-qi/.local/share/hepta-kaggle/multiaccount-cache-import-c2c548b7/account_launcher.py')
ENTRY = Path('/home/qian-qi/.local/bin/hepta-kaggle-account')
OLD_HASHES = {
 'kaggle_jobs.py':'44405daa976f741639ca9596ced1e131263e17e90b71b81010b4947c60a4a337',
 'kaggle_create_only.py':'c655c00729b5b1db3b1e8832599d9088c848c098e7ad1641200c97cca12459da',
 'kaggle_transport.py':'99e44c8054eab22534399de3eef9088fcbb98406f64726ab99241d6b5054566c',
 'hepta_kaggle.py':'5579284b9655da80269a9dd9c0de535ff13ce5827d9cfcd467d9f99ea9567853',
 'tool_contract.py':'34cc0fe783cb813919964163e0fbe69efc816b3fb23bb027ea692b7c8434ae95'}
NEW_HASHES = {
 'kaggle_jobs.py':'7a4f8ea009f3761a63e7fdffc80ecc8759df68aeb6bb11e692f659d483c4ca1b',
 'kaggle_create_only.py':'9bc161048319d14e0cf855f6d4aa937478486842237b1ca6675b5b68e60e0648',
 'kaggle_transport.py':'99e44c8054eab22534399de3eef9088fcbb98406f64726ab99241d6b5054566c',
 'hepta_kaggle.py':'5cbc8455d4482f3d6223cb51f981c302780779f4a1f51325076dea4583a2f864',
 'tool_contract.py':'fd5e91d791831d6eca57594ea925e78ff3d9426d08c69c3b326f2a24d6bb89da'}
OLD_ENTRY_SHA='83cb827b69028c6312ea1560c92d9cbb6c5fd6eb0dbb5597623f98b12a76b5de'
OLD_LAUNCHER_SHA='12cbbd077338b7d034531f7ba188f41d1525c96ace5a55e18c7124eacbd2affe'

def sha(b):return hashlib.sha256(b).hexdigest()
def read(path):
    # Pin each ancestor without following links, then read a current-user single-link file.
    p=Path(path);assert p.is_absolute() and '..' not in p.parts
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for part in p.parts[1:-1]:
            nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=nxt
        child=os.open(p.name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=fd)
        try:
            st=os.fstat(child);assert stat.S_ISREG(st.st_mode) and st.st_uid==os.getuid() and st.st_nlink==1 and not st.st_mode&0o022 and st.st_size<2*1024*1024
            with os.fdopen(child,'rb',closefd=False) as stream:b=stream.read(2*1024*1024)
            assert len(b)==st.st_size
            return b
        finally:os.close(child)
    finally:os.close(fd)
def create(path,raw,mode=0o600):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    with os.fdopen(fd,'wb') as out:out.write(raw);out.flush();os.fsync(out.fileno())
    assert read(path)==raw

def main():
    os.umask(0o077);t=time.monotonic();a=resource.getrusage(resource.RUSAGE_SELF);c=resource.getrusage(resource.RUSAGE_CHILDREN)
    assert Path(__file__).absolute()==TASK/'candidate/recovery/stage_release.py'
    for name,h in OLD_HASHES.items():assert sha(read(OLD_RELEASE/name))==h, 'deployed source changed; do not overwrite'
    source={name:read(INPUT/name) for name in NEW_HASHES}
    for name,h in NEW_HASHES.items():assert sha(source[name])==h;compile(source[name],name,'exec')
    old_launcher=read(OLD_LAUNCHER);old_entry=read(ENTRY)
    assert sha(old_launcher)==OLD_LAUNCHER_SHA and sha(old_entry)==OLD_ENTRY_SHA
    assert old_launcher.count(OLD_RELEASE.name.encode())==1
    new_launcher=old_launcher.replace(OLD_RELEASE.name.encode(),NEW_RELEASE.name.encode())
    def functions(b):return [ast.dump(x,include_attributes=False) for x in ast.parse(b).body if isinstance(x,(ast.FunctionDef,ast.ClassDef))]
    assert functions(old_launcher)==functions(new_launcher)
    assert old_entry.count(str(OLD_LAUNCHER).encode())==1
    proposed=old_entry.replace(str(OLD_LAUNCHER).encode(),str(NEW_LAUNCHER).encode())
    assert not NEW_RELEASE.exists() and not NEW_RELEASE.is_symlink()
    assert not NEW_LAUNCHER.parent.exists() and not NEW_LAUNCHER.parent.is_symlink()
    NEW_RELEASE.mkdir(mode=0o700);NEW_LAUNCHER.parent.mkdir(mode=0o700)
    for name,b in source.items():create(NEW_RELEASE/name,b)
    create(NEW_LAUNCHER,new_launcher)
    create(TASK/'original_account_entry.bin',old_entry,0o700)
    create(TASK/'proposed_account_entry.bin',proposed,0o700)
    env=os.environ.copy();env['PYTHONDONTWRITEBYTECODE']='1'
    argv=['/home/qian-qi/.local/share/hepta-kaggle/venv/bin/python','-I','-B',str(NEW_LAUNCHER),'qiqian','batch','artifacts','--help']
    p=subprocess.run(argv,capture_output=True,text=True,env=env,timeout=15)
    create(TASK/'staged_help_stdout.txt',p.stdout.encode());create(TASK/'staged_help_stderr.txt',p.stderr.encode())
    assert p.returncode==0 and '--cache-root' in p.stdout and '--cache-manifest-sha256' in p.stdout
    assert read(ENTRY)==old_entry, 'live entry unexpectedly changed'
    for name,h in OLD_HASHES.items():assert sha(read(OLD_RELEASE/name))==h
    b=resource.getrusage(resource.RUSAGE_SELF);d=resource.getrusage(resource.RUSAGE_CHILDREN)
    receipt={'schema':'ndu-cache-release-preparation-v1','status':'PREPARED_NOT_ACTIVATED',
        'old_release':str(OLD_RELEASE),'new_release':str(NEW_RELEASE),'old_source_sha256':OLD_HASHES,'new_source_sha256':NEW_HASHES,
        'old_launcher':str(OLD_LAUNCHER),'old_launcher_sha256':OLD_LAUNCHER_SHA,'new_launcher':str(NEW_LAUNCHER),'new_launcher_sha256':sha(new_launcher),
        'live_entry':str(ENTRY),'live_entry_sha256_before':OLD_ENTRY_SHA,'live_entry_sha256_after':sha(read(ENTRY)),
        'proposed_entry':str(TASK/'proposed_account_entry.bin'),'proposed_entry_sha256':sha(proposed),
        'rollback_entry':str(TASK/'original_account_entry.bin'),'rollback_sha256':OLD_ENTRY_SHA,
        'activation':'Separate binary_write with exact current entry version and original SHA check; no source or lock bypass.',
        'rollback':'Exact-version binary_write of retained original bytes only while entry equals proposed hash. Never alter payload/ledger/state.',
        'rollback_limit':'Old adapter cannot independently reuse the new explicit cache-provenance receipt with manifest mode. Preserve the new release and all imported evidence; do not fabricate old HTTP provenance.',
        'cloud_calls':0,'adapter_or_router_ledger_writes':0,'old_source_files_changed':0,
        'staged_cli_help':{'argv':argv,'returncode':p.returncode,'stdout_sha256':sha(p.stdout.encode()),'stderr_sha256':sha(p.stderr.encode())},
        'cost_prefix':{'wall_seconds':time.monotonic()-t,'self_cpu_seconds':b.ru_utime+b.ru_stime-a.ru_utime-a.ru_stime,'waited_child_cpu_seconds':d.ru_utime+d.ru_stime-c.ru_utime-c.ru_stime}}
    create(NEW_RELEASE/'RELEASE_MANIFEST.json',(json.dumps(receipt,sort_keys=True,indent=2)+'\n').encode())
    create(TASK/'release_preparation.json',(json.dumps(receipt,sort_keys=True,indent=2)+'\n').encode())
    print(json.dumps(receipt,sort_keys=True))
if __name__=='__main__':main()
