"""Full retained failure archive readback and source-bound inert diagnostic only."""
from pathlib import Path
import gzip
import hashlib
import json
import os
import signal
import stat
import subprocess
import sys
import tarfile
import time
import urllib.request
import zipfile


def pin(path):
    with path.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
    return dict(bytes=path.stat().st_size,sha256=digest)


def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()


def safe(name):
    parts=name.split('/')
    assert name and not name.startswith('/') and all(x not in ('','.','..') for x in parts)
    return Path(*parts)


def main():
    cfg=json.load(sys.stdin);root=Path(cfg['root']);root.mkdir(parents=True,exist_ok=False)
    started=time.monotonic();archive=root/'complete.zip';download_start=time.monotonic()
    with urllib.request.urlopen(cfg['url'],timeout=60) as response,archive.open('xb') as output:
        while chunk:=response.read(1024*1024):
            assert time.monotonic()-download_start<180,'original archive download deadline'
            output.write(chunk)
    assert pin(archive)=={'bytes':90994723,'sha256':'51b283457a9c1901dbb04d2f671333aa7a420cd8fc9c14b49157f91ad9cfc4d4'}
    outer=root/'zip';outer.mkdir();zip_rows={}
    with zipfile.ZipFile(archive) as z:
        for item in z.infolist():
            assert not item.is_dir() and item.filename not in zip_rows
            assert not stat.S_ISLNK(item.external_attr>>16)
            path=outer/safe(item.filename);path.parent.mkdir(parents=True,exist_ok=True)
            with z.open(item) as source,path.open('xb') as target:
                while chunk:=source.read(1024*1024):target.write(chunk)
            zip_rows[item.filename]=dict(**pin(path),zip_mode=item.external_attr>>16)
            assert path.stat().st_size==item.file_size
    assert set(zip_rows)=={'extract-lines-body.tar.gz','extract-lines-body.tar.gz.json',
                          'extract-lines-body-export.stdout','extract-lines-body-export.stderr'}
    tar_path=outer/'extract-lines-body.tar.gz';receipt=json.loads((outer/'extract-lines-body.tar.gz.json').read_bytes())
    assert {k:receipt[k] for k in ('bytes','sha256')}==pin(tar_path) and receipt['all_members_reread'] is True
    expanded=root/'expanded';expanded.mkdir();members={}
    with tarfile.open(tar_path,'r|gz') as tar:
        while entry:=tar.next():
            assert entry.isfile() and entry.name not in members
            path=expanded/safe(entry.name);path.parent.mkdir(parents=True,exist_ok=True)
            with tar.extractfile(entry) as source,path.open('xb') as target:
                while chunk:=source.read(1024*1024):target.write(chunk)
            path.chmod(entry.mode&0o777);members[entry.name]=dict(**pin(path),mode=entry.mode&0o777)
            assert path.stat().st_size==entry.size
            tar.members.clear()
    metadata=json.loads((expanded/'artifact-manifest.json').read_bytes());expected=dict(metadata['files'])
    expected['artifact-manifest.json']=dict(**pin(expanded/'artifact-manifest.json'),mode=0o644)
    assert members==expected and len(members)==receipt['files']
    assert sum(x['bytes'] for x in members.values())==receipt['logical_bytes']
    assert metadata['git_head']=='a1ad1d8b2fb8d0944c8348f6760b1ef5e1f1b43b' and metadata['run_id']=='43964900937'
    source=expanded/'source';capture=expanded/'run/semantic'
    assert pin(source/'SOURCE_MANIFEST.json')['sha256']=='ab117630de23d39dec8f909afba5460690c04fd2ed0e7f351ba65903fbf198b0'
    for name,row in members.items():
        path=expanded/name
        assert pin(path)=={k:row[k] for k in ('bytes','sha256')} and stat.S_IMODE(path.stat().st_mode)==row['mode']
    (root/'ARCHIVE.json').write_bytes(encoded(dict(schema='hepta.extract-lines.failure-archive-readback.v1',
        artifact=14274914569,zip=pin(archive),tar=pin(tar_path),files=len(members),
        logical_bytes=receipt['logical_bytes'],all_members_reread=True,zip_members=zip_rows)))
    script='''import sys,json,gzip,time
from pathlib import Path
source=Path(sys.argv[1]);capture=Path(sys.argv[2]);sys.path.insert(0,str(source));sys.dont_write_bytecode=True
import read_capture
from read_only_guard import guarded
proof=guarded(lambda:read_capture.semantic(capture),roots=[source,capture],foreign_path=Path('/dev/null'))
assert proof['before']==proof['after'] and len(proof['probes'])==12
assert proof['native_or_rust_executions']==proof['reader_writes']==0
print(json.dumps(proof,sort_keys=True,allow_nan=False))
'''
    command=[sys.executable,'-I','-B','-c',script,str(source),str(capture)]
    begin=time.monotonic();child=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
    timed_out=False
    try:out,err=child.communicate(timeout=180)
    except subprocess.TimeoutExpired:
        timed_out=True;os.killpg(child.pid,signal.SIGKILL);out,err=child.communicate()
    finally:
        if child.poll() is None:os.killpg(child.pid,signal.SIGKILL);child.wait()
    (root/'diagnostic.stdout').write_bytes(out);(root/'diagnostic.stderr').write_bytes(err)
    process=dict(argv=command,pid=child.pid,pgid=child.pid,exit_code=child.returncode,timed_out=timed_out,
        process_reaped=True,deadline_seconds=180,elapsed_seconds=time.monotonic()-begin,
        stdout=pin(root/'diagnostic.stdout'),stderr=pin(root/'diagnostic.stderr'))
    (root/'PROCESS.json').write_bytes(encoded(process))
    result=dict(schema='hepta.extract-lines.failure-readback.v1',status='FULL_ARCHIVE_READBACK_DIAGNOSTIC_FAILED',
        artifact=14274914569,source_head='a1ad1d8b2fb8d0944c8348f6760b1ef5e1f1b43b',archive=pin(archive),
        tar=pin(tar_path),files=len(members),logical_bytes=receipt['logical_bytes'],all_members_reread=True,
        original_failed_ci_preserved=True,stdlib_gzip_preloaded_before_guard=True,
        native_or_rust_reexecutions=0,process=process,whole_runtime_replaced=False)
    if child.returncode==0 and not timed_out:
        proof=json.loads(out);result.update(status='FULL_ARCHIVE_AND_INERT_DIAGNOSTIC_PASS',
            evidence=proof['evidence'],proof=pin(root/'diagnostic.stdout'),guard_entries=len(proof['before']),guard_probes=12)
    result['elapsed_seconds']=time.monotonic()-started;(root/'READBACK.json').write_bytes(encoded(result))
    print(json.dumps(result,sort_keys=True));return 0 if child.returncode==0 and not timed_out else 1


if __name__=='__main__':sys.exit(main())
