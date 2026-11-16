"""Full final artifact transfer and frozen inert archive-reader execution only."""
from pathlib import Path
import hashlib
import json
import os
import signal
import stat
import subprocess
import sys
import time
import urllib.request
import zipfile


def pin(path):
    with path.open('rb') as stream:
        digest=hashlib.file_digest(stream,'sha256').hexdigest()
    return dict(bytes=path.stat().st_size,sha256=digest)


def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()


def main():
    cfg=json.load(sys.stdin);root=Path(cfg['root']);root.mkdir(parents=True,exist_ok=False)
    source=Path(cfg['source']).resolve(strict=True);started=time.monotonic();archive=root/'complete.zip'
    download=time.monotonic()
    with urllib.request.urlopen(cfg['url'],timeout=60) as response,archive.open('xb') as output:
        while chunk:=response.read(1024*1024):
            assert time.monotonic()-download<180,'original 180 second download budget'
            output.write(chunk)
    assert pin(archive)==dict(bytes=192281577,sha256='1cb12d7abda23a56b297a0b9bce46b8416166c05f959328f55c924cd9550a67c')
    outer=root/'zip';outer.mkdir();members={}
    with zipfile.ZipFile(archive) as bundle:
        for item in bundle.infolist():
            assert not item.is_dir() and item.filename not in members and '/' not in item.filename
            assert item.filename not in ('.','..') and not stat.S_ISLNK(item.external_attr>>16)
            path=outer/item.filename
            with bundle.open(item) as reader,path.open('xb') as writer:
                while chunk:=reader.read(1024*1024):writer.write(chunk)
            assert path.stat().st_size==item.file_size
            members[item.filename]=dict(**pin(path),zip_mode=item.external_attr>>16)
    assert set(members)=={'extract-lines-retained.tar.gz','extract-lines-retained.tar.gz.json',
        'extract-lines-retained-pack.stdout','extract-lines-retained-pack.stderr',
        'extract-lines-retained-readonly.json','extract-lines-retained-readonly.stderr'}
    command=[sys.executable,'-I','-B',str(source/'read_archive.py'),'--archive',str(outer/'extract-lines-retained.tar.gz'),
        '--source-manifest-sha256','0c9773a98101c3bfc870986c4aa5c2ea29fd54de8983a19986cea3af28bc65a3']
    begin=time.monotonic();child=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
    timed_out=False
    try:out,err=child.communicate(timeout=180)
    except subprocess.TimeoutExpired:
        timed_out=True;os.killpg(child.pid,signal.SIGKILL);out,err=child.communicate()
    finally:
        if child.poll() is None:os.killpg(child.pid,signal.SIGKILL);child.wait()
    (root/'reader.stdout').write_bytes(out);(root/'reader.stderr').write_bytes(err)
    process=dict(argv=command,pid=child.pid,pgid=child.pid,exit_code=child.returncode,timed_out=timed_out,
        process_reaped=True,deadline_seconds=180,elapsed_seconds=time.monotonic()-begin,
        stdout=pin(root/'reader.stdout'),stderr=pin(root/'reader.stderr'))
    (root/'PROCESS.json').write_bytes(encoded(process))
    result=dict(schema='hepta.extract-lines.complete-artifact-readback.v1',status='FAIL',
        recovery_head='3b62794c73c858acddb1fbf63191b07312b4801e',run_id=43968614545,artifact_id=14277518249,
        zip=pin(archive),outer_files=members,all_outer_members_reread=True,process=process,
        native_or_rust_executions=0,whole_runtime_replaced=False)
    if child.returncode==0 and not timed_out:
        independent=json.loads(out);original=json.loads((outer/'extract-lines-retained-readonly.json').read_bytes())
        assert {k:v for k,v in independent.items() if k!='elapsed_seconds'}=={k:v for k,v in original.items() if k!='elapsed_seconds'}
        assert independent['status']=='COMPLETE_LOCAL_EXTRACT_BODY_ARCHIVE_READONLY_PASS'
        assert independent['native_or_rust_executions']==independent['reader_writes']==0
        result.update(status='COMPLETE_LOCAL_EXTRACT_BODY_FULL_ARTIFACT_READBACK_PASS',
            independent_evidence=independent,original_ci_reader_agrees=True)
    result['elapsed_seconds']=time.monotonic()-started;(root/'READBACK.json').write_bytes(encoded(result))
    print(json.dumps(result,sort_keys=True));return 0 if result['status']!='FAIL' else 1


if __name__=='__main__':sys.exit(main())
