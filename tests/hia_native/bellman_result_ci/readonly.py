"""Re-read complete evidence while refusing writes and semantic execution."""
import argparse
import copy
import ctypes
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
import qualify

def snapshot(roots):
    result={}
    for root in roots:
        for path in (root,*sorted(root.rglob('*'))):
            info=path.lstat()
            assert not path.is_symlink(),('unexpected symlink',path)
            row=[info.st_mode,info.st_dev,info.st_ino,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns]
            if stat.S_ISREG(info.st_mode):
                digest=hashlib.sha256()
                with path.open('rb') as stream:
                    while block:=stream.read(1<<20):digest.update(block)
                row.append(digest.hexdigest())
            else:assert stat.S_ISDIR(info.st_mode)
            result[str(path)]=row
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--native-only',action='store_true')
    args=p.parse_args();args.output=args.output.resolve(strict=True)
    roots=(qualify.PACKAGE,args.output)
    before=snapshot(roots);refusals=[];started=time.monotonic()
    def guard(event,arguments):
        blocked={'subprocess.Popen','os.system','os.posix_spawn','os.fork','os.forkpty',
                 'ctypes.dlopen','ctypes.dlsym','mmap.__new__','os.mkdir','os.remove','os.rmdir',
                 'os.rename','os.chmod','os.chown','os.truncate','os.utime','os.link','os.symlink'}
        writing=False
        if event=='open':
            _,mode,flags=arguments
            writing=bool((isinstance(mode,str) and any(c in mode for c in 'wax+')) or
                         (isinstance(flags,int) and flags&(os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND)))
        if event in blocked or writing:
            refusals.append(event)
            raise PermissionError('read-only evidence verification denied '+event)
    sys.addaudithook(guard)
    probes=(lambda:(args.output/'reader-forbidden-write').write_bytes(b'forbidden'),
            lambda:subprocess.run([sys.executable,'-c','pass'],check=True),
            lambda:ctypes.CDLL(None),
            lambda:(args.output/'reader-forbidden-directory').mkdir())
    for probe in probes:
        count=len(refusals)
        try:probe()
        except PermissionError:pass
        else:raise AssertionError('read-only guard failed')
        assert len(refusals)==count+1
    result=qualify.verify(args)
    assert len(refusals)==len(probes)
    after=snapshot(roots);assert after==before,'evidence or source changed during reader'
    result.update(physical_source_and_evidence_unchanged=True,read_only_entries=len(before),
                  guard_refusals=refusals,semantic_processes_started=0,native_images_loaded=0,
                  files_written=0,wall_seconds=time.monotonic()-started)
    print(json.dumps(result,sort_keys=True))

if __name__=='__main__':main()
