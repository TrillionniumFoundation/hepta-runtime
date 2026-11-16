"""Guard the complete caller reader against mutation, native loading and replay."""
import ctypes,hashlib,json,os,stat,subprocess,sys,time
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent;sys.path.insert(0,str(ROOT))
import verify
def snapshot(roots):
    result={}
    for root in roots:
        for path in (root,*sorted(root.rglob('*'))):
            info=path.lstat();assert not path.is_symlink()
            row=[info.st_mode,info.st_dev,info.st_ino,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns]
            if stat.S_ISREG(info.st_mode):
                with path.open('rb') as stream:row.append(hashlib.file_digest(stream,'sha256').hexdigest())
            else:assert stat.S_ISDIR(info.st_mode)
            result[str(path)]=row
    return result
def main():
    args=verify.parse_arguments();roots={ROOT}
    for name,value in vars(args).items():
        value=value.resolve(strict=True);setattr(args,name,value);roots.add(value)
    before=snapshot(roots);refusals=[];started=time.monotonic()
    def guard(event,arguments):
        blocked={'subprocess.Popen','os.system','os.posix_spawn','os.fork','os.forkpty','ctypes.dlopen','ctypes.dlsym','mmap.__new__',
            'os.mkdir','os.remove','os.rmdir','os.rename','os.chmod','os.chown','os.truncate','os.utime','os.link','os.symlink'}
        writing=False
        if event=='open':
            _,mode,flags=arguments;writing=bool((isinstance(mode,str) and any(c in mode for c in 'wax+')) or
                (isinstance(flags,int) and flags&(os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND)))
        if event in blocked or writing:refusals.append(event);raise PermissionError('readonly caller verification denied '+event)
    sys.addaudithook(guard)
    probes=(lambda:(args.ordinary/'forbidden-write').write_bytes(b'no'),
        lambda:subprocess.run([sys.executable,'-c','pass'],check=True),lambda:ctypes.CDLL(None),
        lambda:(args.ordinary/'forbidden-directory').mkdir())
    for probe in probes:
        count=len(refusals)
        try:probe()
        except PermissionError:pass
        else:raise AssertionError('readonly guard did not reject the operation')
        assert len(refusals)==count+1
    result=verify.verify_all(args);assert len(refusals)==4
    assert snapshot(roots)==before,'source or evidence changed while reading'
    result.update(physical_source_and_evidence_unchanged=True,read_only_entries=len(before),
        guard_refusals=refusals,native_images_loaded=0,files_written=0,wall_seconds=time.monotonic()-started)
    print(json.dumps(result,sort_keys=True))
if __name__=='__main__':main()
