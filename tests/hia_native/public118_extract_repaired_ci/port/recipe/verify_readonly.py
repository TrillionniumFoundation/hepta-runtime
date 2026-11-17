"""Regression guard for the fixed Python port readers, including relocation.

This guards their admitted paths and operations; it is not a sandbox for
arbitrary Python. The optional receipt is written outside all admitted trees.
"""
import argparse,builtins,ctypes,hashlib,io,json,mmap,os,pathlib,stat,subprocess,sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
from qualify_port import verify,encoded,doc,source_evidence

def snapshot(root):
    result={}
    def visit(path):
        info=path.lstat();row=[info.st_mode,info.st_ino,info.st_dev,info.st_size,info.st_mtime_ns,info.st_ctime_ns,info.st_nlink]
        if stat.S_ISREG(info.st_mode):
            with path.open('rb') as stream:row.append(hashlib.file_digest(stream,'sha256').hexdigest())
        else:assert stat.S_ISDIR(info.st_mode)
        result[path.relative_to(root).as_posix()]=row
        if stat.S_ISDIR(info.st_mode):
            for child in sorted(path.iterdir()):visit(child)
    visit(root);return result

def guarded_verify(package,capture,worker_build,pins):
    source_evidence(package,pins)
    # Import all trusted reader dependencies before installing the guard.
    sys.path.insert(0,str(package/'worker-source/tests/hia_native/blocking_worker'))
    import worker_common,worker_build_evidence,worker_compiler_custody
    roots=list(dict.fromkeys([package,capture,worker_build]));admitted=[p for p in roots if not any(p!=q and p.is_relative_to(q) for q in roots)]
    before=[snapshot(p) for p in admitted]
    context=doc(capture/'recipe.json');controls=doc(capture/'controls-v4/RESULT.json')
    origins=[pathlib.Path(context[k]) for k in ('package','capture','worker_build')]+[pathlib.Path(controls[k]) for k in ('run_origin','build_origin','output_origin')]
    blocked=[p for p in dict.fromkeys(origins) if not any(p==q or p.is_relative_to(q) for q in admitted)]
    replaced=[];refusals=[]
    def deny(*args,**kwargs):raise PermissionError('fixed port reader forbids mutation/execution or original-path fallback')
    def admit(path):
        if isinstance(path,int):return
        p=pathlib.Path(os.path.abspath(os.fsdecode(path)))
        if any(p==q or p.is_relative_to(q) for q in admitted):return
        if any(p==q or p.is_relative_to(q) for q in blocked):deny()
    def replace(obj,name,value):replaced.append((obj,name,getattr(obj,name)));setattr(obj,name,value)
    def guarded_open(original):
        def call(file,mode='r',*args,**kwargs):
            if any(c in mode for c in 'wax+'):deny()
            admit(file);return original(file,mode,*args,**kwargs)
        return call
    old_os_open=os.open
    def os_open(path,flags,*args,**kwargs):
        if flags&(os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND):deny()
        admit(path);return old_os_open(path,flags,*args,**kwargs)
    try:
        replace(builtins,'open',guarded_open(builtins.open));replace(io,'open',guarded_open(io.open));replace(os,'open',os_open)
        for name in ('stat','lstat','scandir'):
            original=getattr(os,name)
            def checked(path,*args,_original=original,**kwargs):admit(path);return _original(path,*args,**kwargs)
            replace(os,name,checked)
        for name in ('mkdir','makedirs','remove','unlink','rename','replace','rmdir','chmod','chown','utime','truncate','symlink','link','system','fork','posix_spawn','posix_spawnp'):
            if hasattr(os,name):replace(os,name,deny)
        for name in ('Popen','run','call','check_call','check_output'):replace(subprocess,name,deny)
        for name in ('CDLL','PyDLL','CFUNCTYPE','PYFUNCTYPE'):replace(ctypes,name,deny)
        replace(mmap,'mmap',deny)
        probes=[('open-write',lambda:open(capture/'forbidden','wb')),('path-write',lambda:(package/'forbidden').write_bytes(b'x')),('os-open-write',lambda:os.open(capture/'forbidden',os.O_CREAT|os.O_WRONLY,0o600)),('unlink',lambda:os.unlink(capture/'recipe.json')),('mkdir',lambda:os.mkdir(capture/'forbidden')),('metadata',lambda:os.utime(capture/'recipe.json',None)),('process',lambda:subprocess.run(['true'])),('ctypes-library',lambda:ctypes.CDLL(None)),('ctypes-function',lambda:ctypes.CFUNCTYPE(ctypes.c_int)),('mapping',lambda:mmap.mmap(-1,4096)),('replace',lambda:os.replace(capture/'recipe.json',capture/'forbidden'))]
        for i,origin in enumerate(blocked):
            probes.extend([('original-stat-'+str(i),lambda origin=origin:os.stat(origin)),('original-open-'+str(i),lambda origin=origin:open(origin/'unadmitted','rb'))])
        for name,probe in probes:
            try:probe()
            except PermissionError:refusals.append(name)
            else:raise AssertionError('reader guard accepted '+name)
        result=verify(package,capture,worker_build,pins)
    finally:
        for obj,name,value in reversed(replaced):setattr(obj,name,value)
    after=[snapshot(p) for p in admitted];assert before==after,'guarded read changed tree bytes or metadata'
    return {'status':'RELOCATABLE_PRIVATE_PORT_READER_PASS','qualification':result,'guard_refusals':refusals,'protected_roots':[str(p) for p in admitted],'protected_entries':sum(map(len,before)),'before_sha256':hashlib.sha256(encoded(before)).hexdigest(),'after_sha256':hashlib.sha256(encoded(after)).hexdigest(),'blocked_original_roots':[str(p) for p in blocked],'native_or_rust_executed':False,'protected_tree_writes':False}

def main():
    p=argparse.ArgumentParser()
    for name in ('package','capture','worker-build'):p.add_argument('--'+name,type=pathlib.Path,required=True)
    p.add_argument('--package-sha256',required=True);p.add_argument('--output',type=pathlib.Path);a=p.parse_args()
    paths=[a.package.resolve(),a.capture.resolve(),a.worker_build.resolve()]
    if a.output is not None:assert not any(a.output.resolve().is_relative_to(root) for root in paths)
    result=guarded_verify(*paths,a.package_sha256)
    if a.output is not None:a.output.write_bytes(encoded(result))
    print(json.dumps(result,sort_keys=True))
if __name__=='__main__':main()
