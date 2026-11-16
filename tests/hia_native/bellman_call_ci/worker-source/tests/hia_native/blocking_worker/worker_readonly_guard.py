"""Reject writes and execution during full verification, including after relocation."""
from __future__ import annotations
import argparse,builtins,ctypes,io,json,mmap,os,stat,subprocess,sys
from pathlib import Path
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from worker_common import read,sha,encoded,require,document
from worker_recipe import verify

def snapshot(root):
    rows={}
    def visit(path):
        s=path.lstat();row=[s.st_mode,s.st_ino,s.st_dev,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_nlink]
        name=path.relative_to(root).as_posix()
        if stat.S_ISREG(s.st_mode):row.append(sha(read(path)))
        else:require(stat.S_ISDIR(s.st_mode),'unadmitted snapshot object')
        rows[name]=row
        if stat.S_ISDIR(s.st_mode):
            for child in sorted(path.iterdir()):visit(child)
    visit(root);return rows

def guarded_verify(capture,source,pins):
    before=[snapshot(capture),snapshot(source)];replaced=[];refusals=[]
    context=document(capture/'recipe.json')
    blocked=[Path(context[k]) for k in ['capture','source_root'] if Path(context[k]) not in (capture,source)]
    def admit_path(path):
        if isinstance(path,int):return
        candidate=Path(os.path.abspath(os.fsdecode(path)))
        if candidate.is_relative_to(capture) or candidate.is_relative_to(source):return
        if any(candidate==base or candidate.is_relative_to(base) for base in blocked):deny()
    def replace(obj,key,value):replaced.append((obj,key,getattr(obj,key)));setattr(obj,key,value)
    def deny(*args,**kwargs):raise PermissionError('readonly qualification forbids mutation/execution')
    original_open=builtins.open;original_io=io.open;original_os_open=os.open
    def admitted_open(original):
        def call(file,mode='r',*args,**kwargs):
            if any(c in mode for c in 'wax+'):deny()
            admit_path(file)
            return original(file,mode,*args,**kwargs)
        return call
    def os_open(path,flags,*args,**kwargs):
        if flags & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND):deny()
        admit_path(path)
        return original_os_open(path,flags,*args,**kwargs)
    try:
        replace(builtins,'open',admitted_open(original_open));replace(io,'open',admitted_open(original_io));replace(os,'open',os_open)
        for key in ['stat','lstat','scandir']:
            original=getattr(os,key)
            def checked(path,*args,_original=original,**kwargs):admit_path(path);return _original(path,*args,**kwargs)
            replace(os,key,checked)
        for key in ['mkdir','makedirs','remove','unlink','rename','replace','rmdir','chmod','chown','utime','truncate','symlink','link','system','fork','posix_spawn','posix_spawnp']:
            if hasattr(os,key):replace(os,key,deny)
        for key in ['Popen','run','call','check_call','check_output']:replace(subprocess,key,deny)
        for key in ['CDLL','PyDLL','CFUNCTYPE','PYFUNCTYPE']:replace(ctypes,key,deny)
        replace(mmap,'mmap',deny)
        controls=[('open-write',lambda:open(capture/'forbidden','wb')),('path-write',lambda:(source/'forbidden').write_bytes(b'x')),
                  ('os-open-write',lambda:os.open(capture/'forbidden',os.O_CREAT|os.O_WRONLY,0o600)),
                  ('unlink',lambda:os.unlink(capture/'recipe.json')),('mkdir',lambda:os.mkdir(capture/'forbidden')),
                  ('metadata',lambda:os.utime(capture/'recipe.json',None)),('process',lambda:subprocess.run(['true'])),
                  ('ctypes-library',lambda:ctypes.CDLL(None)),('ctypes-function',lambda:ctypes.CFUNCTYPE(ctypes.c_int)),
                  ('mapping',lambda:mmap.mmap(-1,4096)),('replace',lambda:os.replace(capture/'recipe.json',capture/'forbidden'))]
        for i,base in enumerate(blocked):
            controls.append(('original-tree-stat-'+str(i),lambda base=base:os.stat(base)))
            controls.append(('original-tree-open-'+str(i),lambda base=base:open(base/'unadmitted','rb')))
        for name,fn in controls:
            try:fn()
            except PermissionError:refusals.append(name)
            else:raise AssertionError('readonly guard accepted '+name)
        result=verify(capture,source,pins)
    finally:
        for obj,key,value in reversed(replaced):setattr(obj,key,value)
    after=[snapshot(capture),snapshot(source)];require(before==after,'readonly verification changed bytes or metadata')
    return {'status':'RELOCATABLE_READ_ONLY_GUARD_PASS','refusals':refusals,'capture_entries':len(before[0]),'source_entries':len(before[1]),
            'before_sha256':sha(encoded(before)),'after_sha256':sha(encoded(after)),'qualification':result,
            'blocked_original_roots':[str(x) for x in blocked],'native_or_rust_executed':False,'capture_or_source_writes':False}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['capture','source-root','output']:p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--source-pins-sha256',required=True);a=p.parse_args()
    result=guarded_verify(a.capture.resolve(),a.source_root.resolve(),a.source_pins_sha256)
    require(a.output.resolve().is_relative_to(a.capture.resolve()) is False and a.output.resolve().is_relative_to(a.source_root.resolve()) is False,'guard receipt must remain outside verified trees')
    a.output.write_bytes(encoded(result));print(json.dumps(result,sort_keys=True))

if __name__=='__main__':main()
