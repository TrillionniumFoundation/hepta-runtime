"""Trace one existing native process through complete EOF; never rebuild or replay Rust."""
from pathlib import Path
import argparse,hashlib,json,os,shutil,signal,stat,sys,time,traceback
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'base'))
import source_check,restore,qualify_public as q
from receipt_support import PIN,regular,put,require

def admit(profile):
    raw=regular(ROOT/'PACKAGE.json');require(PIN(raw)['sha256']==profile,'diagnostic source profile')
    rows=json.loads(raw)['files'];require({p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*') if p.is_file()}==set(rows)|{'PACKAGE.json'},'complete diagnostic source set')
    for name,row in rows.items():
        p=ROOT/name;require(PIN(regular(p))=={k:row[k] for k in ('bytes','sha256')} and stat.S_IMODE(p.stat().st_mode)==0o644,'complete diagnostic source bytes and mode')
    return source_check.check(ROOT/'base','e2cdde0e66a38d4bf0b313c1f764b5bcf73e77c9fbf0ef6796b08d1ce09f15c4')

class TracedNative(q.Native):
    def __init__(self,output,binary,cwd,config=None):
        self.io=q.fixture_io.RecordedFixtureProcess(output,binary,cwd,strace='/usr/bin/strace',trace=True)

def main():
    p=argparse.ArgumentParser();p.add_argument('--input',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--profile',required=True);a=p.parse_args()
    require(os.environ.get('GITHUB_ACTIONS')=='true','native diagnostic CI only')
    proof=admit(a.profile);out=a.output.resolve();out.mkdir(exist_ok=False);shutil.copytree(ROOT,out/'source')
    report={'schema':'hepta.runtime.extract-public-teardown-diagnostic.v1','status':'RUNNING','diagnostic_only':True,'qualification_claimed':False,'source':os.environ['GITHUB_SHA'],'run':os.environ['GITHUB_RUN_ID'],'source_profile':a.profile,'source_admission':proof,'runtime_build_replayed':False,'rust_executions':0,'outer_lane_deadline_seconds':180,'per_exchange_deadline_seconds':60,'input_domain':'body-legacy','input_case_index':0}
    put(out/'RUN.json',report)
    try:
        ready=restore.prepare(a.input,out/'retained','body-legacy')
        q.Native=TracedNative
        q.fixture_io.common.TRACE_ARGS=['-f','-qq','-ttt','-T','-s','4096','-xx','-e','trace=%file,read,write,mmap,mprotect,munmap,close,getpgid,getdents64,flock,fcntl,dup,dup2,dup3,exit,exit_group']
        report['trace_arguments']=q.fixture_io.common.TRACE_ARGS
        previous=signal.getsignal(signal.SIGALRM)
        require(signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0),'unrelated alarm active')
        def expired(signum,frame):
            signal.setitimer(signal.ITIMER_REAL,0)
            raise TimeoutError('unchanged 180 second diagnostic lane deadline')
        before=time.monotonic();signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,180)
        try:
            result=q.execute('native',Path(ready['binaries']['native-private']['path']),out/'workspace',out/'trial','body-legacy',0)
        finally:
            signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,previous);report['elapsed_seconds']=time.monotonic()-before
        require(result['status']=='PASS' and result['completed_cases']==1 and report['elapsed_seconds']<180,'complete one-case diagnostic capture')
        report.update(status='COMPLETE_NATIVE_TEARDOWN_DIAGNOSTIC_CAPTURE',actual_native_processes=1,actual_public_operations=1,drain_elapsed_seconds=result['process']['drain_elapsed_seconds'],trace=PIN(regular(out/'trial/process/native.strace')),native_binary=ready['binaries']['native-private'])
    except BaseException as error:
        report.update(status='FAIL',failure={'type':type(error).__name__,'message':str(error),'traceback':traceback.format_exc()});raise
    finally:put(out/'RUN.json',report)

if __name__=='__main__':main()
