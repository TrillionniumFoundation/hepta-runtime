"""Read every retained diagnostic byte and identify actual syscall time gaps."""
from pathlib import Path
import argparse,hashlib,json,re,shutil,stat,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent;sys.path.insert(0,str(ROOT))
import archive_stream,read_only_guard
IDENTITY={'artifact':14294528768,'bytes':157897319,'sha256':'802350f08769e84d02ad6c673c5c4702b51bc4aacbf6861b4eaae98125875fe3','source':'debe68050af9eefe6a2a759114b58684800dabce','run':44007330104}
def put(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def choose(name):return name.startswith(('trial/','source/')) or name=='RUN.json'
def inspect(folder):
    archive_stream.verify_selection(folder,IDENTITY,choose)
    run=json.loads((folder/'RUN.json').read_bytes());trial=json.loads((folder/'trial/result.json').read_bytes())
    assert run['status']=='COMPLETE_NATIVE_TEARDOWN_DIAGNOSTIC_CAPTURE' and run['qualification_claimed'] is False and run['source']==IDENTITY['source'] and run['run']==str(IDENTITY['run'])
    assert trial['status']=='PASS' and trial['process']['exit_code']==0 and all(trial['process']['pipe_eof'].values()) and not trial['process']['kill_requested']
    path=folder/'trial/process/native.strace';raw=path.read_bytes();assert archive_stream.pin(path)==run['trace']
    parsed=[];pattern=re.compile(r'^\s*(\d+)\s+(\d+\.\d+)\s+(.+)$')
    for i,line in enumerate(raw.decode('utf-8').splitlines()):
        match=pattern.fullmatch(line)
        if match:parsed.append({'line':i,'pid':int(match[1]),'time':float(match[2]),'text':match[3]})
    assert len(parsed)>100 and len({r['pid'] for r in parsed})==1
    gaps=[]
    for left,right in zip(parsed,parsed[1:]):
        duration=re.search(r'<([0-9.]+)>$',left['text']);wall=right['time']-left['time'];outside=wall-(float(duration[1]) if duration else 0)
        if outside>=0.005:gaps.append({'outside_previous_syscall_seconds':outside,'wall_between_starts_seconds':wall,'before':left,'after':right})
    gaps.sort(key=lambda row:row['outside_previous_syscall_seconds'],reverse=True)
    eof=[x for x in parsed if x['text'].startswith('read(0,') and re.search(r'= 0\s+<',x['text'])]
    assert len(eof)==1
    final=[x for x in gaps if x['before']['time']>=eof[0]['time']]
    return {'status':'COMPLETE_TEARDOWN_TRACE_PURE_READ_PASS','producer':IDENTITY,'diagnostic_only':True,'qualification_claimed':False,'native_or_rust_executions':0,'processes':1,'trace_lines':len(parsed),'actual_eof':eof[0],'drain_elapsed_seconds':trial['process']['drain_elapsed_seconds'],'complete_native_elapsed_seconds':trial['process']['elapsed_seconds'],'gaps':gaps,'after_eof_gaps':final,'native_binary':{k:trial['binary'][k] for k in ('bytes','sha256')}}
def main():
    p=argparse.ArgumentParser();p.add_argument('--archive',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--profile',required=True);a=p.parse_args()
    profile=(ROOT/'PACKAGE.json').read_bytes();assert hashlib.sha256(profile).hexdigest()==a.profile;rows=json.loads(profile)['files'];assert {p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*') if p.is_file()}==set(rows)|{'PACKAGE.json'}
    for name,row in rows.items():
        path=ROOT/name;assert archive_stream.pin(path)=={k:row[k] for k in ('bytes','sha256')} and not path.is_symlink() and stat.S_IMODE(path.stat().st_mode)==0o644
    out=a.output.resolve();out.mkdir(exist_ok=False);shutil.copytree(ROOT,out/'reader-source');folder=out/'selected';read=archive_stream.archive(a.archive,IDENTITY,choose,output=folder);put(out/'FULL_ARCHIVE_READ.json',read)
    guard=read_only_guard.guarded(lambda:inspect(folder),roots=[folder,ROOT],foreign_path='/proc/self/status');put(out/'READONLY.json',guard)
    proof=guard['evidence'];print(json.dumps({k:proof[k] for k in ('status','trace_lines','actual_eof','drain_elapsed_seconds','complete_native_elapsed_seconds','after_eof_gaps')},sort_keys=True))
if __name__=='__main__':main()
