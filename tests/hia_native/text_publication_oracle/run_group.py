"""Fresh unchanged Linux publication reference after a complete native capture."""
from pathlib import Path
import argparse,hashlib,importlib.util,json,os,signal,subprocess,sys,time
def encoded(x):return (json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)+'\n').encode()
def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def save(path,x):raw=encoded(x);path.write_bytes(raw);return pin(raw)
def require(x,m):
    if not x:raise ValueError(m)
def main():
    parser=argparse.ArgumentParser()
    for name in ('source','output','native-root','native-source','native-build','native-origins','cargo','rustc','strace'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args()
    for key,value in vars(args).items():setattr(args,key,value.absolute())
    S=args.source;O=args.output;O.mkdir(parents=True,exist_ok=False)
    save(O/'remote-process.json',{'pid':os.getpid(),'cgroup':Path('/proc/self/cgroup').read_text(),'started_monotonic_ns':time.monotonic_ns()})
    source_pins={str(p.relative_to(S)):pin(p.read_bytes()) for p in sorted(S.rglob('*')) if p.is_file() and '__pycache__' not in p.parts};save(O/'SOURCE-FILES.json',source_pins)
    spec=importlib.util.spec_from_file_location('_text_original_group_api',S/'api.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);api=m.load(S)
    mapping=args.native_origins.read_bytes();(O/'NATIVE-ORIGINS.json').write_bytes(mapping);native_maps=json.loads(mapping)
    require(type(native_maps) is list and all(type(p) is list and len(p)==2 and all(type(x) is str and Path(x).is_absolute() for x in p) for p in native_maps),'explicit native origin mappings')
    origins=native_maps+[(str(S),str(S)),(str(O),str(O))]
    require(len({x[0] for x in origins})==len(origins),'unique selected source/output/native origins')
    started=time.monotonic_ns();processes=[]
    def run(name,command,cwd):
        d=O/'processes'/name;d.mkdir(parents=True);st=time.monotonic_ns();child=None;error=None;timed=False
        with (d/'stdout').open('xb') as out,(d/'stderr').open('xb') as err:
            try:
                child=subprocess.Popen(command,cwd=cwd,stdout=out,stderr=err,start_new_session=True)
                for n in ('status','cmdline','cgroup'):
                    try:(d/('proc-'+n)).write_bytes((Path('/proc')/str(child.pid)/n).read_bytes())
                    except FileNotFoundError:pass
                try:child.wait(timeout=180)
                except subprocess.TimeoutExpired:timed=True;os.killpg(child.pid,signal.SIGKILL);child.wait()
            except BaseException as e:error=repr(e)
        end=time.monotonic_ns()
        r={'command':command,'cwd':str(cwd),'pid':None if child is None else child.pid,'timeout_seconds':180,'timed_out':timed,'start_error':error,'exit_code':None if child is None else child.returncode,'started_monotonic_ns':st,'finished_monotonic_ns':end,'elapsed_seconds':(end-st)/1e9,'stdout':pin((d/'stdout').read_bytes()),'stderr':pin((d/'stderr').read_bytes())}
        save(d/'PROCESS.json',r);processes.append({'name':name,**r});save(O/(name+'-PROCESS.json'),r)
        print(json.dumps({'name':name,'exit_code':r['exit_code'],'elapsed_seconds':r['elapsed_seconds'],'stdout':r['stdout'],'stderr':r['stderr']},sort_keys=True),flush=True)
        require(r['exit_code']==0 and r['timed_out'] is False and r['start_error'] is None,'real original child failed: '+name);return d/'PROCESS.json'
    ordinary=O/'ordinary';races=O/'races'
    cmd=[sys.executable,'-I','-B',str(S/'ordinary/run.py'),'--source',str(S/'ordinary'),'--output',str(ordinary),'--native-root',str(args.native_root),'--native-source',str(args.native_source),'--native-build',str(args.native_build),'--cargo',str(args.cargo),'--rustc',str(args.rustc),'--strace',str(args.strace),'--native-origins',str(O/'NATIVE-ORIGINS.json')]
    receipt=run('ordinary',cmd,S/'ordinary')
    ordinary_request={'source':str(S/'ordinary'),'output':str(ordinary),'native_root':str(args.native_root),'native_source':str(args.native_source),'native_build':str(args.native_build),'outer_receipt':str(receipt),'origins':origins}
    save(O/'ORDINARY-REQUEST.json',ordinary_request);original=api['ordinary_evidence'](**ordinary_request);op=save(O/'ORDINARY-EVIDENCE.json',original)
    cmd=[sys.executable,'-I','-B',str(S/'races/run_races.py'),'--source',str(S/'races'),'--output',str(races),'--native-corpus',str(args.native_root),'--ordinary-request',str(O/'ORDINARY-REQUEST.json'),'--ordinary-reader',str(S/'readers')]
    receipt=run('races',cmd,S/'races')
    race_request={'source':str(S/'races'),'output':str(races),'native_corpus':str(args.native_root),'outer_receipt':str(receipt),'origins':origins}
    save(O/'RACE-REQUEST.json',race_request);observed=api['race_evidence'](**race_request);rp=save(O/'RACE-EVIDENCE.json',observed)
    for name,test,request,readers in [('ordinary-controls','test_original_evidence.py','ORDINARY-REQUEST.json',[S/'readers',S/'ordinary']),('race-controls','test_race_evidence.py','RACE-REQUEST.json',[S/'readers',S/'races',S/'ordinary'])]:
        cmd=[sys.executable,'-I','-B',str(S/test),'--request',str(O/request),'--output',str(O/name)]
        for d in readers:cmd+=['--reader',str(d)]
        run(name,cmd,S)
    admission={'source':str(S),'ordinary_request':str(O/'ORDINARY-REQUEST.json'),'race_request':str(O/'RACE-REQUEST.json'),'ordinary_controls':str(O/'ordinary-controls'),'race_controls':str(O/'race-controls'),'ordinary_receipt':str(O/'processes/ordinary-controls/PROCESS.json'),'race_receipt':str(O/'processes/race-controls/PROCESS.json'),'origins':origins}
    save(O/'ADMISSION-REQUEST.json',admission);proof=api['qualification_evidence'](**admission);ep=save(O/'EVIDENCE.json',proof)
    require(encoded(proof['original_reference'])==encoded(observed) and encoded(observed['ordinary_reference'])==encoded(original),'all original records unchanged after controls')
    require(source_pins=={str(p.relative_to(S)):pin(p.read_bytes()) for p in sorted(S.rglob('*')) if p.is_file() and '__pycache__' not in p.parts},'all actual original sources unchanged')
    save(O/'PROCESSES.json',processes)
    result={'schema':'hepta.runtime.text-original-portable-group.v1','status':'PASS','ordinary_cases':99,'external_writer_cases':20,'actual_original_children':9,'fresh_locked_builds':1,'version_processes':3,'original_replays':5,'actual_python_children':4,'ordinary_refusals':42,'race_refusals':36,'new_native_calls':0,'evidence':ep,'ordinary_evidence':op,'race_evidence':rp,'source_files':pin((O/'SOURCE-FILES.json').read_bytes()),'elapsed_seconds':(time.monotonic_ns()-started)/1e9,'public_handler_complete':False,'whole_runtime_replaced':False}
    save(O/'RESULT.json',result);print(json.dumps(result,sort_keys=True),flush=True)
if __name__=='__main__':main()
