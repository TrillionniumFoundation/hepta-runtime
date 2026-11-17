"""Execute only new HIA public stdio processes against unchanged complete original captures."""
from pathlib import Path
import argparse,json,os,shutil,sys,traceback
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent;sys.path[:0]=[str(ROOT),str(ROOT/'capture'),str(ROOT/'peer')]
import raw_driver,read_stdio,restore_native_raw,read_native_raw,native_controls,read_only_guard
def put(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def main():
    p=argparse.ArgumentParser()
    for name in ('input','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--profile',required=True);p.add_argument('--domain',required=True);a=p.parse_args()
    assert os.environ.get('GITHUB_ACTIONS')=='true';rows=read_stdio.source_check(ROOT,a.profile)
    for n in rows:
        if n.endswith('.py'):compile((ROOT/n).read_bytes(),str(ROOT/n),'exec',dont_inherit=True)
    out=a.output.resolve();out.mkdir(exist_ok=False);shutil.copytree(ROOT,out/'source')
    report={'status':'RUNNING','source':os.environ['GITHUB_SHA'],'run':os.environ['GITHUB_RUN_ID'],'source_profile':a.profile,'domain':a.domain,
        'original_semantics_replayed':False,'native_build_replayed':False,'original_runtime_executions':0,'full_async_qualified':False,'public_wait_qualified':False,'whole_runtime_replaced':False}
    put(out/'RUN.json',report)
    try:
        binary=restore_native_raw.prepare(a.input.resolve(),out/'retained',a.domain)
        original=json.loads((out/'retained/prior/original/CAPTURE.json').read_bytes())
        work=Path(os.environ['RUNNER_TEMP'])/'public118-raw-domain'/a.domain/'fixture';assert original['fixture']==str(work)
        actual=raw_driver.capture(binary,out/'native',work,a.domain,side='native');report['actual_native_processes']=len(actual['cases'])
        guard=read_only_guard.guarded(lambda:read_native_raw.read(out,ROOT,a.profile),roots=[out,ROOT],foreign_path='/proc/self/status');put(out/'READONLY.json',guard)
        controlroot=out.parent/(out.name+'-controls');report['controls']=native_controls.run(out,ROOT,a.profile,controlroot);shutil.move(str(controlroot),str(out/'reader-controls'))
        report['status']='COMPLETE_NATIVE_ORIGINAL_RAW_STDIO_DIFFERENTIAL_PASS';report['comparison']=guard['evidence']
        print(json.dumps({'status':report['status'],'domain':a.domain,'actual_native_processes':report['actual_native_processes'],'reader_controls':4},sort_keys=True))
    except BaseException as error:
        report.update(status='FAIL',failure={'type':type(error).__name__,'message':str(error),'traceback':traceback.format_exc()});raise
    finally:put(out/'RUN.json',report)
if __name__=='__main__':main()
