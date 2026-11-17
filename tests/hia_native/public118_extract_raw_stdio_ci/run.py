"""Capture six new original raw-stdio domains; no compilation or prior semantic replay."""
from pathlib import Path
import argparse,json,os,shutil,sys,traceback
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent;sys.path[:0]=[str(ROOT),str(ROOT/'capture'),str(ROOT/'peer')]
import raw_driver,restore_stdio,read_stdio,read_only_guard,raw_controls
def put(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def main():
    p=argparse.ArgumentParser()
    for name in ('input','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--profile',required=True);p.add_argument('--domain',required=True);a=p.parse_args()
    assert os.environ.get('GITHUB_ACTIONS')=='true'
    rows=read_stdio.source_check(ROOT,a.profile)
    for n in rows:
        if n.endswith('.py'):compile((ROOT/n).read_bytes(),str(ROOT/n),'exec',dont_inherit=True)
    out=a.output.resolve();out.mkdir(exist_ok=False);shutil.copytree(ROOT,out/'source');retained=out/'retained';retained.mkdir()
    report={'status':'RUNNING','source':os.environ['GITHUB_SHA'],'run':os.environ['GITHUB_RUN_ID'],'source_profile':a.profile,'domain':a.domain,'rust_compiles':0,'hia_compiles':0,'prior_835_original_operations_replayed':False,'native_executions':0,'public_semantics_qualified':False}
    put(out/'RUN.json',report)
    try:
        binary=restore_stdio.prepare(a.input.resolve(),retained)
        work=Path(os.environ['RUNNER_TEMP'])/'public118-raw-domain'/a.domain/'fixture'
        actual=raw_driver.capture(binary,out/'original',work,a.domain,side='original');report['original_runtime_executions']=len(actual['cases'])
        guard=read_only_guard.guarded(lambda:read_stdio.read(out,ROOT,a.profile),roots=[out,ROOT],foreign_path='/proc/self/status');put(out/'READONLY.json',guard)
        controls=out.parent/(out.name+'-reader-controls');report['controls']=raw_controls.run(out,ROOT,a.profile,controls);shutil.move(str(controls),str(out/'reader-controls'))
        report['status']='COMPLETE_ORIGINAL_RAW_STDIO_DOMAIN_PASS';report['full_capture_read']= {k:v for k,v in guard['evidence'].items() if k!='pairs'}
        print(json.dumps({'status':report['status'],'domain':a.domain,**report['full_capture_read'],'original_runtime_executions':report['original_runtime_executions'],'reader_refusals':report['controls']['refusals']},sort_keys=True))
    except BaseException as error:
        report.update(status='FAIL',failure={'type':type(error).__name__,'message':str(error),'traceback':traceback.format_exc()});raise
    finally:put(out/'RUN.json',report)
if __name__=='__main__':main()
