"""Execute only frozen input bytes against one real stdio binary in authorized CI."""
from pathlib import Path
import argparse,json,os,signal,sys,time,traceback
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent;sys.path[:0]=[str(ROOT),str(ROOT/'capture'),str(ROOT/'peer')]
import raw_domain,all_lines,body_fixture
from capture_common import OwnedFixture,file_pin,capture_tool,check_tool
def put(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def snapshot(owner,work,vault):
    return {'complete_metadata':owner.snapshot([os.fsencode(work).hex()]),'filesystem':body_fixture.tree_snapshot(work,vault)}
def capture(binary,output,work,domain,*,side):
    binary,output,work=Path(binary),Path(output),Path(work)
    assert os.environ.get('GITHUB_ACTIONS')=='true' and side in ('original','native')
    output.mkdir(exist_ok=False);owner=OwnedFixture(work.parent,create=True)
    frozen=raw_domain.domain(domain,work);put(output/'DOMAIN.json',raw_domain.serial(frozen))
    selected=capture_tool(binary,output,'runtime');assert selected['bytes']>0
    report={'schema':'hepta.runtime.extract-complete-stdio-capture.v1','status':'RUNNING','side':side,'domain':domain,'fixture':str(work),'binary':selected,'cases':[],'lane_seconds':180,'per_exchange_seconds':60,'full_public_domain_qualified':False}
    put(output/'CAPTURE.json',report);started=time.monotonic();prior=signal.getsignal(signal.SIGALRM)
    assert signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0)
    def expired(signum,frame):signal.setitimer(signal.ITIMER_REAL,0);raise TimeoutError('unchanged whole 180 second actual raw stdio lane')
    signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,180);previous_umask=os.umask(0o022)
    try:
        for index,item in enumerate(frozen['cases']):
            check_tool(selected);work.mkdir(mode=0o700)
            case=output/f'{index:03d}';case.mkdir();vault=case/'blobs';vault.mkdir()
            setup=OwnedFixture(work).actions(item['actions']);plan=raw_domain.steps(item)
            row={'index':index,'name':item['name'],'input':raw_domain.serial(item),'planned_steps':raw_domain.serial(plan),'setup':setup,'initial':snapshot(owner,work,vault),'milestones':[],'status':'RUNNING'}
            put(case/'CASE.json',row);child=None;failed=True
            try:
                child=all_lines.AllLines(case/'process',binary,work,strace=None,trace=False,extra_argv=('--stdio',) if side=='original' else ())
                for i,step in enumerate(plan):
                    if child.eof['stdout']:break
                    result=child.send(step['wire'],label=step['label'],until=step['correlation_id'],segments=step['segments'])
                    if result['matched_correlation']:row['milestones'].append({'after_step':i,'snapshot':snapshot(owner,work,vault)})
                    put(case/'CASE.json',row)
                row['not_attempted_steps']=[p['label'] for p in plan[len(child.exchanges):]]
                failed=False
            except BaseException as error:
                row.update(status='FAIL',failure={'type':type(error).__name__,'message':str(error),'traceback':traceback.format_exc()});raise
            finally:
                if child is not None:row['process']=child.close(failed=failed)
                row['final']=snapshot(owner,work,vault);row['cleanup']=owner.remove_tree(os.fsencode(work))
                if not failed:row['status']='COMPLETE_WITH_ACTUAL_PROCESS_EXIT'
                put(case/'CASE.json',row)
            report['cases'].append({'index':index,'name':item['name'],'case':file_pin(case/'CASE.json')});put(output/'CAPTURE.json',report)
        report['status']='COMPLETE_ORIGINAL_STDIO_DOMAIN_CAPTURED' if side=='original' else 'COMPLETE_NATIVE_STDIO_DOMAIN_CAPTURED'
    except BaseException as error:
        report.update(status='FAIL',failure={'type':type(error).__name__,'message':str(error),'traceback':traceback.format_exc()});raise
    finally:
        signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,prior);os.umask(previous_umask)
        report['elapsed_seconds']=time.monotonic()-started;put(output/'CAPTURE.json',report)
    assert report['elapsed_seconds']<180;return report
if __name__=='__main__':
    p=argparse.ArgumentParser()
    for name in ('binary','output','work'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--domain',required=True);p.add_argument('--side',choices=('original','native'),required=True);a=p.parse_args()
    result=capture(a.binary,a.output,a.work,a.domain,side=a.side);print(json.dumps({'status':result['status'],'domain':result['domain'],'cases':len(result['cases']),'elapsed_seconds':result['elapsed_seconds']},sort_keys=True))
