# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Finite nine-tool runtime captures and a Rust-only retained-native consumer.

The declared cases retain their complete input/output streams and ordinary
filesystem observations. Pending tests use only an owned advisory lock and
read-only /proc observations. Public cancellation and true EOF are distinct.
"""
from pathlib import Path
import copy,json,os,sys,time,traceback

ROOT=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ROOT/'scripts'),str(Path(__file__).resolve().parent)]
from public_lifecycle_registry import encoded,regular,require,sha,source_pins
from lifecycle_inputs import pin
import lifecycle_preflight as preflight
import lifecycle_preflight_evidence as preflight_evidence
import lifecycle_success as success
import lifecycle_success_cases as success_cases
import lifecycle_success_evidence as success_evidence
import lifecycle_pending as pending
import lifecycle_pending_evidence as pending_evidence
import lifecycle_fixtures as fixtures
import lifecycle_fixture_controls as fixture_controls

PROTOCOLS=('2025-06-18','2026-07-28')
COUNTS=dict(processes=22,messages=350,requests=348,responses=344,successful_starts=11)

def declared():
    rows=[dict(name='preflight-'+str(i),domain='preflight',case=dict(protocol=p))
          for i,p in enumerate(PROTOCOLS)]
    rows += [dict(name='success-'+str(i),domain='success',case=c)
             for i,c in enumerate(success_cases.cases())]
    rows += [dict(name='pending-'+str(i)+'-'+action,domain='pending',case=dict(
        name=action+'-'+str(i),protocol=p,action=action,hosts=1,fence='v4',
        key='public-pending-'+action,operation=dict(tool='host_list',arguments={}),
        success=action!='eof',expected_result='stored'))
        for i,p in enumerate(PROTOCOLS)for action in ('normal','cancel','eof')]
    require(len(rows)==22 and len({r['name']for r in rows})==22,'declared lifecycle domain changed')
    return rows

def object_at(path):
    value=json.loads(regular(path));require(type(value)is dict,'expected retained object')
    return value

def counts(folder,process):
    incoming=[json.loads(x)for x in regular(folder/'input.bin').splitlines()]
    outgoing=[json.loads(x)for x in regular(folder/'stdout.bin').splitlines()]
    return dict(processes=1,messages=len(incoming),requests=sum('id'in x for x in incoming),
        responses=len(outgoing),successful_starts=process.get('successful_starts',0))

def reconstruct(spec,folder,binary,process,common):
    require(process['side']==folder.name and type(process.get('pid'))is int
        and process['pid']>0,'actual lifecycle process owner absent')
    if spec['domain']=='preflight':
        answer=preflight_evidence.side(folder,spec['case']['protocol'],process,binary,common=common)
        observations=None
    elif spec['domain']=='success':
        answer=success_evidence.side(spec['case'],folder,binary,process,common=common)
        observations=json.loads(regular(folder/'scheduling-observations.json'))
    else:
        answer,observations,_=pending_evidence.side(spec['case'],folder,binary,process,common=common)
    return answer,observations

def _summary(report):
    return dict(status=report['status'],native_processes=report['counts']['processes']if report['side']=='native'else 0,
        original_processes=report['counts']['processes']if report['side']=='original'else 0,
        requests_per_implementation=report['counts']['requests'],
        producer_starts_per_implementation=report['counts']['successful_starts'])

def verify(folder,binary,*,side='native',retained=None,native_binary=None):
    folder,binary=Path(folder).resolve(strict=True),Path(binary).resolve(strict=True)
    report=object_at(folder/'result.json');plan=declared()
    require(report['schema']=='hepta.public-lifecycle.finite-captures.v1'and report['status']=='PASS'
        and report['side']==side and report['binary']==dict(path=str(binary),**pin(binary))
        and report['sources']==source_pins(ROOT)and report['counts']==COUNTS
        and report['outer_timeout_seconds']==180 and report['response_timeout_seconds']==30
        and all(report[k]is False for k in ('syscall_interception','fault_injection',
            'arbitrary_parallel_handlers_qualified','full_blocking_pool_qualified',
            'production_activated','whole_runtime_replaced')),'finite lifecycle identity/domain changed')
    require(json.loads(regular(folder/'declared-cases.json'))==plan
        and len(report['processes'])==len(report['completed'])==22,'finite lifecycle capture domain incomplete')
    require(report['fixture_controls']==fixture_controls.EXPECTED,
        'fixture transport controls are incomplete')
    require(len({r['pid']for r in report['processes']})==22,'lifecycle process identifiers repeated')
    before_native=None
    if side=='original':
        require(retained is not None and native_binary is not None,'original has no retained native owner')
        retained=Path(retained).resolve(strict=True)
        before_native=verify(retained,native_binary)
        require(report['retained_native']==before_native and report['new_native_processes']==0,
            'original consumer changed the retained native domain')
    else:
        require(retained is None and report['retained_native']is None,'native report has another capture owner')
        require(report['new_native_processes']==22,'actual native execution count changed')
    total={k:0 for k in COUNTS};control_rows=[]
    for index,(spec,process,completed)in enumerate(zip(plan,report['processes'],report['completed'],strict=True)):
        casefolder=folder/spec['name'];common=(casefolder if side=='native'else retained/spec['name'])/'common'
        require(not (common/'state').exists(),'runtime fixture did not retire its temporary live path')
        require(object_at(casefolder/'case.json')==spec,'declared case changed')
        target=casefolder/side
        fixtures.admit(target,spec['domain'],process,require_retired=True)
        answer,observations=reconstruct(spec,target,binary,process,common)
        actual=counts(target,process)
        for key in total:total[key]+=actual[key]
        expected=dict(name=spec['name'],counts=actual,
            projection_sha256=sha(encoded(answer)),observation_sha256=sha(encoded(observations)))
        require(completed==expected,'complete lifecycle projection differs')
        require(object_at(target/'stable-projection.json')==answer,'retained stable projection changed')
        if side=='original':
            native_report=object_at(retained/'result.json')
            native_answer,_=reconstruct(spec,retained/spec['name']/'native',Path(native_binary),
                native_report['processes'][index],common)
            require(answer==native_answer,'full stable original/native lifecycle difference: '+spec['name'])
        if spec['domain']=='pending'and spec['case']['protocol']==PROTOCOLS[0]:
            _,_,raw=pending_evidence.side(spec['case'],target,binary,process,common=common)
            control_rows += [dict(case=spec['name'],**x)for x in pending_evidence.controls(spec['case'],raw)]
    require(total==COUNTS and len(control_rows)==17 and report['controls']==control_rows,
        'lifecycle complete domain or rejection controls changed')
    require(before_native is None or verify(retained,native_binary)==before_native,
        'retained native captures changed during original admission')
    return dict(schema='hepta.public-lifecycle.finite-evidence.v1',report=pin(folder/'result.json'),
        counts=total,controls=17,fixture_transport_controls=len(fixture_controls.EXPECTED),
        source_sha256=sha(encoded(report['sources'])),
        actual_native_processes=22 if side=='native'else 0,
        actual_original_processes=22 if side=='original'else 0,
        retained_native_processes=22 if side=='original'else 0,
        complete_raw_and_filesystem_reconstruction=True,new_executions_in_admission=0,
        production_activated=False,whole_runtime_replaced=False)

def execute(binary,output,*,side='native',retained=None,native_binary=None):
    binary=Path(binary).resolve(strict=True);output=Path(output).resolve()
    require(side in ('native','original'),'unknown implementation')
    output.mkdir(mode=0o700,parents=True,exist_ok=False)
    plan=declared();sources=source_pins(ROOT);identity=dict(path=str(binary),**pin(binary))
    retained=Path(retained).resolve(strict=True)if retained is not None else None
    retained_evidence=verify(retained,native_binary)if side=='original'else None
    require((side=='native')==(retained is None),'retained capture owner mismatch')
    report=dict(schema='hepta.public-lifecycle.finite-captures.v1',status='RUNNING',side=side,
        sources=sources,binary=identity,processes=[],completed=[],controls=[],fixture_controls=[],
        counts={k:0 for k in COUNTS},retained_native=retained_evidence,new_native_processes=0,
        outer_timeout_seconds=180,response_timeout_seconds=30,syscall_interception=False,
        fault_injection=False,arbitrary_parallel_handlers_qualified=False,
        full_blocking_pool_qualified=False,production_activated=False,whole_runtime_replaced=False)
    begin=time.monotonic()
    def save():
        report['elapsed_seconds']=time.monotonic()-begin
        success.atomic(output/'result.json',encoded(report))
    (output/'declared-cases.json').write_bytes(encoded(plan));save()
    try:
        report['fixture_controls']=fixture_controls.run();save()
        for index,spec in enumerate(plan):
            folder=output/spec['name'];folder.mkdir(mode=0o700)
            (folder/'case.json').write_bytes(encoded(spec))
            common=(folder if side=='native'else retained/spec['name'])/'common'
            if side=='native':common.mkdir(mode=0o700)
            else:require(common.is_dir()and not common.is_symlink()and not (common/'state').exists(),
                'retained native fixture path is not ready for its original replay')
            process={};report['processes'].append(process)
            def update(value):
                process.clear()
                if spec['domain']=='pending':
                    omitted=('sends','responses','final','fence_after','baseline_snapshot',
                             'while_blocked_snapshot','completion_snapshot')
                    process.update(copy.deepcopy({k:v for k,v in value.items()if k not in omitted}))
                    process['messages']=len(value['sends'])
                    process['requests']=sum('id'in x['request']for x in value['sends'])
                    process['responses']=len(value['responses'])
                elif spec['domain']=='success':
                    # Complete frames and filesystem snapshots remain in the
                    # per-process result and their independently checked files.
                    # Do not rewrite those large captures in every progress
                    # update of the aggregate report.
                    process.update(copy.deepcopy({k:v for k,v in value.items()
                        if k not in ('frames','boundaries','final')}))
                else:process.update(copy.deepcopy(value))
                save()
            common_arg=common if side=='original'else None
            if spec['domain']=='preflight':
                answer=preflight.run_side(binary,side,folder,spec['case']['protocol'],update,retained_common=common_arg)
                (folder/side/'projection.json').write_bytes(encoded(answer))
            elif spec['domain']=='success':
                success.run_side(spec['case'],folder,binary,side,update,retained_common=common_arg)
            else:
                pending.run_case(spec['case'],folder,binary,side,update,retained_common=common_arg)
            target=folder/side;answer,observations=reconstruct(spec,target,binary,process,common)
            if side=='original':
                original_native=object_at(retained/'result.json')
                native_answer,_=reconstruct(spec,retained/spec['name']/'native',Path(native_binary),
                    original_native['processes'][index],common)
                require(answer==native_answer,'complete original/native lifecycle difference: '+spec['name'])
            actual=counts(target,process)
            for key in report['counts']:report['counts'][key]+=actual[key]
            report['new_native_processes']=report['counts']['processes']if side=='native'else 0
            (target/'stable-projection.json').write_bytes(encoded(answer))
            report['completed'].append(dict(name=spec['name'],counts=actual,
                projection_sha256=sha(encoded(answer)),observation_sha256=sha(encoded(observations))))
            if spec['domain']=='pending'and spec['case']['protocol']==PROTOCOLS[0]:
                _,_,raw=pending_evidence.side(spec['case'],target,binary,process,common=common)
                report['controls'] += [dict(case=spec['name'],**x)for x in pending_evidence.controls(spec['case'],raw)]
            # The completed process, full wire and semantic snapshots have all
            # been checked above. Preserve those captures before retiring only
            # the owned live fixture, so artifact restoration may change inodes.
            fixtures.retire(target,spec['domain'],process)
            save()
        require(report['counts']==COUNTS and len(report['controls'])==17,'actual lifecycle domain incomplete')
        require(source_pins(ROOT)==sources and dict(path=str(binary),**pin(binary))==identity,
            'source or binary changed during lifecycle execution')
        if side=='original':require(verify(retained,native_binary)==retained_evidence,'native captures changed during replay')
        report['status']='PASS';save()
        verify(output,binary,side=side,retained=retained,native_binary=native_binary)
    except BaseException as error:
        report.update(status='FAIL',error=repr(error),traceback=traceback.format_exc());save();raise
    return _summary(report)

if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--retained',type=Path)
    p.add_argument('--native-binary',type=Path)
    a=p.parse_args()
    # The Rust recipe owns the supervised process group. This consumer and
    # every runtime child inherit it; the consumer is not its group leader.
    answer=execute(a.binary,a.output,side='original'if a.retained else'native',
                   retained=a.retained,native_binary=a.native_binary)
    print(json.dumps(answer,sort_keys=True))
