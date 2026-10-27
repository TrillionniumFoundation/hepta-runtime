#!/usr/bin/env python3
"""Offline audit of actual X230 custody selfcheck and the resulting lease plan."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parent.parent
PREP=ROOT/'multihost-review/six-host-a54/actual-r01'
DOC=ROOT/'runtime-resume/docs/experiments/x230/a54'
TOOLS='/home/qian/hepta-runtime-optimization-20261023/a41-phase-timing-20261025-r01/a54-six-host-lease-tools-r01'
BUNDLE_SHA='34005768bdfd5649b79ca393d59472014ca717e7e7425ddbc3943910cae5bf6c'
NAMES=[
    'original_wait4_dual_eof_and_non_utf8_bytes_preserved',
    'driver_sigint_cleanup_uses_original_pidfd_and_latched_deadline',
    'ignored_interrupt_forces_only_original_child_without_renewal',
    'pidfd_setup_failure_retains_and_reaps_original_popen',
    'control_eof_preserves_original_child_for_clean_exit',
    'registration_without_write_is_not_submission',
    'actual_partial_control_write_stays_unknown_without_retry',
    'deferred_signal_cannot_interrupt_original_popen_handoff',
    'cleanup_io_error_still_reaps_original_and_cannot_pass',
    'bounded_plan_input_refuses_open_non_eof_pipe',
]


def sha(raw):return hashlib.sha256(raw).hexdigest()


def audit(args):
    checks=[]
    def check(ok,label):
        checks.append({'check':label,'passed':bool(ok)})
        if not ok:raise ValueError(label)
    raw=(PREP/'source-bundle.json').read_bytes()
    check(len(raw)==229922 and sha(raw)==BUNDLE_SHA,'frozen complete source package')
    bundle=json.loads(raw)
    files={r['path']:r['content'].encode() for r in bundle['files']}
    check(len(files)==len(bundle['files'])==10,'fixed10 source bodies')
    for row in bundle['files']:
        check(len(files[row['path']])==row['bytes'] and sha(files[row['path']])==row['sha256'],
              'bundled original source: '+row['path'])
    manifest=json.loads(files['package-manifest.json']);template=json.loads(files['plan.template.json'])
    check_raw=args.selfcheck.read_bytes();check(sha(check_raw)==args.selfcheck_sha256,'actual selfcheck original SHA')
    result=json.loads(check_raw)
    check(result['schema']=='hepta-six-host-lease-custody-selfcheck/v1' and result['passed'] is True
          and result['checks']==NAMES and result['unexecuted']==[],'all10 exact checks actually completed')
    check(result['platform']=='linux' and result['uid']==1000,'actual X230 account Linux check')
    check(result['ssh_connections']==result['agent_queries']==result['business_launches']==0,
          'no SSH or agent or business calls in implementation selfcheck')
    check(result['tested_sources']==manifest['source_sha256'],'all actual tested source hashes match frozen package')
    rows=result['original_local_children']
    check(len(rows)==9 and len({r['original_popen_pid'] for r in rows})==9,'nine distinct original local child identities')
    observations=[]
    for i,row in enumerate(rows):
        wait=row['original_wait4']
        check(wait['pid']==row['original_popen_pid'] and row['custody_uncertain'] is False,
              str(i)+': actual original wait4 and retained custody')
        check(row['stdout_eof'] is True and row['stderr_eof'] is True
              and row['discarded_bytes']=={'stdout':0,'stderr':0},str(i)+': complete exact captured streams')
        for stream in ('stdout','stderr'):
            data=base64.b64decode(row[stream+'_original_base64'],validate=True)
            check(len(data)==row[stream+'_bytes'] and sha(data)==row[stream+'_sha256']
                  and data.decode('utf-8',errors='replace')==row[stream+'_original'],str(i)+': '+stream+' raw byte receipt')
        if i!=8:
            check(row['cleanup_complete'] is True and row['cleanup_errors']==[],str(i)+': original cleanup complete')
        else:
            check(row['cleanup_complete'] is False and row['cleanup_errors']
                  and all('injected selector cleanup failure' in v for v in row['cleanup_errors']),
                  '8: injected I/O failure remains failed although original child was reaped')
        for key in ('driver_abort','ssh_close'):
            if key not in row:continue
            state=row[key];begin=state['started_monotonic'];grace=state['grace_seconds'];forced=state['forced_seconds']
            if key=='driver_abort':
                check(state['grace_deadline']==begin+grace and state['forced_deadline']==begin+grace+forced,
                      str(i)+': fixed original driver cleanup deadlines')
            else:
                check(state['eof_deadline']==begin+grace and state['term_deadline']==begin+grace+forced/2
                      and state['kill_deadline']==begin+grace+forced,str(i)+': fixed original SSH cleanup deadlines')
        observations.append({'slot':i,'pid':wait['pid'],'exit_code':wait['exit_code'],
                             'signals':row['signals'],'cleanup_complete':row['cleanup_complete']})
    check([rows[i]['original_wait4']['exit_code'] for i in (0,1,2,4,5,6,7,8)]==[0,0,-9,0,0,0,0,-9],
          'normal and intentional original exit outcomes')
    check(base64.b64decode(rows[0]['stderr_original_base64'])==b'\xff\tERR\n','non-UTF8 stderr remains original bytes')
    check([s['signal'] for s in rows[1]['signals']]==['SIGINT'] and 'CLEANED\n' in rows[1]['stdout_original'],
          'original graceful driver cleanup observed')
    for i in (2,8):
        check([s['signal'] for s in rows[i]['signals']]==['SIGINT','SIGKILL']
              and all(s['target']=='original_pidfd' for s in rows[i]['signals']),str(i)+': only original forced signals')
    check(rows[3]['signals'][0]['target']=='original_unreaped_Popen'
          and rows[3]['original_wait4'] is not None,'pidfd setup failure still owns original child')
    check(rows[5]['packets'][0]['bytes_written']==0 and rows[5]['packets'][0]['write_state']=='not_written',
          'unwritten registration cannot be mistaken for submission')
    packet=rows[6]['packets'][0]
    check(0<packet['bytes_written']<packet['bytes']==131072 and packet['write_state']=='partial_unknown',
          'actual partial prefix remains an unknown original attempt')
    check(not rows[7]['signals'] and rows[7]['stdout_original']=='OWNED-AFTER-SIGNAL\n',
          'deferred local signal preserves original Popen handoff')
    plan_raw=args.plan.read_bytes();check(sha(plan_raw)==args.plan_sha256,'actual frozen plan original SHA')
    plan=json.loads(plan_raw)
    check(set(plan)==set(template),'frozen plan shape unchanged')
    allowed={'ready','nonce','main_out','custody_selfcheck'}
    check({k:plan[k] for k in plan if k not in allowed}=={k:template[k] for k in template if k not in allowed},
          'only actual selfcheck fresh nonce and readiness fields changed')
    check(plan['ready'] is True and re.fullmatch('[0-9a-f]{32}',plan['nonce']) is not None
          and 'PENDING' not in plan_raw.decode(),'fully frozen fresh attempt plan')
    check(plan['main_out']=='/tmp/hepta-a54-main-lease-'+plan['nonce'],'unique fixed private main evidence directory')
    check(plan['custody_selfcheck']=={'path':TOOLS+'/custody-selfcheck.json','sha256':args.selfcheck_sha256},
          'actual X230 same-source custody receipt bound into plan')
    qraw=(DOC/'qualification-r01.original.json').read_bytes();q=json.loads(qraw)
    check(sha(qraw)==plan['qualification']['sha256'] and q['qualified'] is True and q['current_stage']=='complete'
          and len(q['source_tested'])==175 and q['source_tested']==q['source_after']
          and sha(json.dumps(q['source_tested'],sort_keys=True,separators=(',',':')).encode())==plan['source_map_compact_sha256']
          and q['binary']['sha256']==plan['elf_sha256'],'actual completed A54 r01 qualification 175map and ELF')
    for field,name in [('driver','run_a54_native_validation_r01.py'),('binding','binding.json')]:
        original=(ROOT/'multihost-review/six-host-a54/actual-r01'/name).read_bytes()
        check(sha(original)==plan[field]['sha256'],'actual frozen six-host '+field)
    report={'schema':'hepta-a54-six-host-lease-admission-independent-audit/v1','passed':True,
            'actual_selfcheck':{'path':str(args.selfcheck),'bytes':len(check_raw),'sha256':args.selfcheck_sha256},
            'actual_frozen_plan':{'path':str(args.plan),'bytes':len(plan_raw),'sha256':args.plan_sha256},
            'checks':checks,'original_children':observations,'native_execution_proven':False,
            'fresh_remote_directory_existence_claimed':False,'network_calls':0,'business_launches':0,
            'scope':'Actual X230 same-source implementation checks and planned single native attempt admission only.'}
    encoded=(json.dumps(report,sort_keys=True,indent=2)+'\n').encode()
    assert not args.out.exists(),'do not overwrite an earlier audit'
    args.out.write_bytes(encoded)
    print(json.dumps({'path':str(args.out),'bytes':len(encoded),'sha256':sha(encoded),
                      'checks':len(checks),'passed':True,'native_execution_proven':False},sort_keys=True))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--selfcheck',type=Path,required=True);p.add_argument('--selfcheck-sha256',required=True)
    p.add_argument('--plan',type=Path,required=True);p.add_argument('--plan-sha256',required=True)
    p.add_argument('--out',type=Path,required=True)
    audit(p.parse_args())
