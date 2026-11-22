#!/usr/bin/env python3
"""Kill and restart the complete root binary around canonical owner effects.

Only a four-element synthetic F64 artifact is used. All output is preserved;
completed stages and exact binary/source identity are checked independently.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import shutil
import subprocess
import time

TEST='mcp::weight_artifact::recovery_tests::canonical_f64_crash_recovery_worker'
CUTS=['prepared','publish_intent','publish_before_rename','publish_effect','published',
      'verify_intent','verify_effect','verified','accepted','restore_intent',
      'restore_before_rename','restore_effect','restored','complete']

def digest(b):
    return hashlib.sha256(b).hexdigest()

def save(path,value):
    with open(path,'x',encoding='utf-8') as f:
        json.dump(value,f,indent=2,ensure_ascii=False);f.write('\n');f.flush();os.fsync(f.fileno())

def usage():
    r=resource.getrusage(resource.RUSAGE_CHILDREN)
    s=resource.getrusage(resource.RUSAGE_SELF)
    return {'child_cpu':r.ru_utime+r.ru_stime,'supervisor_cpu':s.ru_utime+s.ru_stime,'children_peak_rss_kib':r.ru_maxrss}

def command(binary):
    return [str(binary),'--ignored','--exact',TEST,'--nocapture','--test-threads=1']

def environment(case,mode,result,cut='',reject=False):
    e=os.environ.copy()
    for k in list(e):
        if k.startswith('HEPTA_RECOVERY_TEST_'):
            del e[k]
    e.update(HEPTA_RECOVERY_TEST_ROOT=str(case),HEPTA_RECOVERY_TEST_MODE=mode,
             HEPTA_RECOVERY_TEST_RESULT=result,HEPTA_RECOVERY_TEST_CUT=cut,
             HEPTA_RECOVERY_TEST_REJECT='true' if reject else 'false')
    return e

def run(binary,case,mode,result,cut='',reject=False,expected_error=None):
    logbase=case.parent/(case.name+'-'+result)
    began=time.monotonic();before=usage()
    with open(str(logbase)+'.stdout','xb') as out,open(str(logbase)+'.stderr','xb') as err:
        p=subprocess.Popen(command(binary),stdout=out,stderr=err,env=environment(case,mode,result,cut,reject),start_new_session=True)
        killed=False
        try:
            if cut:
                end=began+15
                marker=case/'CUT_REACHED.json'
                while not marker.exists():
                    if p.poll() is not None:
                        raise RuntimeError(f'worker ended before {cut}: {p.returncode}')
                    if time.monotonic()>end:
                        raise TimeoutError(f'checkpoint {cut} not reached')
                    time.sleep(.01)
                receipt=json.loads(marker.read_text())
                assert receipt['phase']==cut and receipt['pid']==p.pid,receipt
                os.kill(p.pid,signal.SIGKILL)
                killed=True
                code=p.wait(timeout=5)
                assert code==-signal.SIGKILL,code
            else:
                code=p.wait(timeout=20)
                if code!=0 and expected_error is None:
                    raise RuntimeError(f'worker {mode} failed: {code}; {logbase}.stderr')
                if expected_error is not None and code==0:
                    raise RuntimeError('invalid recovery unexpectedly succeeded')
        finally:
            if p.poll() is None:
                os.killpg(p.pid,signal.SIGKILL);p.wait(timeout=5)
    after=usage()
    if expected_error is not None:
        logs=Path(str(logbase)+'.stdout').read_text()+Path(str(logbase)+'.stderr').read_text()
        assert expected_error in logs,(expected_error,logs)
    return {'pid':p.pid,'returncode':code,'sigkill_sent_by_parent':killed,
            'wall_seconds':time.monotonic()-began,'child_cpu_seconds':after['child_cpu']-before['child_cpu'],
            'supervisor_cpu_seconds':after['supervisor_cpu']-before['supervisor_cpu']}

def inspect(case,expected_effects,expected_pending=()):
    intent=json.loads((case/'INTENT.json').read_text())
    original=(case/'original.safetensors').read_bytes()
    assert digest(original)==intent['source_sha256']
    store=case/'owner-state/weight-artifacts-v1'
    artifacts=[];pending=[]
    if store.exists():
        for p in sorted(store.iterdir()):
            if p.name.startswith('.pending-'):
                pending.append(p.name);continue
            manifest=json.loads((p/'manifest.json').read_text())
            ident=dict(manifest);ident.pop('artifact_id')
            calculated='wa1_'+digest(json.dumps(ident,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode())
            assert calculated==p.name==manifest['artifact_id']
            data=(p/'model.safetensors').read_bytes()
            assert digest(data)==manifest['target_sha256']
            assert len(data)==manifest['patch']['source_size_bytes']
            if manifest['kind']=='restore':
                assert data==original
            artifacts.append({'id':p.name,'kind':manifest['kind'],'content_sha256':digest(data)})
    assert len(artifacts)==expected_effects,artifacts
    assert sorted(pending)==sorted(expected_pending),pending
    if expected_effects:
        assert sorted(x['kind'] for x in artifacts)==['patch','restore']
    journal=case/'journal'
    tree={str(p.relative_to(journal)):digest(p.read_bytes()) for p in journal.rglob('*') if p.is_file()}
    pending_files={str(p.relative_to(store)):digest(p.read_bytes()) for name in pending for p in (store/name).rglob('*') if p.is_file()}
    return {'artifacts':artifacts,'pending':pending,'pending_files':pending_files,'journal_files':tree,'source_sha256':digest(original)}

def latest_record(case):
    records=sorted((case/'journal').rglob('record-*.json'))
    assert records
    return json.loads(records[-1].read_text())

def flip_last_byte(path):
    with open(path,'r+b') as f:
        f.seek(-1,os.SEEK_END);old=f.read(1);f.seek(-1,os.SEEK_END)
        f.write(bytes([old[0]^1]));f.flush();os.fsync(f.fileno())

def main():
    p=argparse.ArgumentParser()
    group=p.add_mutually_exclusive_group(required=True)
    group.add_argument('--binary');group.add_argument('--compiler-json')
    p.add_argument('--source',required=True);p.add_argument('--features',required=True)
    p.add_argument('--output',required=True)
    args=p.parse_args()
    if args.binary:
        binary=Path(args.binary).resolve()
    else:
        outputs=[json.loads(x) for x in Path(args.compiler_json).read_text().splitlines() if x.startswith('{')]
        bins=[x['executable'] for x in outputs if x.get('reason')=='compiler-artifact' and x.get('executable') and x.get('target',{}).get('name')=='hepta_runtime' and 'lib' in x.get('target',{}).get('kind',[])]
        assert len(bins)==1,bins
        binary=Path(bins[0]).resolve()
    assert binary.is_file() and os.access(binary,os.X_OK)
    output=Path(args.output).resolve();output.mkdir(mode=0o700)
    protocol={'schema':'hepta.canonical-recovery-protocol.v1','source_commit':args.source,'features':args.features,
              'binary':str(binary),'binary_sha256':digest(binary.read_bytes()),'test':TEST,'cuts':CUTS,
              'normal_controls':['accept','reject'],'recovery_repetitions':2,'worker_deadline_seconds':20,
              'negative_controls':['corrupt_pending_model','corrupt_pending_manifest','missing_durable_restore','corrupt_durable_restore'],
              'retention_control':'preserve_unrelated_and_partial_pending',
              'scope':'canonical owner with synthetic F64 tensor; no model-quality experiment or production pointer',
              'power_loss_tested':False,'script_sha256':digest(Path(__file__).read_bytes())}
    save(output/'PROTOCOL.json',protocol)
    began=time.monotonic();before=usage();rows=[]
    try:
        for cut in CUTS:
            case=output/('cut-'+cut)
            attempt=run(binary,case,'start','unreachable-start.json',cut=cut)
            resumed=run(binary,case,'recover','recovered.json')
            assert resumed['pid']!=attempt['pid']
            result=json.loads((case/'recovered.json').read_text())
            decision=result['record']['decision']
            expected='KeptOriginal' if cut=='prepared' else 'ResearchAcceptedRestored' if cut=='complete' else 'InterruptedRestored'
            assert decision==expected,(cut,decision,expected)
            assert result['evaluator_calls_this_process']==0 and result['source_unchanged']
            before_retry=inspect(case,0 if cut=='prepared' else 2)
            retried=run(binary,case,'recover','recovered-again.json')
            after_retry=inspect(case,0 if cut=='prepared' else 2)
            assert before_retry==after_retry
            again=json.loads((case/'recovered-again.json').read_text())
            assert again['record']==result['record'] and again['evaluator_calls_this_process']==0
            rows.append({'cut':cut,'status':'PASS','killed_process':attempt,'fresh_recovery':resumed,
                         'idempotent_recovery':retried,'decision':decision,'inspection':after_retry})
            save(output/f'CASE_{len(rows):02}.json',rows[-1])
        for label,reject in [('accept',False),('reject',True)]:
            case=output/('normal-'+label)
            attempt=run(binary,case,'start','normal.json',reject=reject)
            r=json.loads((case/'normal.json').read_text())
            assert r['evaluator_calls_this_process']==1
            assert r['record']['decision']==('ResearchRejectedRestored' if reject else 'ResearchAcceptedRestored')
            checked=inspect(case,2)
            rows.append({'control':label,'status':'PASS','process':attempt,'decision':r['record']['decision'],'inspection':checked})
            save(output/f'CASE_{len(rows):02}.json',rows[-1])
        for label in protocol['negative_controls']:
            case=output/('negative-'+label)
            pending='pending' in label
            cut='publish_before_rename' if pending else 'restored'
            attempt=run(binary,case,'start','unreachable.json',cut=cut)
            store=case/'owner-state/weight-artifacts-v1'
            if pending:
                stages=[x for x in store.iterdir() if x.name.startswith('.pending-')]
                assert len(stages)==1
                if label=='corrupt_pending_model':
                    flip_last_byte(stages[0]/'model.safetensors')
                    expected_error='matching pending content differs'
                else:
                    file=stages[0]/'manifest.json';m=json.loads(file.read_text());m['target_sha256']='0'*64
                    with open(file,'w') as f:
                        json.dump(m,f);f.flush();os.fsync(f.fileno())
                    expected_error='matching pending artifact identity is inconsistent'
            else:
                restore=[x for x in store.iterdir() if x.name.startswith('wa1_') and json.loads((x/'manifest.json').read_text())['kind']=='restore']
                assert len(restore)==1
                if label=='missing_durable_restore':
                    (restore[0]/'model.safetensors').unlink()
                    expected_error='No such file or directory'
                else:
                    flip_last_byte(restore[0]/'model.safetensors')
                    expected_error='canonical pinned artifact content differs'
            refusal=run(binary,case,'recover','must-not-exist.json',expected_error=expected_error)
            assert not (case/'must-not-exist.json').exists()
            record=latest_record(case)
            assert record['stage']==('PublishIntent' if pending else 'Restored')
            assert digest((case/'original.safetensors').read_bytes())==record['intent']['source_sha256']
            rows.append({'negative_control':label,'status':'PASS','killed_process':attempt,'refusal':refusal,
                         'retained_stage':record['stage'],'source_unchanged':True,'false_complete_prevented':True})
            save(output/f'CASE_{len(rows):02}.json',rows[-1])
        case=output/'preserve-unrelated-and-partial'
        attempt=run(binary,case,'start','unreachable.json',cut='publish_intent')
        store=case/'owner-state/weight-artifacts-v1';store.mkdir(parents=True,mode=0o700)
        donor=output/'cut-publish_before_rename/owner-state/weight-artifacts-v1'
        original_stage=next(x for x in donor.iterdir() if x.name.startswith('wa1_') and json.loads((x/'manifest.json').read_text())['kind']=='patch')
        unrelated='.pending-unrelated-complete';partial='.pending-retained-partial'
        shutil.copytree(original_stage,store/unrelated)
        (store/partial).mkdir(mode=0o700)
        with os.fdopen(os.open(store/partial/'model.safetensors',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb') as f:
            f.write(b'partial uncommitted model');f.flush();os.fsync(f.fileno())
        before_files={str(p.relative_to(store)):digest(p.read_bytes()) for name in [unrelated,partial] for p in (store/name).rglob('*') if p.is_file()}
        resumed=run(binary,case,'recover','recovered.json')
        checked=inspect(case,2,[unrelated,partial]);assert checked['pending_files']==before_files
        retried=run(binary,case,'recover','again.json');assert inspect(case,2,[unrelated,partial])==checked
        rows.append({'retention_control':'preserve_unrelated_and_partial_pending','status':'PASS','killed_process':attempt,
                     'fresh_recovery':resumed,'idempotent_recovery':retried,'inspection':checked})
        save(output/f'CASE_{len(rows):02}.json',rows[-1])
        status='PASS'
        error=None
    except BaseException as e:
        status='FAILED_OR_UNKNOWN';error=repr(e)
    after=usage()
    results={'schema':'hepta.canonical-recovery-results.v1','status':status,'error':error,'protocol':protocol,'cases':rows,
             'sigkill_cases_completed':sum('cut' in x for x in rows),'normal_controls_completed':sum('control' in x for x in rows),
             'additional_negative_sigkill_cases':sum('negative_control' in x for x in rows),
             'retained_pending_controls':sum('retention_control' in x for x in rows),
             'wall_seconds':time.monotonic()-began,'child_cpu_seconds':after['child_cpu']-before['child_cpu'],
             'supervisor_cpu_seconds':after['supervisor_cpu']-before['supervisor_cpu'],
             'campaign_children_peak_rss_kib':after['children_peak_rss_kib'],'production_adoption':False,
             'new_model_quality_comparison':False,'power_loss_verified':False}
    save(output/'RESULTS.json',results)
    print(json.dumps({k:v for k,v in results.items() if k not in ['cases','protocol']}))
    if status!='PASS':raise SystemExit(1)

if __name__=='__main__':main()
