#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Fixed, serial R12 matrix on X230; run with main's agent forwarded.
Fresh output paths are required. Existing production services are not changed.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def main():
    root = Path('/home/qian/hepta-runtime-optimization-20261103-r12')
    source = root / 'source'
    harness = source / 'tools/x230/20261103/r12'
    qualification = root / 'qualification-02'
    output = root / 'qualified-matrix-01'
    output.mkdir(mode=0o700)
    report = {'schema':'hepta-x230-r12-qualified-matrix/v1','passed':False,
              'started_unix':time.time(),'stages':[],'service_changes':False,
              'runner_sha256':digest(__file__),'state':'waiting-for-qualification'}
    def save():
        temporary = output / 'report.next'
        temporary.write_text(json.dumps(report, indent=2) + '\n')
        temporary.replace(output / 'report.json')
    def run(name, command, timeout, env=None):
        row = {'name':name,'command':[str(x) for x in command],'returncode':None}
        report['stages'].append(row)
        report['state'] = name
        save()
        print(json.dumps({'stage':name,'state':'started'}), flush=True)
        start = time.monotonic()
        with (output / (name + '.stdout')).open('xb') as stdout, (output / (name + '.stderr')).open('xb') as stderr:
            result = subprocess.run(row['command'], cwd=source, env=env, stdout=stdout, stderr=stderr, timeout=timeout)
        row.update(returncode=result.returncode, seconds=time.monotonic()-start,
                   stdout_sha256=digest(output/(name+'.stdout')), stderr_sha256=digest(output/(name+'.stderr')))
        save()
        print(json.dumps({'stage':name,'returncode':result.returncode,'seconds':row['seconds']}), flush=True)
        if result.returncode:
            raise RuntimeError(name + ' failed; original logs retained')
    save()
    try:
        deadline = time.monotonic()+1800
        while True:
            qualified = json.loads((qualification/'report.json').read_text())
            if qualified.get('finished_utc'):
                break
            if time.monotonic()>deadline:
                raise TimeoutError('qualification still incomplete')
            time.sleep(3)
        if not qualified['qualified'] or qualified['source_tested'] != qualified['source_after']:
            raise RuntimeError('qualification failed or compiler inputs changed')
        candidate = qualification/'hepta-runtime'
        baseline = Path('/home/qian/hepta-runtime-optimization-20261103-r11/qualification-01/hepta-runtime')
        if digest(candidate) != qualified['binaries']['hepta-runtime']['sha256']:
            raise RuntimeError('candidate binary does not match qualification')
        if digest(baseline) != '660d64674fe3422006c0c2a82bc31f3f36edf19baf6613df7cdce51e8f3f8e4c':
            raise RuntimeError('baseline binary changed')
        report['qualification_report_sha256'] = digest(qualification/'report.json')
        report['binary_sha256'] = {'baseline':digest(baseline),'candidate':digest(candidate)}
        artifacts = [json.loads(line) for line in (qualification/'retained-artifacts.jsonl').read_text().splitlines()]
        libtests = [a['executable'] for a in artifacts if a.get('reason')=='compiler-artifact'
                    and a.get('profile',{}).get('test') and a.get('executable')
                    and 'lib' in a.get('target',{}).get('kind',[])]
        if len(libtests)!=1:
            raise RuntimeError('expected exactly one qualified library test binary')
        report['persistence_libtest_sha256'] = digest(libtests[0])
        env = dict(os.environ)
        env['HEPTA_PERSISTENCE_BENCH_OUTPUT'] = str(output/'persistence-cargo.json')
        run('persistence-cargo', [libtests[0],'--exact','--ignored','--test-threads=1','--nocapture',
            'mcp::runtime::jobs::persistence::tests::reserved_receipt_encoding_and_durable_save_benchmark'],180,env)
        run('cancel-responsiveness',['python3',harness/'run_cancel_responsiveness.py',
            '--baseline',baseline,'--candidate',candidate,'--out',root/'cancel-responsiveness-01',
            '--workers','1','2','--receipt-bytes','1024','4194272','--waves','24'],900)
        template = Path('/home/qian/hepta-runtime-optimization-20261023/r11-native-observation-abba-20261103-02/profile/profile.json')
        frozen = Path('/home/qian/hepta-runtime-optimization-20261023/a31-frozen-originals-r01')
        canary_sockets = Path('/home/qian/hepta-r12-cs1')
        canary_sockets.mkdir(mode=0o700)
        run('cancel-recovery',['python3',harness/'run_six_host_cancel_recovery.py',
            '--candidate',candidate,'--profile-template',template,'--frozen-jobs',frozen,
            '--socket-parent',canary_sockets,'--out',root/'candidate-cancel-recovery-01',
            '--workers','2','--interrupt-host','rog'],650)
        observation_sockets = Path('/home/qian/hepta-r12-ns1')
        observation_sockets.mkdir(mode=0o700)
        run('native-observation',['python3',harness/'run_native_observation.py',
            '--baseline',baseline,'--candidate',candidate,'--profile-template',template,
            '--frozen-jobs',frozen,'--socket-parent',observation_sockets,
            '--out',root/'native-observation-01','--calls','96','--concurrency','1','4','8',
            '--workers','2','--order','ABBA','--warmup-calls','24'],900)
        report['passed'] = True
        report['state'] = 'finished'
    except Exception as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
        report['state'] = 'failed'
    finally:
        report['finished_unix'] = time.time()
        save()
        print(json.dumps({'passed':report['passed'],'error':report.get('error'),'report':str(output/'report.json')}), flush=True)
    return 0 if report['passed'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
