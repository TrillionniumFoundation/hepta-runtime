"""Instantiate an approved relative source/budget contract on one exact CI checkout."""
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import time


def pin(path):
    path=Path(path).resolve()
    with path.open('rb') as f:digest=hashlib.file_digest(f,'sha256').hexdigest()
    return dict(path=str(path),bytes=path.stat().st_size,sha256=digest)


def save(path,value):
    with Path(path).open('x') as f:json.dump(value,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())


def main():
    started=time.monotonic();self_cpu=time.process_time();children=resource.getrusage(resource.RUSAGE_CHILDREN)
    root=Path(os.environ['GITHUB_WORKSPACE']).resolve();scripts=Path(__file__).resolve().parent
    expected=os.environ['EXPECTED_HEAD_SHA'];head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
    if head!=expected or os.environ.get('GITHUB_RUN_ATTEMPT')!='1' or os.environ.get('GITHUB_EVENT_NAME')!='push':raise ValueError('exact first-attempt push checkout required')
    policy_path=scripts/'CI_POLICY_FROZEN.json';policy=json.loads(policy_path.read_text())
    if policy['status']!='ROOT_AUTHORIZED_ONE_SOURCE_PUBLICATION' or policy['automatic_retry'] is not False:raise ValueError('root-reviewed publication authorization required')
    manifest_path=scripts/'PUBLICATION_MANIFEST.json';manifest=json.loads(manifest_path.read_text())
    if pin(manifest_path)['sha256']!=policy['publication_manifest_sha256']:raise ValueError('reviewed source manifest differs')
    if subprocess.run(['git','merge-base','--is-ancestor',manifest['base_commit'],head],cwd=root,check=False).returncode:raise ValueError('source is not based on reviewed canonical owner')
    changed=set(subprocess.check_output(['git','diff','--name-only',manifest['base_commit'],head],cwd=root,text=True).splitlines())
    allowed={p['path'] for p in manifest['files']}|{str(policy_path.relative_to(root)),str(manifest_path.relative_to(root))}
    if not changed.issubset(allowed):raise ValueError('unreviewed source path changed')
    for record in manifest['files']:
        path=(root/record['path']).resolve()
        if not path.is_relative_to(root):raise ValueError('source path escape')
        actual=pin(path)
        if actual['bytes']!=record['bytes'] or actual['sha256']!=record['sha256']:raise ValueError('source pin differs: '+record['path'])
    files=subprocess.check_output(['git','ls-files','-z'],cwd=root).split(b'\0')
    sources=[pin(root/os.fsdecode(name)) for name in files if name and (root/os.fsdecode(name)).is_file()]
    control=root/'owner-ci-control';control.mkdir(exist_ok=False)
    attempt=root/'owner-ci-attempt001';affinity=[min(os.sched_getaffinity(0))]
    limits=dict(policy['limits'],affinity=affinity,threads=1)
    contract=dict(schema='hepta.native-closure-contract.v1',scope='D1_canonical_root_owner_CI',automatic_retry=False,cwd=str(root),attempt_root=str(attempt),
                  command=[sys.executable,str(scripts/'build_owner_ci.py'),'--contract',str(control/'CONTRACT.json')],
                  source_pins=sources,source_head=head,source_tree=subprocess.check_output(['git','rev-parse','HEAD^{tree}'],cwd=root,text=True).strip(),
                  source_manifest_pin=pin(manifest_path),limits=limits,required_result_status='PASS',result_path=str(attempt/'output/RESULTS.json'),
                  environment={'CARGO_BUILD_JOBS':'1','CARGO_INCREMENTAL':'0','CARGO_TARGET_DIR':str(root/'owner-ci-target'),'RUSTUP_TOOLCHAIN':'1.95.0',
                               'OPENBLAS_NUM_THREADS':'1','OMP_NUM_THREADS':'1','PYTHONDONTWRITEBYTECODE':'1','PYTHONPYCACHEPREFIX':str(control/'fresh_pyc')})
    save(control/'CONTRACT.json',contract)
    save(control/'ADMISSION.json',dict(status='AUTHORIZED_ONE_EXECUTION',scope=contract['scope'],contract_pin=pin(control/'CONTRACT.json'),root_policy_pin=pin(policy_path),source='root-reviewed published source/budget policy; paths/affinity instantiated by pinned bootstrap'))
    dispatch_wall=time.monotonic()-started
    with (control/'supervisor.stdout').open('xb') as stdout,(control/'supervisor.stderr').open('xb') as stderr:
        result=subprocess.run([sys.executable,str(scripts/'run_bounded.py'),'--contract',str(control/'CONTRACT.json'),'--admission',str(control/'ADMISSION.json')],cwd=root,stdout=stdout,stderr=stderr,check=False)
    after=resource.getrusage(resource.RUSAGE_CHILDREN)
    receipt=dict(schema='hepta.owner-ci-bootstrap-receipt.v1',status='PASS' if result.returncode==0 else 'FAILED',source_head=head,source_files=len(sources),
                 source_verification_and_dispatch_wall_seconds=dispatch_wall,whole_wrapper_wall_seconds=time.monotonic()-started,
                 wrapper_CPU_seconds=time.process_time()-self_cpu,all_waited_descendant_CPU_seconds=after.ru_utime+after.ru_stime-children.ru_utime-children.ru_stime,
                 accounting='reaped descendant CPU includes bounded supervisor/build/test; do not add it again from PROCESS. Failure totals remain incomplete/unknown.',
                 actual_descendant_CPU_seconds=(after.ru_utime+after.ru_stime-children.ru_utime-children.ru_stime) if result.returncode==0 else None,
                 descendant_CPU_accounting_complete=result.returncode==0,
                 checkout_upload_and_artifact_download_CPU='outside this wrapper; report job/setup wall bounds and actual download separately, never zero')
    save(control/'BOOTSTRAP.json',receipt);print(json.dumps(receipt))
    raise SystemExit(result.returncode)


if __name__=='__main__':main()
