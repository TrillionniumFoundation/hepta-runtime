"""Negative artifact and complete-corpus controls; no semantic re-execution."""
from __future__ import annotations
import argparse,contextlib,copy,json,os,shutil,struct,sys,tempfile,time,traceback
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
for path in (ROOT/'scripts',HERE):
    if str(path) not in sys.path:sys.path.insert(0,str(path))
import hia_native_atomic_write_qualification as q
from hia_native_atomic_write_build import inspect_bundle,read,obj,file_record,exact,require,sha

@contextlib.contextmanager
def changed(path,raw):
    path=Path(path);old=path.read_bytes();mode=path.stat().st_mode&0o777
    try:
        path.chmod(0o600);path.write_bytes(raw);yield
    finally:path.write_bytes(old);path.chmod(mode)

def raw_json(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()+b'\n'
def clone(source,destination):
    return Path(shutil.copytree(source,destination,ignore=shutil.ignore_patterns('fixture')))

def run(manifest,policy,kernel,boundary,destination,*,reference,hepta,policy_stdout,kernel_stdout,boundary_stdout):
    destination=Path(destination).resolve();destination.mkdir(mode=0o700)
    before=q.pins(ROOT,reference);started=time.monotonic();controls=[]
    result={'schema':'hepta.runtime.atomic-write-evidence-controls.v1','status':'RUNNING','source_files':before,
      'fresh_native_invocations':0,'fresh_original_rust_invocations':0,'controls':controls}
    def refuses(name,call):
        try:call()
        except (ValueError,OSError,EOFError,KeyError,TypeError,AssertionError) as error:
            controls.append({'name':name,'status':'REFUSED','reason':str(error)})
        else:raise AssertionError('mutated evidence was admitted: '+name)
    def jmut(path,name,fn,check):
        value=obj(path);fn(value)
        with changed(path,raw_json(value)):refuses(name,check)
    try:
        positive=q.evidence(manifest,policy,kernel,boundary,reference_root=reference,hepta=hepta,
          policy_stdout=policy_stdout,kernel_stdout=kernel_stdout,boundary_stdout=boundary_stdout)
        (destination/'native-evidence.json').write_bytes(raw_json(positive))
        result['native_evidence']=file_record(destination/'native-evidence.json');result['artifact_evidence']=positive['artifact']
        with tempfile.TemporaryDirectory(prefix='atomic-evidence-',dir=destination) as temp:
            temp=Path(temp);bundle=clone(Path(manifest).parent,temp/'bundle');metadata=bundle/'manifest.json'
            check=lambda:inspect_bundle(metadata)
            base=obj(metadata)
            jmut(metadata,'compiler-pin',lambda v:v.update(compiler_commit='0'*40),check)
            jmut(metadata,'native-capacity',lambda v:v.update(input_capacity=(512<<20)+1),check)
            jmut(metadata,'runtime-fallback-claim',lambda v:v.update(runtime_python_required=True),check)
            jmut(metadata,'missing-compile-file',lambda v:v['policy_compilation'].pop('module.output.bin'),check)
            module=bundle/'policy.json'
            jmut(module,'module-profile',lambda v:v.update(buffer_profile='standard'),check)
            jmut(module,'module-compiler',lambda v:v.update(compiler_sha256='0'*64),check)
            # Rehash the actual replacement at the outward-facing fields.
            # Admission still requires the fixed compiled owner image.
            path=bundle/'policy.image.bin';replacement=bytes([read(path)[0]^1])+read(path)[1:]
            m=obj(module);m['image_sha256']=sha(replacement);meta=copy.deepcopy(base);meta['policy_image_sha256']=sha(replacement)
            meta['policy_manifest_sha256']=sha(raw_json(m))
            with changed(path,replacement),changed(module,raw_json(m)),changed(metadata,raw_json(meta)):
                refuses('consistently-rehashed-policy-image',check)
            path=bundle/'native-atomic-write.elf';replacement=bytearray(read(path));replacement[176]^=1
            meta=copy.deepcopy(base);meta['executable_sha256']=sha(replacement);meta['inspection']['sha256']=sha(replacement)
            with changed(path,bytes(replacement)),changed(metadata,raw_json(meta)):
                refuses('consistently-rehashed-fixed-boundary',check)
            path=bundle/'policy-build/module.output.bin';replacement=bytearray(read(path));replacement[-1]^=1
            receipt_path=bundle/'policy-build/module.receipt.json';stdout_path=bundle/'policy-build/module.stdout.log'
            rec=obj(receipt_path);out=obj(stdout_path);rec['output_sha256']=out['output_sha256']=sha(replacement)
            with changed(path,bytes(replacement)),changed(receipt_path,raw_json(rec)),changed(stdout_path,raw_json(out)):
                refuses('consistently-rehashed-compiler-output-tail',check)
            path=bundle/'packer-build/module.stderr.log'
            with changed(path,b'unaccounted diagnostic\n'):refuses('compiler-stderr',check)
            path=bundle/'policy-build/build.json'
            jmut(path,'compiler-dependency',lambda v:v['compiler_dependency'].update(commit='0'*40),check)
            path=bundle/'pack.stdout.log'
            jmut(path,'packer-source-protection',lambda v:v.update(source_unchanged=False),check)
            path=bundle/'pack.request.json'
            jmut(path,'native-invocation-workspace',lambda v:v.update(workspace_size=(1<<20)-1),check)

            policy_copy=clone(policy,temp/'policy');policy_check=lambda:q.policy_evidence(policy_copy,positive['artifact'])
            policy_result=policy_copy/'result.json'
            jmut(policy_result,'omitted-path-domain',lambda v:v.update(path_cases=88806),policy_check)
            jmut(policy_result,'synthetic-as-real-kernel',lambda v:v.update(actual_filesystem_effects=1),policy_check)
            jmut(policy_result,'actual-native-call-count',lambda v:v.update(native_calls=170946),policy_check)
            for name in ('path-requests.bin.gz','path-native-output.bin.gz','contracts.jsonl.gz'):
                path=policy_copy/name;old=read(path)
                with changed(path,old[:-1]):refuses('incomplete-'+name,policy_check)
            kernel_copy=clone(kernel,temp/'kernel');kernel_check=lambda:q.kernel_evidence(kernel_copy,positive['artifact']['executable']['sha256'])
            kernel_result=kernel_copy/'result.json'
            jmut(kernel_result,'omitted-real-kernel-case',lambda v:v.update(cases=150),kernel_check)
            jmut(kernel_result,'omitted-blocked-signal-domain',lambda v:v.update(cancellation_cases=23),kernel_check)
            jmut(kernel_result,'wrong-kernel-executable',lambda v:v.update(native_or_original_executable_sha256='0'*64),kernel_check)
            jmut(kernel_result,'omitted-kernel-observation',lambda v:v['observations'].pop(),kernel_check)
            jmut(kernel_result,'invented-file-state',lambda v:v['observations'][0]['semantic_snapshot'][0].update(mode=0),kernel_check)
            path=kernel_copy/'0000-existing/stdout.bin'
            with changed(path,read(path)+b'x'):refuses('actual-kernel-stdout-tamper',kernel_check)
            path=kernel_copy/'0000-existing/after-content/0001.bin.gz';old=read(path)
            with changed(path,old[:-1]):refuses('full-file-content-tamper',kernel_check)

            boundary_copy=clone(boundary,temp/'boundary')
            boundary_check=lambda:q.boundary_evidence(boundary_copy,positive['artifact'])
            br=boundary_copy/'result.json'
            jmut(br,'omitted-actual-contract-refusal',lambda v:v.update(actual_contract_refusals=18),boundary_check)
            jmut(br,'omitted-parent-death',lambda v:v.update(actual_owned_worker_deaths=0),boundary_check)
            jmut(br,'omitted-boundary-stream',lambda v:v['observations'][0]['files'].pop('stdout.bin'),boundary_check)
            jmut(br,'invented-refusal-file-state',lambda v:v['observations'][0]['after'][1].update(content_bytes=1),boundary_check)
            path=boundary_copy/'transport-bad-frame/stdout.bin'
            with changed(path,struct.pack('<I',0)):refuses('transport-success-for-invalid-frame',boundary_check)
            path=boundary_copy/'parent-death/trace.json'
            jmut(path,'unreaped-parent-death',lambda v:v['parent_death'].update(reaped=False),boundary_check)
            altered=temp/'completed.stdout';altered.write_bytes(raw_json({'status':'PASS'}))
            refuses('fabricated-completed-policy-stdout',lambda:q.policy_evidence(policy,positive['artifact'],stdout=altered))
            refuses('missing-completed-process-stdout',lambda:q.evidence(manifest,policy,kernel,boundary,reference_root=reference,hepta=hepta))
        exact(q.pins(ROOT,reference),before,'atomic evidence control sources changed')
        exact(inspect_bundle(manifest),positive['artifact'],'original actual bundle changed during refusal controls')
        exact(len(controls),34,'atomic refusal control domain differs')
        result.update(status='PASS',test_groups=4,accepted_complete_native_receipts=1,negative_controls=34,
          actual_native_calls_recounted=170947,actual_kernel_cases_recounted=151,actual_elf_boundary_processes_recounted=28,
          production_activated=False,whole_runtime_replaced=False)
    except BaseException as error:
        result.update(status='FAIL',failure=repr(error),traceback=traceback.format_exc());raise
    finally:
        result['elapsed']=time.monotonic()-started;(destination/'result.json').write_bytes(raw_json(result))
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name,env in [('manifest','HIA_ATOMIC_MANIFEST'),('policy','HIA_ATOMIC_POLICY_CORPUS_DIR'),('kernel','HIA_ATOMIC_KERNEL_DIR'),
      ('boundary','HIA_ATOMIC_BOUNDARY_DIR'),('policy-stdout','HIA_ATOMIC_POLICY_STDOUT'),('kernel-stdout','HIA_ATOMIC_KERNEL_STDOUT'),
      ('boundary-stdout','HIA_ATOMIC_BOUNDARY_STDOUT')]:
        p.add_argument('--'+name,type=Path,default=os.environ.get(env))
    p.add_argument('--runtime',type=Path,default=os.environ.get('HIA_REFERENCE_RUNTIME',ROOT))
    p.add_argument('--hepta',type=Path,default=os.environ.get('HIA_HEPTA_DIR'));p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    if any(getattr(a,name) is None for name in ('manifest','policy','kernel','boundary','policy_stdout','kernel_stdout','boundary_stdout','hepta')):
        p.error('complete native artifacts, all three actual completed stdout files and the pinned compiler are required')
    print(json.dumps(run(a.manifest,a.policy,a.kernel,a.boundary,a.output,reference=a.runtime,hepta=a.hepta,
      policy_stdout=a.policy_stdout,kernel_stdout=a.kernel_stdout,boundary_stdout=a.boundary_stdout),sort_keys=True))
if __name__=='__main__':main()
