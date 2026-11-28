"""Capture all 123 real native filesystem cases before the original recipe."""
from pathlib import Path
import argparse
import gzip
import importlib.util
import json
import os
import shutil
import stat
import sys
import time
import traceback
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
INPUT_FILES = ('cases.py', 'replay_original.py', 'native_capture.py', 'strict_reference.py', 'capture_native.py')


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


def main():
    parser = argparse.ArgumentParser()
    for name in ('manifest', 'output', 'cross-root'): parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    args.output = args.output.absolute(); args.manifest = args.manifest.absolute()
    args.cross_root = args.cross_root.absolute(); args.output.mkdir(mode=0o700)
    prior_umask = os.umask(0o77); started = time.monotonic()
    support = load(HERE/'replay_original.py', '_fs_capture_support')
    corpus = load(HERE/'cases.py', '_fs_capture_cases')
    native = load(HERE/'native_capture.py', '_fs_capture_native')
    strict = load(HERE/'strict_reference.py', '_fs_capture_trace')
    sys.path.insert(0, str(ROOT/'scripts'))
    builder = load(ROOT/'scripts/hia_native_filesystem_parity_build.py', '_fs_capture_builder')
    processes = []; rows = []; receipts = []; traces = []; snapshots = 0; active = None
    frozen = {str(path):support.pin(path) for path in [*(HERE/name for name in INPUT_FILES), Path('/usr/bin/strace')]}
    try:
        assert os.geteuid()!=0 and not args.cross_root.exists()
        assert support.pin(HERE/'cases.py') == dict(bytes=12031, sha256='f2d3efb4e3da4a800206c018908bd5999a6d14b31dc8a7dd81a502413111dedb')
        assert support.pin(HERE/'replay_original.py') == dict(bytes=18199, sha256='f46faf9747aa13c4ea5b1188c3a19fe1d8d1afb5befab3fc4d129da1506b3950')
        support.dump(args.output/'remote-process.json', dict(pid=os.getpid(), cgroup=Path('/proc/self/cgroup').read_text(), argv=sys.argv))
        evidence = builder.inspect_bundle(args.manifest, source_root=ROOT)
        support.dump(args.output/'BUILD-EVIDENCE.json', evidence)
        metadata = json.loads(args.manifest.read_bytes()); binary = args.manifest.parent/metadata['elf']
        frozen[str(binary)] = support.pin(binary); frozen[str(args.manifest)] = support.pin(args.manifest)
        assert frozen[str(binary)]['sha256'] == metadata['elf_sha256'] == builder.ELF_SHA
        source = dict(schema='hepta.runtime.filesystem-parity-native-only-source.v1', source_root=str(ROOT),
             helper_root=str(HERE), helper_files={name:support.pin(HERE/name) for name in INPUT_FILES},
             native_source_files=builder.source_pins(ROOT), bundle_manifest=str(args.manifest),
             bundle_manifest_pin=support.pin(args.manifest), native_elf=dict(path=str(binary), **support.pin(binary)),
             build_evidence=support.pin(args.output/'BUILD-EVIDENCE.json'), fixture_home=str(args.output),
             cross_root=str(args.cross_root), fixture_umask=0o77, elf_umask=0o22, prior_umask=prior_umask,
             uid=os.getuid(), euid=os.geteuid(), gid=os.getgid(), egid=os.getegid(),
             strace=dict(path='/usr/bin/strace', **support.pin(Path('/usr/bin/strace'))),
             actual_original_processes=0, original_outputs_read=False, public_handler_executed=False)
        support.dump(args.output/'SOURCE.json', source)
        groups = corpus.groups(args.output, args.cross_root)
        assert [case['case_id'] for group in groups.values() for case in group['cases']] == list(range(123))
        support.dump(args.output/'INPUTS.json', dict(groups={name:[corpus.summary(case) for case in group['cases']] for name,group in groups.items()},
             fixture_definitions=corpus.fixture_json({name:{key:value for key,value in group.items() if key!='cases'} for name,group in groups.items()})))
        for name, group in groups.items():
            support.setup_fixture(group); folder=args.output/name; folder.mkdir(exist_ok=True)
            def observe(filename, already=None):
                nonlocal snapshots
                value=already if already is not None else support.snapshot(group['roots'],args.output)
                target=folder/filename; support.dump(target,value); snapshots+=1
                return dict(path=str(target.relative_to(args.output)),**support.pin(target))
            observe('prepared-state.json')
            for item in group['setup']:
                if item['kind']=='chmod': os.chmod(item['path'],item['mode'],follow_symlinks=False)
            observe('armed-state.json')
            if name=='cross_device':
                devices=[os.stat(root).st_dev for root in group['roots']]; assert devices[0]!=devices[1]
                support.dump(folder/'devices.json',dict(roots_hex=[root.hex() for root in group['roots']],devices=devices))
            subsets=[[case] for case in group['cases']] if group.get('regular_file_stdin') else [group['cases']]
            for index, subset in enumerate(subsets):
                process_name=name+('-'+str(index) if len(subsets)>1 else '')
                first_before=support.snapshot(group['roots'],args.output)
                active=native.NativeProcess(args.output,process_name,subset,binary,bool(group.get('regular_file_stdin')),support)
                for ordinal, case in enumerate(subset):
                    prefix='case-'+str(case['case_id'])
                    before=observe(prefix+'-before.json',first_before if ordinal==0 else None)
                    row=active.call(case); after=observe(prefix+'-after.json')
                    row.update(corpus.summary(case)); row.update(dict(group=name,process=process_name,before_state=before,after_state=after))
                    rows.append(row)
                    with (args.output/'cases.jsonl').open('a') as stream:
                        stream.write(json.dumps(row,sort_keys=True,ensure_ascii=True,allow_nan=False)+'\n')
                process=active.finish(); active=None; processes.append(process)
                (args.output/'processes.json').write_text(json.dumps(processes,sort_keys=True,indent=2)+'\n')
                receipt=native.receipt_evidence((args.output/process['stderr']['path']).read_bytes(),process['cases'])
                support.dump(args.output/'processes'/process_name/'receipts.json',receipt); receipts.append(receipt)
                current=[row for row in rows if row['process']==process_name]
                trace=native.trace_evidence((args.output/process['trace']['path']).read_bytes(),subset,current,receipt,
                     (process['stdin']['bytes'],process['stdout']['bytes'],process['stderr']['bytes']),strict)
                support.dump(args.output/'processes'/process_name/'trace-evidence.json',trace); traces.append(trace)
            restorations=[]
            for item in group['restore_modes']:
                before=stat.S_IMODE(os.lstat(item['path']).st_mode)
                os.chmod(item['path'],item['mode'],follow_symlinks=False)
                restorations.append(dict(path_hex=item['path'].hex(),before_mode=before,after_mode=stat.S_IMODE(os.lstat(item['path']).st_mode)))
            observe('restored-state.json'); support.dump(folder/'observer-restorations.json',restorations)
        assert len(rows)==123 and len(processes)==8 and snapshots==267
        exdev=[row for row in rows if row['group']=='cross_device']
        assert all(row['status']==1 and row['errno']==18 for row in exdev[:4])
        for process in processes:
            for key in ('stdin','stdout','stderr','trace'):
                path=args.output/process[key]['path']
                with path.open('rb') as src, path.with_name(path.name+'.gz').open('xb') as dest:
                    with gzip.GzipFile(filename='',fileobj=dest,mode='wb',mtime=0) as zipped: shutil.copyfileobj(src,zipped,1<<20)
        for path,value in frozen.items(): assert support.pin(Path(path))==value,('changed input',path)
        assert builder.inspect_bundle(args.manifest,source_root=ROOT)==evidence
        support.dump(args.output/'BOUND-SOURCES.json',frozen)
        result=dict(schema='hepta.runtime.filesystem-parity-native-only-capture.v1',status='PASS',
             cases=len(rows),actual_elf_processes=len(processes),filesystem_snapshots=snapshots,
             native_calls=sum(x['native_calls'] for x in receipts),effects=sum(x['effects'] for x in receipts),
             actual_trace_syscalls=sum(x['actual_semantic_syscalls'] for x in traces),
             actual_trace_lines=sum(x['raw_lines'] for x in traces),opens=sum(x['opens'] for x in receipts),closes=sum(x['closes'] for x in receipts),
             workspace_growth=sum(x['workspace_growth'] for r in receipts for x in r['cases']),
             output_growth=sum(x['output_growth'] for r in receipts for x in r['cases']),
             complete_error_bytes=sum(len(row['short'].encode())+len(row['chain'].encode()) for row in rows),
             source=support.pin(args.output/'SOURCE.json'),inputs=support.pin(args.output/'INPUTS.json'),
             processes=support.pin(args.output/'processes.json'),cases_stream=support.pin(args.output/'cases.jsonl'),
             build_evidence=support.pin(args.output/'BUILD-EVIDENCE.json'),bound_sources=support.pin(args.output/'BOUND-SOURCES.json'),
             source_files_unchanged=True,new_rust_processes=0,original_outputs_read=False,original_comparison_pending=True,
             public_filesystem_handlers_complete=False,whole_runtime_replaced=False,elapsed_seconds=time.monotonic()-started)
        support.dump(args.output/'NATIVE.json',result); print(json.dumps(result,sort_keys=True),flush=True)
    except BaseException:
        failure=dict(traceback=traceback.format_exc(),elapsed_seconds=time.monotonic()-started,completed_cases=len(rows))
        if active is not None:
            try: processes.append(active.finish(failure))
            except BaseException as error: failure['cleanup_error']=repr(error)
        failure['processes']=processes; support.dump(args.output/'FAILURE.json',failure); raise
    finally:
        os.umask(prior_umask)


if __name__=='__main__': main()
