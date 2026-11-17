#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Fresh Rust 1.95 outer call_tool reference and complete normal paired replay.

The caller must supervise this new process group with its unchanged 180-second
deadline. All descendants inherit that group. No fault injection is performed.
"""
from pathlib import Path
import argparse, json, os, shutil, signal, subprocess, sys, time, tomllib
ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'scripts'),str(ROOT/'tests/hia_native/public_lifecycle')]
from public_lifecycle_registry import encoded, regular, require, sha, source_pins
from hia_native_public_lifecycle_reference import prepare,check
from hia_native_public_lifecycle_qualification import verify_build,normal_evidence,inventory
from public_lifecycle_crates import REMOVED,registry
from public_lifecycle_retained import LIFECYCLE, admit, pin
from normal_original import verify as retained_pair_evidence
from lifecycle_suite import verify as retained_lifecycle_evidence


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('repo','build','output','cargo','rustc','rustfmt'):
        parser.add_argument('--'+name,required=True,type=Path)
    parser.add_argument('--native-admission',required=True,type=Path)
    parser.add_argument('--native-admission-sha256',required=True)
    parser.add_argument('--native-invocation',required=True)
    parser.add_argument('--offline',action='store_true')
    args=parser.parse_args()
    root=args.repo.resolve(strict=True)
    require(root==ROOT and os.getpid()==os.getpgrp(),'reference requires the source-owned outer process group')
    output=args.output.resolve();output.mkdir(mode=0o700,parents=True,exist_ok=False)
    manifest=args.build.resolve(strict=True);built=verify_build(root,manifest)
    pins=source_pins(root);native=manifest.parent/built['executable']
    admission=args.native_admission.resolve(strict=True)
    retained=admit(admission,args.native_admission_sha256,args.native_invocation,root,manifest,execution=True)
    cargo,rustc,rustfmt=(p.absolute()for p in (args.cargo,args.rustc,args.rustfmt))
    project=output/'project';target=output/'target';temporary=output/'temporary';temporary.mkdir(mode=0o700)
    env={k:v for k,v in os.environ.items()if k not in REMOVED and not k.startswith('HIA_')}
    env.update(RUSTC=str(rustc),CARGO_TARGET_DIR=str(target),TMPDIR=str(temporary),
        CARGO_NET_OFFLINE='true'if args.offline else 'false')
    begin=time.monotonic()
    report=dict(schema='hepta.public-lifecycle.original-result.v2',status='RUNNING',sources=pins,
        build_sha256=sha(regular(manifest)),native_build_evidence=built,cargo=str(cargo),rustc=str(rustc),
        rustfmt=str(rustfmt),tool_sha256={str(p):sha(regular(p.resolve(strict=True)))for p in (cargo,rustc,rustfmt)},
        processes=[],fresh_actual_cargo_build=False,original_blocks=315,locked_registry_dependencies=140,
        native_processes=0,original_processes=0,requests_per_implementation=0,
        retained_native_processes=86,retained_native_requests=707,retained_native=retained,
        native_admission=str(admission),native_admission_sha256=args.native_admission_sha256,
        native_invocation=args.native_invocation,
        actual_outer_call_tool_included=True,original_index_present_branch_qualified=False,
        syscall_interception=False,fault_injection=False,external_host_operations=0,
        production_activated=False,whole_runtime_replaced=False,
        environment=dict(removed=list(REMOVED),removed_prefixes=['HIA_'],RUSTC=str(rustc),
            CARGO_TARGET_DIR=str(target),TMPDIR=str(temporary),offline=args.offline),
        owner=dict(pid=os.getpid(),pgid=os.getpgrp(),outer_timeout_seconds=180,
            inherited_child_process_group=True,parent_death_cleanup_qualified=False))
    def save():
        report['elapsed_seconds']=time.monotonic()-begin
        (output/'result.json').write_bytes(encoded(report))
    def run(name,command,cwd,timeout):
        command=list(map(str,command));started=time.monotonic();timed=False;error=None;pid=None
        try:
            process=subprocess.Popen(command,cwd=cwd,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            pid=process.pid
            try:out,err=process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired as failure:
                out,err=failure.output or b'',failure.stderr or b'';timed=True
            code=process.returncode
        except OSError as failure:out,err,code,error=b'',b'',None,repr(failure)
        for suffix,raw in (('stdout',out),('stderr',err)):(output/(name+'.'+suffix)).write_bytes(raw)
        report['processes'].append(dict(name=name,command=command,cwd=str(cwd),pid=pid,
            exit_code=code,timed_out=timed,start_error=error,timeout_seconds=timeout,
            elapsed_seconds=time.monotonic()-started,stdout_bytes=len(out),stdout_sha256=sha(out),
            stderr_bytes=len(err),stderr_sha256=sha(err)))
        if timed:report.update(status='FAIL',error='owned process group deadline: '+name)
        save()
        if timed:os.killpg(os.getpgrp(),signal.SIGKILL)
        require(error is None and code==0,'actual reference command failed: '+name)
        return out,err
    def run_captures(normal_command,lifecycle_command):
        # Both consumers use the same immutable ELF but disjoint retained
        # common directories. The normal consumer first completes its full
        # cross-domain native admission; only then may the lifecycle consumer
        # create a temporary live fixture. Parent verification waits for both.
        # Direct files preserve all actual output even if the outer group is
        # killed. There are no new native runtime executions in this helper.
        jobs=[]
        def launch(name,command):
            command=list(map(str,command));started=time.monotonic()
            row=dict(name=name,command=command,cwd=str(root),pid=None,
                exit_code=None,timed_out=False,start_error=None,timeout_seconds=120,
                elapsed_seconds=0,stdout_bytes=0,stdout_sha256=sha(b''),
                stderr_bytes=0,stderr_sha256=sha(b''))
            report['processes'].append(row)
            job=dict(row=row,started=started,process=None,done=False)
            jobs.append(job)
            try:
                with (output/(name+'.stdout')).open('xb') as stdout, \
                     (output/(name+'.stderr')).open('xb') as stderr:
                    job['process']=subprocess.Popen(command,cwd=root,env=env,
                        stdout=stdout,stderr=stderr)
                row['pid']=job['process'].pid
            except OSError as error:
                row['start_error']=repr(error)
                abort('original capture launch failed: '+name)
            save()
            return job
        def record(job):
            row=job['row'];process=job['process']
            row['elapsed_seconds']=time.monotonic()-job['started']
            row['exit_code']=None if process is None else process.poll()
            for suffix in ('stdout','stderr'):
                path=output/(row['name']+'.'+suffix)
                raw=regular(path) if path.exists() else b''
                row[suffix+'_bytes'],row[suffix+'_sha256']=len(raw),sha(raw)
            save()
        def abort(reason):
            for job in jobs:record(job)
            report.update(status='FAIL',error=reason);save()
            # The entry check requires this process to lead the owned group.
            os.killpg(os.getpgrp(),signal.SIGKILL)
            raise RuntimeError(reason)
        normal=launch('normal-pairs',normal_command)
        ready_path=output/'paired/native-admission-ready.json'
        while True:
            if time.monotonic()-normal['started']>=120:
                normal['row']['timed_out']=True
                abort('owned original capture deadline before native-admission barrier')
            ready=None
            if ready_path.exists():
                try:ready=json.loads(regular(ready_path))
                except json.JSONDecodeError:pass
            if ready is not None:
                expected=dict(schema='hepta.public-lifecycle.original-capture-ready.v1',
                    pid=normal['row']['pid'],process_group=os.getpgrp(),output=str(output/'paired'),
                    admission=pin(admission),invocation=args.native_invocation,manifest=pin(manifest),
                    original_binary=pin(binary),complete_native_admission=True,native_processes=0)
                if ready!=expected:abort('source-owned original admission barrier differs')
                break
            if normal['process'].poll() is not None:
                abort('original capture exited without its complete native-admission barrier')
            time.sleep(0.01)
        report['capture_scheduling']=dict(
            schema='hepta.public-lifecycle.independent-consumers.v1',
            admission_ready_file='paired/native-admission-ready.json',
            admission_ready=pin(ready_path),normal_pid=normal['row']['pid'],
            native_admission_completed_before_lifecycle=True,
            normal_live_before_lifecycle=normal['process'].poll() is None,
            parent_verification_after_both=True,native_processes=0)
        lifecycle=launch('lifecycle-pairs',lifecycle_command)
        report['capture_scheduling']['lifecycle_pid']=lifecycle['row']['pid'];save()
        while not all(job['done']for job in jobs):
            for job in jobs:
                if job['done']:continue
                if job['process'].poll() is not None:
                    record(job);job['done']=True
                elif time.monotonic()-job['started']>=120:
                    job['row']['timed_out']=True
                    abort('owned original capture deadline: '+job['row']['name'])
            if not all(job['done']for job in jobs):time.sleep(0.01)
        require(all(job['row']['exit_code']==0 for job in jobs),
            'actual original capture command failed')
        return tuple((regular(output/(job['row']['name']+'.stdout')),
                      regular(output/(job['row']['name']+'.stderr')))for job in jobs)
    save()
    try:
        report['prepared']=prepare(root,project)
        version,error=run('rustc-version',[rustc,'--version','--verbose'],root,10)
        require(not error and b'release: 1.95.0\n'in version,'explicit Rust 1.95 required')
        offline=['--offline']if args.offline else []
        run('cargo-fetch',[cargo,'fetch','--locked',*offline],project,120)
        metadata,error=run('cargo-metadata',[cargo,'metadata','--locked','--format-version','1',*offline],project,30)
        require(not error,'actual Cargo metadata stderr differs')
        metadata=json.loads(metadata)
        lock=tomllib.loads(regular(project/'Cargo.lock').decode())
        original_lock=tomllib.loads(regular(root/'Cargo.lock').decode())
        report['registry_before']=registry(metadata,lock,original_lock,output/'registry')
        run('cargo-build',[cargo,'build','--release','--locked','--bin','hia-public-async-original',*offline],project,120)
        report['fresh_actual_cargo_build']=True
        origin=target/'release/hia-public-async-original';raw=regular(origin)
        binary=output/'original.elf';binary.write_bytes(raw);binary.chmod(0o500)
        require(regular(origin)==raw,'Cargo executable changed while retaining')
        report['original_binary']=dict(origin=str(origin),path=str(binary),bytes=len(raw),sha256=sha(raw))
        report['registry_after']=registry(metadata,lock,original_lock,output/'registry')
        require(report['registry_after']==report['registry_before'],'actual registry sources changed during build')
        normal_command=[sys.executable,'-I','-B',root/'tests/hia_native/public_lifecycle/normal_original.py',
            '--admission',admission,'--admission-sha256',args.native_admission_sha256,
            '--invocation',args.native_invocation,'--build',manifest,
            '--original',binary,'--output',output/'paired','--defer-final-admission']
        lifecycle_command=[sys.executable,'-I','-B',root/'tests/hia_native/public_lifecycle/lifecycle_suite.py',
            '--binary',binary,'--retained',admission.parent/LIFECYCLE,'--native-binary',native,
            '--output',output/'lifecycle','--defer-final-admission']
        normal_streams,lifecycle_streams=run_captures(normal_command,lifecycle_command)
        out,err=normal_streams
        paired=retained_pair_evidence(output/'paired',binary,admission,args.native_admission_sha256,
            args.native_invocation,manifest,captured=True)
        require(not err and json.loads(out)==dict(status='CAPTURED_NOT_QUALIFIED',native_processes=0,
            retained_native_processes=64,original_processes=64,requests_per_implementation=359),
            'actual complete paired capture summary differs')
        report.update(original_processes=64,requests_per_implementation=359);save()
        out,err=lifecycle_streams
        finite=retained_lifecycle_evidence(output/'lifecycle',binary,side='original',
            retained=admission.parent/LIFECYCLE,native_binary=native,captured=True)
        require(not err and json.loads(out)==dict(status='CAPTURED_NOT_QUALIFIED',native_processes=0,original_processes=22,
            requests_per_implementation=348,producer_starts_per_implementation=11),
            'actual finite lifecycle paired summary differs')
        require(check(root,project)==report['prepared'] and source_pins(root)==pins
            and verify_build(root,manifest)==built and regular(binary)==raw and regular(origin)==raw,
            'reference or native source changed during replay')
        require(registry(metadata,lock,original_lock,output/'registry')==report['registry_before'],
            'actual installed registry changed during replay')
        require(admit(admission,args.native_admission_sha256,args.native_invocation,root,manifest,execution=True)==retained,
            'current native capture or execution binding changed')
        controls=[sys.executable,'-I','-B',root/'tests/hia_native/public_lifecycle/retained_controls.py',
            '--admission',admission,'--admission-sha256',args.native_admission_sha256,
            '--invocation',args.native_invocation,'--build',manifest,'--output',output/'controls']
        out,err=run('retained-native-controls',controls,root,30)
        require(not err and json.loads(out)==dict(status='PASS',rejected_controls=16,
            complete_restoration=True,native_processes=0,original_processes=0),
            'retained native evidence controls failed')
        require(target.is_dir() and not target.is_symlink() and target.parent==output,
            'Cargo cache is not the owned disposable build directory')
        shutil.rmtree(target)
        report['cargo_cache_retired_after_binary_and_source_verification']=True
        report.update(native_processes=0,original_processes=86,requests_per_implementation=707,
            paired=paired,lifecycle=finite,complete_wire_and_filesystem_equality=True,status='PASS')
    except BaseException as error:
        report.update(status='FAIL',error=repr(error));raise
    finally:
        # Cargo caches remain excluded. The actual binary, complete retained
        # crate archives, sources and replay streams are immutable evidence.
        artifacts={}
        for branch in ('project','registry','paired','lifecycle','controls'):
            if (output/branch).exists():
                artifacts.update({branch+'/'+p:d for p,d in inventory(output/branch).items()})
        for path in output.iterdir():
            if path.is_file() and path.name!='result.json':artifacts[path.name]=sha(regular(path))
        report['artifacts']=artifacts;save()
        print(json.dumps({k:report[k]for k in ('status','fresh_actual_cargo_build','native_processes',
            'retained_native_processes','original_processes','requests_per_implementation','original_blocks','locked_registry_dependencies')},sort_keys=True))


if __name__=='__main__':main()
