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


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('repo','build','output','cargo','rustc','rustfmt'):
        parser.add_argument('--'+name,required=True,type=Path)
    parser.add_argument('--offline',action='store_true')
    args=parser.parse_args()
    root=args.repo.resolve(strict=True)
    require(root==ROOT and os.getpid()==os.getpgrp(),'reference requires the source-owned outer process group')
    output=args.output.resolve();output.mkdir(mode=0o700,parents=True,exist_ok=False)
    manifest=args.build.resolve(strict=True);built=verify_build(root,manifest)
    pins=source_pins(root);native=manifest.parent/built['executable']
    cargo,rustc,rustfmt=(p.absolute()for p in (args.cargo,args.rustc,args.rustfmt))
    project=output/'project';target=output/'target';temporary=output/'temporary';temporary.mkdir(mode=0o700)
    env={k:v for k,v in os.environ.items()if k not in REMOVED and not k.startswith('HIA_')}
    env.update(RUSTC=str(rustc),CARGO_TARGET_DIR=str(target),TMPDIR=str(temporary),
        CARGO_NET_OFFLINE='true'if args.offline else 'false')
    begin=time.monotonic()
    report=dict(schema='hepta.public-lifecycle.original-result.v1',status='RUNNING',sources=pins,
        build_sha256=sha(regular(manifest)),native_build_evidence=built,cargo=str(cargo),rustc=str(rustc),
        rustfmt=str(rustfmt),tool_sha256={str(p):sha(regular(p.resolve(strict=True)))for p in (cargo,rustc,rustfmt)},
        processes=[],fresh_actual_cargo_build=False,original_blocks=274,locked_registry_dependencies=138,
        native_processes=0,original_processes=0,requests_per_implementation=0,
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
        run('cargo-build',[cargo,'build','--release','--locked','--bin','hia-public-eligible-original',*offline],project,120)
        report['fresh_actual_cargo_build']=True
        origin=target/'release/hia-public-eligible-original';raw=regular(origin)
        binary=output/'original.elf';binary.write_bytes(raw);binary.chmod(0o500)
        require(regular(origin)==raw,'Cargo executable changed while retaining')
        report['original_binary']=dict(origin=str(origin),path=str(binary),bytes=len(raw),sha256=sha(raw))
        report['registry_after']=registry(metadata,lock,original_lock,output/'registry')
        require(report['registry_after']==report['registry_before'],'actual registry sources changed during build')
        command=[sys.executable,'-I','-B',root/'tests/hia_native/public_lifecycle/normal_runner.py',
            '--native',native,'--original',binary,'--output',output/'paired']
        out,err=run('normal-pairs',command,root,120)
        paired=normal_evidence(root,output/'paired',native,binary)
        require(not err and json.loads(out)==paired,'actual complete paired summary differs')
        require(check(root,project)==report['prepared'] and source_pins(root)==pins
            and verify_build(root,manifest)==built and regular(binary)==raw and regular(origin)==raw,
            'reference or native source changed during replay')
        require(registry(metadata,lock,original_lock,output/'registry')==report['registry_before'],
            'actual installed registry changed during replay')
        require(target.is_dir() and not target.is_symlink() and target.parent==output,
            'Cargo cache is not the owned disposable build directory')
        shutil.rmtree(target)
        report['cargo_cache_retired_after_binary_and_source_verification']=True
        report.update(native_processes=64,original_processes=64,requests_per_implementation=359,
            paired=paired,complete_wire_and_filesystem_equality=True,status='PASS')
    except BaseException as error:
        report.update(status='FAIL',error=repr(error));raise
    finally:
        # Cargo caches remain excluded. The actual binary, complete retained
        # crate archives, sources and replay streams are immutable evidence.
        artifacts={}
        for branch in ('project','registry','paired'):
            if (output/branch).exists():
                artifacts.update({branch+'/'+p:d for p,d in inventory(output/branch).items()})
        for path in output.iterdir():
            if path.is_file() and path.name!='result.json':artifacts[path.name]=sha(regular(path))
        report['artifacts']=artifacts;save()
        print(json.dumps({k:report[k]for k in ('status','fresh_actual_cargo_build','native_processes',
            'original_processes','requests_per_implementation','original_blocks','locked_registry_dependencies')},sort_keys=True))


if __name__=='__main__':main()
