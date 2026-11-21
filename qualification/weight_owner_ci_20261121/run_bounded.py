"""One create-only process group under a separate source-pinned stage contract."""
import argparse
import ctypes
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import resource
import signal
import subprocess
import time


def pin(path):
    path = Path(path).resolve()
    return dict(path=str(path), bytes=path.stat().st_size,
                sha256=hashlib.sha256(path.read_bytes()).hexdigest())


def save(path, value):
    with Path(path).open('x') as f:
        json.dump(value, f, indent=2, allow_nan=False); f.write('\n'); f.flush(); os.fsync(f.fileno())


def utc():
    return datetime.now(timezone.utc).isoformat()


class GroupLedger:
    """Own-PID CPU samples are disjoint lower bounds; reaped root CPU fills short gaps."""
    def __init__(self):
        self.observed_own_ticks={};self.entry_tree_ticks=0

    def sample(self,group):
        members=[]
        for path in Path('/proc').iterdir():
            if not path.name.isdigit():continue
            try:
                fields=(path/'stat').read_text().rsplit(') ',1)[1].split()
                if int(fields[2])!=group:continue
                pid=int(path.name);key=(pid,int(fields[19]));own=int(fields[11])+int(fields[12])
                self.observed_own_ticks[key]=max(self.observed_own_ticks.get(key,0),own)
                if pid==group:self.entry_tree_ticks=max(self.entry_tree_ticks,own+int(fields[13])+int(fields[14]))
                members.append(dict(pid=pid,start_ticks=key[1],state=fields[0],parent_pid=int(fields[1])))
            except (FileNotFoundError,PermissionError,ProcessLookupError):pass
        lower=max(sum(self.observed_own_ticks.values()),self.entry_tree_ticks)/os.sysconf('SC_CLK_TCK')
        return lower,members


def reap_adopted():
    reaped=[]
    while True:
        try:pid,status,usage=os.wait4(-1,os.WNOHANG)
        except ChildProcessError:break
        if pid==0:break
        reaped.append(dict(pid=pid,status=status,CPU_seconds=usage.ru_utime+usage.ru_stime))
    return reaped


def stop_group(group):
    try:os.killpg(group,signal.SIGKILL)
    except ProcessLookupError:pass


def main():
    start, cpu_start = time.monotonic(), time.process_time()
    parser=argparse.ArgumentParser();parser.add_argument('--contract', required=True);parser.add_argument('--admission',required=True)
    args=parser.parse_args();contract_pin=pin(args.contract);c=json.loads(Path(args.contract).read_text())
    authorization=json.loads(Path(args.admission).read_text())
    if (authorization['status']!='AUTHORIZED_ONE_EXECUTION' or authorization['contract_pin']!=contract_pin or
            authorization['scope']!=c['scope'] or c['automatic_retry'] is not False):
        raise ValueError('root frozen single-stage admission differs')
    for expected in c['source_pins']:
        if pin(expected['path']) != expected:
            raise ValueError('frozen stage source changed: '+expected['path'])
    attempt=Path(c['attempt_root']);attempt.mkdir(parents=True,exist_ok=False)
    limits=c['limits'];env=dict(os.environ,**c['environment'])
    def bounded():
        os.sched_setaffinity(0,set(limits['affinity']))
        resource.setrlimit(resource.RLIMIT_CPU,(limits['CPU_soft'],limits['CPU_hard']))
        resource.setrlimit(resource.RLIMIT_AS,(limits['address_space_bytes'],limits['address_space_bytes']))
    launch=dict(schema='hepta.native-closure-launch.v1',scope=c['scope'],created_utc=utc(),contract_pin=contract_pin,
                authorization_pin=pin(args.admission),command=c['command'],limits=limits,source_pins=c['source_pins'])
    save(attempt/'LAUNCH.json',launch)
    before=resource.getrusage(resource.RUSAGE_CHILDREN);reason=None;peak=0.0
    ledger=GroupLedger();child=None;code=None;error=None;residual_before=[];residual_after=[];adopted=[];subreaper_enabled=False
    try:
        # A dedicated supervisor adopts orphan descendants so cleanup can reap them.
        libc=ctypes.CDLL(None,use_errno=True)
        if libc.prctl(36,1,0,0,0)!=0:
            raise OSError(ctypes.get_errno(),'PR_SET_CHILD_SUBREAPER required')
        subreaper_enabled=True
        with (attempt/'stdout.log').open('xb') as out,(attempt/'stderr.log').open('xb') as err:
            child=subprocess.Popen(c['command'],cwd=c['cwd'],env=env,stdout=out,stderr=err,
                                   start_new_session=True,preexec_fn=bounded)
            while child.poll() is None:
                used,_=ledger.sample(child.pid);peak=max(peak,used)
                if time.monotonic()-start>=limits['wall_hard']-limits.get('cleanup_wall_reserve',0):reason='wall_deadline_with_cleanup_reserve'
                if used>=limits['CPU_soft']:reason='CPU_soft'
                if reason:stop_group(child.pid);break
                time.sleep(.05)
            code=child.wait(timeout=5)
    except BaseException as exception:
        error=repr(exception);reason=reason or 'supervisor_exception'
    finally:
        if child is not None:
            if child.poll() is None:
                stop_group(child.pid)
                try:code=child.wait(timeout=5)
                except (subprocess.TimeoutExpired,ChildProcessError):pass
            _,residual_before=ledger.sample(child.pid)
            if residual_before:
                reason=reason or 'residual_descendants_after_entry_exit';stop_group(child.pid)
            deadline=time.monotonic()+5
            while True:
                adopted.extend(reap_adopted());used,residual_after=ledger.sample(child.pid);peak=max(peak,used)
                if not residual_after or time.monotonic()>=deadline:break
                stop_group(child.pid);time.sleep(.02)
            adopted.extend(reap_adopted())
            if residual_after:reason=reason or 'descendant_cleanup_incomplete'
    after=resource.getrusage(resource.RUSAGE_CHILDREN)
    reaped_cpu=after.ru_utime+after.ru_stime-before.ru_utime-before.ru_stime
    peak=max(peak,reaped_cpu)
    if reaped_cpu>=limits['CPU_soft']:reason=reason or 'CPU_soft_at_final_reap'
    try:unchanged=all(pin(p['path'])==p for p in c['source_pins'])
    except OSError as exception:unchanged=False;error=error or repr(exception)
    if not unchanged:reason=reason or 'source_changed'
    if time.monotonic()-start>=limits['wall_hard']:reason=reason or 'wall_hard_after_cleanup'
    expected=Path(c['result_path']);result_ok=False;result_pin=None
    if expected.is_file():
        try:
            result=json.loads(expected.read_text());result_ok=result.get('status')==c['required_result_status']
            result_pin=pin(expected)
        except (ValueError,OSError):pass
    if not result_ok and reason is None:reason='required_result_missing_or_unsuccessful'
    success=code==0 and reason is None and error is None and unchanged and result_ok
    row=dict(launch,schema='hepta.native-closure-process.v2',completed_utc=utc(),returncode=code,
             status='COMPLETED' if success else 'FAILED_OR_UNKNOWN',stop_reason=reason,error=error,
             reaped_child_tree_CPU_seconds=reaped_cpu,actual_descendant_CPU_seconds=reaped_cpu if success else None,
             descendant_CPU_accounting_complete=success,observed_CPU_lower_bound_seconds=peak,
             CPU_accounting_note='Successful frozen steps wait for descendants; failures report reaped usage and observed lower bounds only, never a complete total.',
             supervisor_CPU_seconds=time.process_time()-cpu_start,wall_seconds=time.monotonic()-start,
             peak_child_RSS_KiB=after.ru_maxrss,source_unchanged=unchanged,automatic_retry=False,
             child_subreaper_enabled=subreaper_enabled,adopted_descendants_reaped=adopted,
             residual_descendants_before_cleanup=residual_before,residual_descendants_after_cleanup=residual_after)
    if result_pin is not None:row['result_pin']=result_pin
    save(attempt/'PROCESS.json',row);print(json.dumps(dict(status=row['status'],process_pin=pin(attempt/'PROCESS.json'),stop_reason=reason)))
    raise SystemExit(0 if success else 1)


if __name__=='__main__':main()
