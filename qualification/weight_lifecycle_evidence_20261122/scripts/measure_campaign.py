#!/usr/bin/env python3
"""Outer standard-library measurement for one already frozen native campaign."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import time


def verify(pin):
    raw = Path(pin['path']).read_bytes()
    assert len(raw) == pin['bytes'] and hashlib.sha256(raw).hexdigest() == pin['sha256']


def retained_summary(path):
    """Incomplete inner evidence must never prevent the outer cost receipt."""
    raw = None
    try:
        with path.open('rb') as file:
            raw = file.read(8*1024*1024+1)
        if len(raw) > 8*1024*1024:
            return {}, {'sha256_of_read_prefix':hashlib.sha256(raw).hexdigest(),
                        'error':'inner summary exceeds 8 MiB; complete hash unknown'}
        pin = {'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)}
        value = json.loads(raw)
        if not isinstance(value, dict):
            return {}, dict(pin,error='inner summary is not an object')
        return value, pin
    except (OSError, ValueError, UnicodeDecodeError) as error:
        return {}, {'sha256':hashlib.sha256(raw).hexdigest() if raw is not None else None,
                    'bytes':len(raw) if raw is not None else None,'error':repr(error)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--plan', required=True)
    parser.add_argument('--mode', choices=['all-features', 'no-default-features'], required=True)
    parser.add_argument('--output-base', required=True)
    args = parser.parse_args()
    plan_path = Path(args.plan).resolve()
    plan_raw = plan_path.read_bytes()
    plan = json.loads(plan_raw)
    for pin in [plan['script'], plan['input_manifest'], plan['binaries'][args.mode]]:
        verify(pin)
    base = Path(args.output_base).resolve()
    command = [sys.executable, plan['script']['path'],
               '--binary', plan['binaries'][args.mode]['path'],
               '--binary-sha', plan['binaries'][args.mode]['sha256'],
               '--input-manifest', plan['input_manifest']['path'],
               '--input-sha', plan['input_manifest']['sha256'],
               '--output', str(base/args.mode), '--features', args.mode,
               '--source', plan['source_commit']]
    parent = os.getpid()
    libc = ctypes.CDLL(None, use_errno=True)

    def lifetime():
        if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent:
            os._exit(126)

    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    begin = time.monotonic()
    forced = False
    error = None
    with (base/(args.mode+'.stdout')).open('xb') as stdout, (base/(args.mode+'.stderr')).open('xb') as stderr:
        child = subprocess.Popen(command, stdout=stdout, stderr=stderr,
                                 start_new_session=True, preexec_fn=lifetime)
        try:
            child.wait(timeout=plan['per_mode_budget']['wall_seconds'])
        except BaseException as exc:
            error = repr(exc)
            forced = True
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)
        finally:
            if child.poll() is None:
                forced = True
                child.kill()
                child.wait(timeout=5)
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    summary_path = base/args.mode/'RESULTS.json'
    summary, summary_evidence = retained_summary(summary_path)
    descendants_complete = summary.get('all_owned_descendants_reaped') is True
    measurement = {'schema':'hepta.lifecycle-outer-process-measurement.v1',
                   'command':command,'pid':child.pid,'returncode':child.returncode,
                   'plan_sha256':hashlib.sha256(plan_raw).hexdigest(),
                   'wall_seconds':time.monotonic()-begin,
                   'whole_reaped_tree_cpu_seconds':after.ru_utime+after.ru_stime-before.ru_utime-before.ru_stime,
                   'whole_reaped_tree_peak_rss_kib':after.ru_maxrss,
                   'forced_termination':forced,'error':error,
                   'scope':'One campaign process and its reaped descendants; forced termination can make descendant cost incomplete',
                   'inner_result_evidence':summary_evidence,
                   'inner_descendant_accounting_complete':descendants_complete,
                   'exact_descendant_cost_claim':not forced and descendants_complete}
    with (base/(args.mode+'.measurement.json')).open('x') as file:
        json.dump(measurement,file,indent=2)
        file.write('\n')
        file.flush()
        os.fsync(file.fileno())
    print(json.dumps(measurement))
    if child.returncode != 0 or forced:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
