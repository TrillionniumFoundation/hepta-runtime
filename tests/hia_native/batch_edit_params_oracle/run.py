"""Fresh, locked original parameter/SDK replay; no native semantics here."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import subprocess
import time


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def run(runtime, output, rust_bin):
    runtime, output, rust_bin = map(lambda p:Path(p).resolve(), (runtime, output, rust_bin))
    here = Path(__file__).resolve().parent
    output.mkdir(parents=True, exist_ok=False)
    manifest = module('batch_original_sources', here/'verify_sources.py').verify(runtime, here)
    def identity(path):
        raw=path.read_bytes()
        return {'path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
    toolchain={name:identity(rust_bin/name) for name in ('rustc','cargo')}
    cases = module('batch_original_cases', here/'cases.py')
    rows = list(cases.iter_cases())+list(cases.extra_cases())+list(cases.sdk_cases())
    wire = cases.encode(rows)
    (output/'input.jsonl').write_bytes(wire)
    env = dict(os.environ)
    env.update(PATH=str(rust_bin)+':/usr/bin:/bin', RUSTC=str(rust_bin/'rustc'),
               CARGO_BUILD_JOBS='2', LC_ALL='C', CARGO_TARGET_DIR=str(output/'target'))
    receipts = []
    def execute(name, command, stdin=None):
        started = time.monotonic()
        stdout_path, stderr_path = output/(name+'.stdout'), output/(name+'.stderr')
        timeout = False
        with stdout_path.open('wb') as stdout, stderr_path.open('wb') as stderr:
            try:
                proc = subprocess.run(command, input=stdin, cwd=here, env=env,
                                      stdout=stdout, stderr=stderr, timeout=180, check=False)
                exit_code = proc.returncode
            except subprocess.TimeoutExpired:
                timeout = True
                exit_code = None
        receipt = {'name':name, 'command':list(map(str,command)), 'cwd':str(here),
                   'timeout_seconds':180, 'timed_out':timeout, 'exit_code':exit_code,
                   'elapsed_seconds':time.monotonic()-started,
                   'controlled_env':{k:env[k] for k in ('PATH','RUSTC','CARGO_BUILD_JOBS','LC_ALL','CARGO_TARGET_DIR')},
                   'stdin':None if stdin is None else {'bytes':len(stdin),'sha256':hashlib.sha256(stdin).hexdigest()}}
        for stream, path in (('stdout',stdout_path),('stderr',stderr_path)):
            raw = path.read_bytes()
            receipt[stream]={'path':path.name,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
        receipts.append(receipt)
        (output/'process-receipts.json').write_text(json.dumps(receipts,indent=2,sort_keys=True)+'\n')
        assert not timeout and exit_code == 0, (name,receipt)
        return stdout_path
    version = execute('rustc-version',[rust_bin/'rustc','--version']).read_bytes()
    assert version == b'rustc 1.95.0 (59807616e 2026-04-14)\n', version
    execute('cargo-build',[rust_bin/'cargo','build','--release','--locked','--manifest-path',here/'Cargo.toml'])
    binary = output/'target/release/hepta-batch-edit-params-original-oracle'
    result_path = execute('original',[binary],wire)
    results = [json.loads(line) for line in result_path.read_bytes().splitlines()]
    assert len(results) == len(rows)
    assert [(r['case_id'],r['name'],r['domain']) for r in results] == [(r['case_id'],r['name'],r['domain']) for r in rows]
    summary = {'status':'PASS','cases':len(rows),'typed_object_cases':sum(r['domain']=='typed-object' for r in rows),
               'private_raw_value_cases':sum(r['domain']=='private-raw-value' for r in rows),
               'actual_sdk_cases':sum(r['domain']=='actual-sdk' for r in rows),
               'original_batch_handler_executed':False,'effects_executed':False,
               'actual_processes':len(receipts),'source_manifest':manifest,'toolchain':toolchain,
               'binary':{'bytes':binary.stat().st_size,'sha256':hashlib.sha256(binary.read_bytes()).hexdigest()},
               'input':{'bytes':len(wire),'sha256':hashlib.sha256(wire).hexdigest()},
               'output':{'bytes':result_path.stat().st_size,'sha256':hashlib.sha256(result_path.read_bytes()).hexdigest()},
               'harness_sources':{str(p.relative_to(here)):{'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(here.rglob('*')) if p.is_file()}}
    assert toolchain == {name:identity(rust_bin/name) for name in ('rustc','cargo')}
    (output/'result.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n')
    print(json.dumps(summary,sort_keys=True))
    return summary


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--runtime',required=True);p.add_argument('--output',required=True)
    p.add_argument('--rust-bin',required=True)
    a=p.parse_args();run(a.runtime,a.output,a.rust_bin)
