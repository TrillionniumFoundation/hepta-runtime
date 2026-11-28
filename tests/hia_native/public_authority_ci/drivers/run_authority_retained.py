"""Run all 23 retained native groups on the explicitly rebound authority profile.

The seven immutable v6 receipt groups remain a distinct historical-source gate.
No old receipt is rewritten or promoted to the current profile by this runner.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import signal
import subprocess
import sys
import time

sys.dont_write_bytecode=True
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
def put(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('source','manifests','hepta','output'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();source=a.source.resolve(strict=True);indices=json.loads(a.manifests.read_bytes())
    authority=Path(indices['authority']);probe=Path(indices['probe']);scope=Path(indices['scope'])
    out=a.output.absolute();out.mkdir(parents=True,exist_ok=False);(out/'processes').mkdir()
    sys.path.insert(0,str(source/'scripts'));import hia_native_authority_qualification as q
    before=q.source_pins(source)
    env=dict(os.environ,HIA_HEPTA_DIR=str(a.hepta.resolve(strict=True)),
        HIA_AUTHORITY_ELF_MANIFEST=str(authority),HIA_AUTHORITY_PROBE_MANIFEST=str(probe),
        HIA_AUTHORITY_MANIFEST=str(authority.parent/'module_00.json'),
        HIA_AUTHORITY_LOADER_MANIFEST=str(authority.parent/'module_08.json'),HIA_SCOPE_MANIFEST=str(scope),
        HIA_AUTHORITY_CORPUS_DIR=str(out/'controller'),HIA_AUTHORITY_TEST_REPORT=str(out/'controller.json'),
        HIA_AUTHORITY_KERNEL_CORPUS_DIR=str(out/'kernel'),HIA_AUTHORITY_TRANSPORT_CORPUS_DIR=str(out/'transport'),
        HIA_AUTHORITY_PACKER_REPORT=str(out/'packer.json'),PYTHONDONTWRITEBYTECODE='1')
    report=dict(schema='hepta.public-authority.retained-native.v1',status='RUNNING',processes=[],
        suite_source_root=str(source),runner_source_sha256=SHA(Path(__file__).read_bytes()),
        current_profile_sha256=q.PROFILE_SHA,source_pins=before,original_rust_executed=False,
        historical_v6_receipt_promoted=False,current_sdk_original_replay_pending=True,
        public_http_qualified=False,concurrent_binding_qualified=False,full_sdk_qualified=False,
        production_activated=False,old_path_removed=False)
    put(out/'SUMMARY.json',report)
    for name,_,result_name,tests,counts in q.SUITES[:4]:
        command=[sys.executable,'-I','-B',str(source/'tests/hia_native'/name)];start=time.monotonic();timed=False
        with (out/'processes'/(name+'.stdout')).open('xb') as stdout,(out/'processes'/(name+'.stderr')).open('xb') as stderr:
            process=subprocess.Popen(command,stdout=stdout,stderr=stderr,env=env,start_new_session=True)
            try:code=process.wait(timeout=120)
            except subprocess.TimeoutExpired:
                timed=True;os.killpg(process.pid,signal.SIGKILL);code=process.wait()
        row=dict(label=name,command=command,exit_code=code,timed_out=timed,timeout_seconds=120,
                 elapsed_seconds=time.monotonic()-start)
        for key in ('stdout','stderr'):
            raw=(out/'processes'/(name+'.'+key)).read_bytes();row[key]=dict(bytes=len(raw),sha256=SHA(raw))
        report['processes'].append(row);put(out/'SUMMARY.json',report)
        assert code==0 and not timed,name
        result=json.loads((out/result_name).read_bytes())
        assert result['tests_run']==tests and result['counts_match'] is True and result['counts']==counts,name
        print(json.dumps(dict(group=name,tests=tests,status='PASS',counts=counts)),flush=True)
    assert q.source_pins(source)==before
    report.update(status='RETAINED_NATIVE_23_GROUPS_PASS',test_groups=23,source_unchanged=True)
    put(out/'SUMMARY.json',report)

if __name__=='__main__':main()
