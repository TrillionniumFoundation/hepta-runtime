"""Run the unchanged seven historical receipt groups with their original profile.

Their frozen original observations remain historical evidence. The selected
profile and all 107 retained fixture files are preserved without substitution.
"""
from pathlib import Path
import argparse
import base64
import gzip
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
    for name in ('source','manifests','output'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();source=a.source.resolve(strict=True);out=a.output.absolute()
    indices=json.loads(a.manifests.read_bytes());out.mkdir(parents=True,exist_ok=False);(out/'processes').mkdir()
    sys.path.insert(0,str(source/'scripts'));import hia_native_authority_qualification as q
    before=q.source_pins(source)
    assert q.PROFILE_SHA=='927cb5e16d8c3fcb9f4d61dc00c4aa48ae09592fec8e28cb2ba3deb4b0950b92'
    env=dict(os.environ,HIA_AUTHORITY_ELF_MANIFEST=indices['authority'],
        HIA_AUTHORITY_PROBE_MANIFEST=indices['probe'],HIA_SCOPE_MANIFEST=indices['scope'],
        HIA_AUTHORITY_EVIDENCE_REPORT=str(out/'evidence.json'),PYTHONDONTWRITEBYTECODE='1')
    name='test_authority_evidence.py';command=[sys.executable,'-I','-B',str(source/'tests/hia_native'/name)]
    start=time.monotonic();timed=False
    with (out/'processes'/(name+'.stdout')).open('xb') as stdout,(out/'processes'/(name+'.stderr')).open('xb') as stderr:
        process=subprocess.Popen(command,stdout=stdout,stderr=stderr,env=env,start_new_session=True)
        try:code=process.wait(timeout=120)
        except subprocess.TimeoutExpired:
            timed=True;os.killpg(process.pid,signal.SIGKILL);code=process.wait()
    receipt=dict(label=name,command=command,exit_code=code,timed_out=timed,timeout_seconds=120,
        elapsed_seconds=time.monotonic()-start)
    for key in ('stdout','stderr'):
        raw=(out/'processes'/(name+'.'+key)).read_bytes();receipt[key]=dict(bytes=len(raw),sha256=SHA(raw))
    report=dict(schema='hepta.public-authority.retained-historical.v1',status='RUNNING',processes=[receipt],
        suite_source_root=str(source),runner_source_sha256=SHA(Path(__file__).read_bytes()),source_pins=before,
        historical_profile_sha256=q.PROFILE_SHA,new_owner_profile_qualified_by_this=False,
        original_rust_executed=False,new_native_calls_in_reader_suite=0,
        historical_v6_receipt_promoted=False,production_activated=False,old_path_removed=False)
    put(out/'SUMMARY.json',report);assert code==0 and not timed
    result=json.loads((out/'evidence.json').read_bytes())
    assert result['tests_run']==7 and result['counts_match'] is True and result['counts']==q.EVIDENCE_COUNTS
    files=json.loads(gzip.decompress((source/'tests/hia_native/authority_receipt_fixture.json.gz').read_bytes()))
    assert len(files)==107
    for name,value in files.items():
        relative=Path(name);assert not relative.is_absolute() and '..' not in relative.parts and relative.as_posix()==name
        path=out/'retained-fixture'/relative;path.parent.mkdir(parents=True,exist_ok=True)
        with path.open('xb') as f:f.write(base64.b64decode(value,validate=True))
    assert q.source_pins(source)==before
    report.update(status='HISTORICAL_SEVEN_GROUPS_PASS',test_groups=7,source_unchanged=True,fixture_files=107)
    put(out/'SUMMARY.json',report);print(json.dumps(report,sort_keys=True))

if __name__=='__main__':main()
