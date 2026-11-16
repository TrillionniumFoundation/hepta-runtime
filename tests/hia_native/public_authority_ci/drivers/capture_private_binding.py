"""Capture owned fixed-graph sessions without reading an original response."""
from pathlib import Path
import argparse
import gzip
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from authority_cases import plan, framed
from ordinary_public_helpers import setup, snapshot

SHA = lambda b: hashlib.sha256(b).hexdigest()
def put(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2)+'\n')

def record(path):
    digest = hashlib.sha256(); size = 0
    with path.open('rb') as stream:
        while block := stream.read(1 << 20):
            digest.update(block); size += len(block)
    return dict(bytes=size, sha256=digest.hexdigest())

def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'manifest', 'output'):
        p.add_argument('--'+name, type=Path, required=True)
    a = p.parse_args(); source=a.source.resolve(strict=True); manifest=a.manifest.resolve(strict=True)
    md=json.loads(manifest.read_bytes()); binary=manifest.parent/md['elf']
    assert md['physical_images']==91 and md['private_instance_fixture'] is True
    assert md['fixture_pseudo_selectors']==[33,34,41,57,58]
    assert record(binary)==dict(bytes=md['elf_bytes'],sha256=md['elf_sha256'])
    assert md['authority_slot']==56 and md['authority_context_offset']==432
    out=a.output.absolute(); out.mkdir(parents=True,exist_ok=False)
    report=dict(schema='hepta.public-authority.private-capture.v1',status='RUNNING',processes=[],
        elf_sha256=md['elf_sha256'],manifest_sha256=SHA(manifest.read_bytes()),
        source_binding_sha256=SHA((source/'native/runtime_mcp_sources.json').read_bytes()),
        target_reference_read=False,original_rust_executed=False,public_http_qualified=False,
        concurrent_binding_qualified=False,full_sdk_qualified=False,production_activated=False,old_path_removed=False)
    put(out/'SUMMARY.json',report)
    for configured in (False,True):
        label='configured' if configured else 'disabled'; folder=out/label;folder.mkdir()
        work,config=setup(folder/'fixture'); corpus=plan(configured);stdin=framed(corpus)
        (folder/'stdin').write_bytes(stdin);put(folder/'CORPUS.json',corpus)
        before=snapshot(folder/'fixture');put(folder/'files-before.json',before)
        command=[str(binary)]+(['--runtime-config',str(config)] if configured else [])
        start=time.monotonic();timed=False
        with (folder/'stdout.raw').open('xb') as stdout,(folder/'stderr').open('xb') as stderr:
            process=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=stdout,stderr=stderr,
                                     cwd=work,env={'PATH':'','LC_ALL':'C'},start_new_session=True)
            try:process.communicate(stdin,timeout=60)
            except subprocess.TimeoutExpired:
                timed=True;os.killpg(process.pid,signal.SIGKILL);process.communicate()
        put(folder/'files-after.json',snapshot(folder/'fixture'))
        receipt=dict(label=label,configured=configured,command=command,exit_code=process.returncode,
            elapsed_seconds=time.monotonic()-start,timed_out=timed,timeout_seconds=60,
            pid=process.pid,environment={'PATH':'','LC_ALL':'C'},input_frames=len(corpus),files={})
        for name in ('stdin','stdout.raw','stderr','CORPUS.json','files-before.json','files-after.json'):
            receipt['files'][name]=record(folder/name)
        with (folder/'stdout.raw').open('rb') as raw,(folder/'stdout.bin.gz').open('xb') as target:
            with gzip.GzipFile(fileobj=target,mode='wb',mtime=0) as packed:
                shutil.copyfileobj(raw,packed,1<<20)
        receipt['files']['stdout.bin.gz']=record(folder/'stdout.bin.gz')
        put(folder/'PROCESS.json',receipt)
        report['processes'].append(dict(label=label,process_sha256=SHA((folder/'PROCESS.json').read_bytes())))
        put(out/'SUMMARY.json',report)
        assert process.returncode==0 and not timed,label
    report.update(status='NATIVE_PRIVATE_BINDING_CAPTURE_COMPLETE',process_count=2,sessions=4,input_frames=56)
    put(out/'SUMMARY.json',report);print(json.dumps(report,sort_keys=True))

if __name__=='__main__':main()
