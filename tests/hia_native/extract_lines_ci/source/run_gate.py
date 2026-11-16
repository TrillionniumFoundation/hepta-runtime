"""Fresh native/original body graph, real pairs, physical waits, and inert readers."""
from pathlib import Path
import argparse
import os
import sys
import time
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT))
from common import encoded, loads, pin, read, require, seal, source
from process import Recorder, environment


def run(hepta,output,rust_bin,expected_source):
    frozen=source();require(frozen==expected_source,'explicit frozen source identity')
    domain=loads(read(ROOT/'DOMAIN.json'));output.mkdir(parents=True,exist_ok=False)
    semantic=output/'semantic';semantic.mkdir()
    env,binding=environment(os.environ,rust_bin)
    rec=Recorder(ROOT,semantic/'processes',env);python=str(Path(sys.executable).resolve(strict=True))
    recipes=[('native-build',[python,'-B',ROOT/'build_native.py','--hepta',hepta,'--output',semantic/'native']),
        ('original-build',[python,'-B',ROOT/'build_reference.py','--rust-bin',rust_bin,'--output',semantic/'original']),
        ('ordinary-pairs',[python,'-B',ROOT/'run_paired.py','--original-build',semantic/'original',
            '--native-build',semantic/'native','--output',semantic/'paired']),
        ('capability-controls',[python,'-B',ROOT/'qualify_capabilities.py','--manifest',semantic/'native/BUILD.json',
            '--source-root',ROOT,'--output',semantic/'capabilities'])]
    started=time.monotonic()
    metadata=dict(schema='hepta.extract-lines.capture.v1',status='INCOMPLETE',source_manifest_sha256=frozen,
        domain=pin(read(ROOT/'DOMAIN.json')),producer_root=str(semantic),source_root=str(ROOT),python=python,
        rust_bin=str(rust_bin),compiler_root=str(hepta),environment=binding,
        git_head=os.environ.get('GITHUB_SHA'),run_id=os.environ.get('GITHUB_RUN_ID'),
        full_body_async_qualified=False,public_handler_qualified=False,whole_runtime_replaced=False)
    try:
        for name,argv in recipes:rec.run(name,argv,timeout=domain['process_budgets'][name])
        require(source()==frozen,'source remains unchanged through execution')
        metadata.update(status='PASS',elapsed_seconds=time.monotonic()-started);seal(semantic,metadata)
        readers=Recorder(ROOT,output/'reader-processes',env)
        readers.run('readonly-semantic',[python,'-B',ROOT/'verify_readonly.py','--output',output,
            '--source-manifest-sha256',frozen],timeout=180)
        readers.run('reader-controls',[python,'-B',ROOT/'reader_controls.py','--output',output,
            '--source-manifest-sha256',frozen],timeout=180)
        readers.run('readonly-complete',[python,'-B',ROOT/'verify_readonly.py','--output',output,
            '--source-manifest-sha256',frozen,'--require-controls'],timeout=180)
        result=dict(schema='hepta.extract-lines.gate.v1',status='COMPLETE_LOCAL_EXTRACT_BODY_PASS',
            source_manifest_sha256=frozen,ordinary_root_pairs=153,ordinary_operations_per_side=175,
            physical_capability_cases=26,reader_refusals=8,relocated_admissions=2,post_refusal_admissions=2,
            elapsed_seconds=time.monotonic()-started,full_body_async_qualified=False,
            public_handler_qualified=False,remote_qualified=False,whole_runtime_replaced=False)
        (output/'GATE.json').write_bytes(encoded(result));print(encoded(result).decode(),end='')
    except BaseException as failure:
        metadata.update(status='FAIL',elapsed_seconds=time.monotonic()-started,failure_type=type(failure).__name__,failure=str(failure))
        if not (semantic/'CAPTURE.json').exists():seal(semantic,metadata)
        (output/'GATE.json').write_bytes(encoded(dict(metadata,files_omitted_from_gate=True)));raise


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--hepta',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--rust-bin',type=Path,required=True)
    p.add_argument('--source-manifest-sha256',required=True);a=p.parse_args()
    run(a.hepta.resolve(strict=True),a.output.absolute(),a.rust_bin.resolve(strict=True),a.source_manifest_sha256)
