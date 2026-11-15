"""Run both actual Local batch bodies at the identical owned fixture path."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys
import time

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
sys.path.insert(0,str(HERE.parents[1]/'scripts'))
from test_batch_write_files import execute
from batch_write_trace_common import equal_streams,json_bytes
import hia_native_batch_write_qualification as q

sha=lambda raw:hashlib.sha256(raw).hexdigest()


def run(native,original,reference,output):
    native=native.resolve(strict=True);original=original.resolve(strict=True)
    reference=reference.resolve(strict=True);output=output.absolute();output.mkdir(parents=True,exist_ok=False)
    sources={str(path):sha(path.read_bytes()) for path in [
        HERE/'compare_batch_write_files.py',HERE/'test_batch_write_files.py',
        HERE/'test_batch_write_controller.py',HERE/'batch_write_harness.py',
        HERE/'batch_render_reference.py',HERE/'batch_write_trace_common.py']}
    sources.update({str(reference/name):sha((reference/name).read_bytes()) for name in [
        'tests/hia_native/test_batch_plan.py','tests/hia_native/batch_plan_harness.py',
        'tests/hia_native/test_line_endpoint.py','tests/hia_native/test_line_verify.py',
        'tests/hia_native/batch_apply_reference.py','tests/hia_native/test_editable_content.py',
        'tests/hia_native/rust_debug_properties.json','scripts/hia_native_loader.py']})
    result={'schema':'hepta.runtime.batch-write-files-comparison.v1','status':'RUNNING',
            'source_inputs':sources,'native_sha256':sha(native.read_bytes()),'original_sha256':sha(original.read_bytes()),
            'required_outer_timeout_seconds':180,'actual_original_calls':0,'actual_native_calls':0}
    started=time.monotonic()
    try:
        native_result=execute(native,reference,output/'fixture',output/'native',large=True)
        assert native_result['status']=='PASS' and native_result['requests']==926
        result['actual_native_calls']=native_result['requests']
        captured=q.file_process_evidence(output/'native',result['native_sha256'],reference)
        result['native_fixture_retirement']={'path':str(output/'fixture'),
            'complete_capture_verified_before_removal':True,
            'verified_evidence_sha256':sha(json_bytes(captured))}
        shutil.rmtree(output/'fixture')
        original_result=execute(original,reference,output/'fixture',output/'original',large=True)
        assert original_result['status']=='PASS' and original_result['requests']==926
        summary=json.loads((output/'original/stderr.bin').read_bytes())
        assert summary=={'status':'PASS','original_owner_calls':926,'responses':926,'canceled':0},summary
        assert (output/'native/stderr.bin').read_bytes()==b''
        result['actual_original_calls']=summary['original_owner_calls']
        result['compared']={name:equal_streams(output/'native'/name,output/'original'/name,True)
                            for name in ('requests.bin.gz','normalized.bin.gz','filesystem.bin.gz','events.jsonl.gz')}
        assert native_result['domains']==original_result['domains']
        assert native_result['outcomes']==original_result['outcomes']
        assert native_result['observed_file_bytes']==original_result['observed_file_bytes']==10528942
        result.update(original_summary=summary,domains=native_result['domains'],outcomes=native_result['outcomes'],
            file_bytes_per_side=10528942,native_result_sha256=sha((output/'native/result.json').read_bytes()),
            original_result_sha256=sha((output/'original/result.json').read_bytes()),status='PASS')
        assert sources=={name:sha(Path(name).read_bytes()) for name in sources}
        assert sha(native.read_bytes())==result['native_sha256'] and sha(original.read_bytes())==result['original_sha256']
    except BaseException as error:
        result.update(status='FAIL',failure=repr(error))
    result['elapsed_seconds']=time.monotonic()-started
    (output/'result.json').write_bytes(json_bytes(result))
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--native',type=Path,required=True)
    parser.add_argument('--original',type=Path,required=True)
    parser.add_argument('--reference',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();result=run(args.native,args.original,args.reference,args.output)
    print(json.dumps(result,sort_keys=True))
    if result['status']!='PASS':raise SystemExit(1)
