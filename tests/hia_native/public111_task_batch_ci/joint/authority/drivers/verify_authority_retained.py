"""Reconstruct retained authority suites from full source and process evidence."""
from pathlib import Path
import argparse
import base64
import gzip
import hashlib
import importlib.util
import json
import re
import sys

sys.dont_write_bytecode=True
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
def doc(path):return json.loads(path.read_bytes())
def load_reader(source):
    sys.path.insert(0,str(source/'scripts'))
    spec=importlib.util.spec_from_file_location('_selected_authority_reader_'+SHA(str(source).encode())[:12],source/'scripts/hia_native_authority_qualification.py')
    q=importlib.util.module_from_spec(spec);spec.loader.exec_module(q);return q

def verify(source,build,capture,*,historical=False):
    q=load_reader(source);built=doc(build/'BUILD.json');summary=doc(capture/'SUMMARY.json')
    assert built['status']=='PASS' and built['source_pins']==q.source_pins(source)==summary['source_pins']
    assert built['profile_sha256']==q.PROFILE_SHA
    paths={}
    for name,row in built['manifests'].items():
        rel=Path(row['path']);assert not rel.is_absolute() and '..' not in rel.parts
        path=build/rel;assert SHA(path.read_bytes())==row['sha256'];paths[name]=path
    artifact=q.composition_artifacts(source,build/'build',paths['authority'],q.object_at(paths['authority'])['compiler_sha256'])
    probe=q.probe_artifacts(source,build/'build',paths['probe'],artifact['compiler_image_sha256'])
    selected=q.SUITES[4:] if historical else q.SUITES[:4]
    assert len(summary['processes'])==len(selected)
    process_rows=[]
    for receipt,(name,_,report_file,tests,counts) in zip(summary['processes'],selected,strict=True):
        assert receipt['label']==name and receipt['exit_code']==0 and receipt['timed_out'] is False and receipt['timeout_seconds']==120
        assert receipt['command'][1:]==['-I','-B',str(Path(summary['suite_source_root'])/'tests/hia_native'/name)]
        logs={}
        for key in ('stdout','stderr'):
            raw=(capture/'processes'/(name+'.'+key)).read_bytes();logs[key]=raw
            assert receipt[key]==dict(bytes=len(raw),sha256=SHA(raw))
        result=doc(capture/report_file)
        assert result['tests_run']==tests and result['counts_match'] is True and result['counts']==counts
        assert json.loads(logs['stdout'])==result
        stderr=logs['stderr'].decode()
        assert len(re.findall(r'\.\.\. ok\n',stderr))==tests
        assert re.search(r'\nRan '+str(tests)+r' tests in [0-9.]+s\n\nOK\n\Z',stderr)
        process_rows.append(dict(name=name,tests=tests,stdout_sha256=SHA(logs['stdout']),stderr_sha256=SHA(logs['stderr'])))
    if historical:
        assert summary['status']=='HISTORICAL_SEVEN_GROUPS_PASS' and summary['new_owner_profile_qualified_by_this'] is False
        assert q.PROFILE_SHA=='927cb5e16d8c3fcb9f4d61dc00c4aa48ae09592fec8e28cb2ba3deb4b0950b92'
        expected=json.loads(gzip.decompress((source/'tests/hia_native/authority_receipt_fixture.json.gz').read_bytes()))
        fixture=capture/'retained-fixture'
        actual={path.relative_to(fixture).as_posix():path.read_bytes() for path in fixture.rglob('*') if path.is_file()}
        assert len(actual)==len(expected)==107 and actual=={key:base64.b64decode(value,validate=True) for key,value in expected.items()}
        controller=q.controller_evidence(source,fixture/'controller')
        kernel=q.kernel_evidence(source,fixture/'capture/native-kernel',probe['executable_sha256'])
        transport=q.transport_evidence(source,fixture/'capture/authority-transport',artifact['executable_sha256'],fixture/'controller')
        packed=q.packer_evidence(source,fixture/'packer.json',artifact)
        original=q.captured_original_evidence(source,fixture/'capture',fixture/'controller',artifact,probe)
        result=doc(capture/'evidence.json')
        q.suite_report(source,result,schema='hepta.runtime.authority-evidence.tests.v1',tests=7,counts=q.EVIDENCE_COUNTS,sources=q.EVIDENCE_SOURCES)
        assert result['manifest_sha256']==artifact['manifest_sha256'] and result['probe_manifest_sha256']==probe['manifest_sha256']
    else:
        assert summary['status']=='RETAINED_NATIVE_23_GROUPS_PASS' and summary['historical_v6_receipt_promoted'] is False
        assert q.PROFILE_SHA=='1bc46dd775110425c5350efa66cc1ccef3d393cd190a335e6717e013b369e367'
        controller=q.controller_evidence(source,capture/'controller')
        q.direct_loaded_evidence(source,controller['loaded_artifacts'],authority=doc(paths['authority']),scope=doc(paths['scope']),scope_sha256=SHA(paths['scope'].read_bytes()))
        assert doc(capture/'controller.json')==doc(capture/'controller/native-corpus.json')['native_report']
        kernel=q.kernel_evidence(source,capture/'kernel',probe['executable_sha256'])
        transport=q.transport_evidence(source,capture/'transport',artifact['executable_sha256'],capture/'controller')
        packed=q.packer_evidence(source,capture/'packer.json',artifact);original=None
    return dict(schema='hepta.public-authority.retained-readonly.v1',status='PASS',historical=historical,
        test_groups=7 if historical else 23,source_pins=summary['source_pins'],profile_sha256=q.PROFILE_SHA,
        build=artifact,probe=probe,controller=controller,kernel=kernel,transport=transport,packer=packed,
        historical_original=original,processes=process_rows,new_original_rust_calls=0,
        old_original_reference_remains_historical=True,reader_wrote_files=False,reader_executed_native_or_rust=False,
        full_sdk_qualified=False,production_activated=False,old_path_removed=False)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('source','build','capture'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--historical',action='store_true');a=p.parse_args()
    print(json.dumps(verify(a.source.resolve(strict=True),a.build.resolve(strict=True),a.capture.resolve(strict=True),historical=a.historical),sort_keys=True))
