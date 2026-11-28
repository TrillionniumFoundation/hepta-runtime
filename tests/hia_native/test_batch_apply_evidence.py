"""Physical receipt/image corruption controls; adds no native or Rust calls."""
from __future__ import annotations
import argparse
import copy
import gzip
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time

ROOT=Path(__file__).resolve().parents[2]
REFERENCE=Path(os.environ.get('HIA_RUNTIME_REPO',ROOT))
sys.path.insert(0,str(ROOT/'scripts'))
import hia_native_batch_apply_qualification as q
from hia_native_batch_apply_build import inspect_bundle,module_identity,read,sha,IMAGES

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle',type=Path,default=os.environ.get('HIA_APPLY_BUNDLE'))
    parser.add_argument('--corpus',type=Path,default=os.environ.get('HIA_APPLY_CORPUS_DIR'))
    parser.add_argument('--contract',type=Path,required=True)
    parser.add_argument('--artifacts',type=Path,required=True)
    parser.add_argument('--result',type=Path,required=True)
    args=parser.parse_args();assert args.bundle and args.corpus
    started=time.monotonic();accepted=q.evidence(args.corpus,args.contract,args.artifacts,args.bundle,reference_root=REFERENCE)
    bundle=inspect_bundle(args.bundle,reference_root=REFERENCE);closure=accepted['source_contract'];pins=accepted['source_pins']
    refusals=[]
    def refused(name,callback):
        try:callback()
        except (ValueError,AssertionError,KeyError,TypeError,EOFError,gzip.BadGzipFile):refusals.append(name)
        else:raise AssertionError('corrupt evidence accepted: '+name)
    with tempfile.TemporaryDirectory(prefix='batch-apply-evidence-') as temporary:
        root=Path(temporary);corpus=root/'corpus';shutil.copytree(args.corpus,corpus)
        path=corpus/'native-corpus.json';original=path.read_bytes();base=json.loads(original)
        changes=[('false_status',lambda v:v.__setitem__('status','PENDING')),
            ('partial_domain',lambda v:v.__setitem__('development_small',True)),
            ('wrong_source',lambda v:v.__setitem__('source_sha256','0'*64)),
            ('wrong_loaded_image',lambda v:v['loaded_artifacts'][1].__setitem__('image_sha256','0'*64)),
            ('omitted_reference',lambda v:v['rows'].pop()),
            ('omitted_refusal',lambda v:v['controls'].pop()),
            ('changed_control_code',lambda v:v['controls'][0].__setitem__('code',0)),
            ('unrecorded_call',lambda v:v['rows'][0].__setitem__('controller_calls',1)),
            ('missing_guard',lambda v:v['rows'][0].__setitem__('guards_unchanged',False)),
            ('missing_clear',lambda v:v['rows'][0].__setitem__('cleared_prefix_bytes',0)),
            ('wrong_source_closure',lambda v:v['execution_source_pins']['owner'].pop('scripts/hia_native_loader.py'))]
        for name,change in changes:
            value=copy.deepcopy(base);change(value);path.write_text(json.dumps(value))
            refused(name,lambda:q.corpus_evidence(corpus,bundle,closure,pins))
        path.write_bytes(original)
        requests=corpus/'requests.bin.gz';requests_before=requests.read_bytes()
        with gzip.open(requests,'rb') as source,gzip.open(root/'changed.gz','wb') as target:
            first=bytearray(source.read(160));first[-1]^=1;target.write(first);shutil.copyfileobj(source,target,1<<20)
        requests.write_bytes((root/'changed.gz').read_bytes())
        value=copy.deepcopy(base);value['corpus_files']['requests.bin.gz']=q.file_record(requests);path.write_text(json.dumps(value))
        refused('actual_gzip_changed_rehashed',lambda:q.corpus_evidence(corpus,bundle,closure,pins))
        requests.write_bytes(requests_before);path.write_bytes(original)
        contract=root/'contract.json';contract.write_bytes(args.contract.read_bytes());base_contract=json.loads(contract.read_bytes())
        for name,change in [('missing_contract_fault',lambda v:v['rows'].pop()),
            ('fault_never_installed',lambda v:v['rows'][0].__setitem__('fault_applied',[])),
            ('contract_private_not_erased',lambda v:v['rows'][0].__setitem__('cleared_prefix_bytes',0))]:
            value=copy.deepcopy(base_contract);change(value);contract.write_text(json.dumps(value))
            refused(name,lambda:q.contract_evidence(contract,bundle,closure,pins))
        artifacts=root/'artifacts';shutil.copytree(args.artifacts,artifacts)
        value=json.loads((artifacts/'result.json').read_bytes());value['joined_cases'][0]['apply_output_sha256']='0'*64
        (artifacts/'result.json').write_text(json.dumps(value))
        corpus_proof=q.corpus_evidence(args.corpus,bundle,closure,pins)
        refused('joined_wrong_original_result',lambda:q.artifact_evidence(artifacts,bundle,closure,pins,corpus_proof))
        # Change real executable image bytes and consistently rehash the copied
        # manifest; the fixed source/image table must still refuse admission.
        module_root=root/'module';module_root.mkdir();module_path=bundle['manifests'][4]
        metadata=json.loads(read(module_path))
        for field in ('source','image'):shutil.copyfile(module_path.parent/metadata[field],module_root/metadata[field])
        image=bytearray((module_root/metadata['image']).read_bytes());image[-1]^=1
        (module_root/metadata['image']).write_bytes(image);metadata['image_sha256']=sha(image)
        modified=module_root/'manifest.json';modified.write_text(json.dumps(metadata))
        refused('actual_image_consistently_rehashed',lambda:module_identity(modified,read(ROOT/'native/batch_apply.hepta'),wide=True,image_sha=IMAGES[4]))
    assert len(refusals)==17
    result={'schema':'hepta.runtime.batch-apply-evidence-controls.v1','status':'PASS',
        'accepted_complete_receipts':1,'rejected_corruptions':len(refusals),'refusals':refusals,
        'native_calls_added':0,'rust_calls_added':0,'elapsed_seconds':time.monotonic()-started,
        'native_evidence_sha256':sha(q.canonical(accepted)),'execution_source_pins':q.execution_source_pins(reference=REFERENCE)}
    args.result.write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k!='execution_source_pins'},sort_keys=True))

if __name__=='__main__':main()
