"""Join three verified byte ranges of an existing artifact; execute no capture code."""
from pathlib import Path
import hashlib, json, stat, zipfile

ROOT=Path('/dev/shm/hia-public111-build-parts-review-6780-v1')
IDS=[14284082411,14283743608,14283863426]
EXPECTED={'bytes':741930469,'sha256':'deecbd7eba816a7c59f2bb749664b132de4db14176e1814c65ef3d62c26d6b15'}
OUTPUT=ROOT/'original-build-artifact.zip'

def main():
    whole=hashlib.sha256();position=0;parts_expected=None;original_expected=None;observed=[]
    with OUTPUT.open('xb') as sink:
        for index,ident in enumerate(IDS):
            path=ROOT/(str(ident)+'.zip')
            declared=json.loads((ROOT/(str(ident)+'-outer.json')).read_bytes())
            h=hashlib.sha256();n=0
            with path.open('rb') as f:
                while b:=f.read(1<<20):h.update(b);n+=len(b)
            assert {'bytes':n,'sha256':h.hexdigest()}=={k:declared[k] for k in ('bytes','sha256')}
            assert declared['id']==ident and declared['name']=='public111-build-complete-part-'+str(index)
            with zipfile.ZipFile(path) as z:
                assert len(z.infolist())==3 and set(z.namelist())=={'part.bin','parts.json','original-artifact.json'}
                for item in z.infolist():
                    assert not item.is_dir() and not stat.S_ISLNK(item.external_attr>>16)
                parts_raw=z.read('parts.json');original_raw=z.read('original-artifact.json')
                parts=json.loads(parts_raw);original=json.loads(original_raw)
                if index==0:parts_expected=parts_raw;original_expected=original_raw
                assert parts_raw==parts_expected and original_raw==original_expected
                assert parts['schema']=='hepta.complete-original-artifact-zip-parts.v1'
                assert parts['original_artifact']==14282953118 and parts['original_run']==43979626193
                assert parts['original_head']=='d397daea2c098746b47e88efa0cb566c6ef71103'
                assert parts['original_job']==133692433112 and parts['original_zip']==EXPECTED
                assert parts['semantic_executions']==0 and parts['source_or_evidence_modified'] is False
                assert len(parts['parts'])==3 and parts['original_failure_reclassified_as_pass'] is False
                assert original['id']==14282953118 and original['size_in_bytes']==EXPECTED['bytes']
                assert original['digest']=='sha256:'+EXPECTED['sha256']
                assert original['workflow_run']['id']==43979626193
                assert original['workflow_run']['head_sha']==parts['original_head']
                row=parts['parts'][index];assert row['index']==index and row['offset']==position
                h=hashlib.sha256();n=0
                with z.open('part.bin') as f:
                    while b:=f.read(1<<20):sink.write(b);h.update(b);whole.update(b);position+=len(b);n+=len(b)
                assert n==row['bytes'] and h.hexdigest()==row['sha256']
                assert z.testzip() is None
                observed.append({'outer':declared,'range':row})
    assert {'bytes':position,'sha256':whole.hexdigest()}==EXPECTED
    with OUTPUT.open('rb') as f:assert f.read(4)==b'PK\x03\x04'
    report={'schema':'hepta.public111.complete-build-zip-reassembly.v1','status':'PASS',
            'source_run':43979626193,'export_run':43984231360,'original_artifact':14282953118,
            'whole_original_zip':EXPECTED,'parts':observed,'semantic_executions':0,
            'source_or_evidence_modified':False,'qualification_inferred_from_export':False}
    with (ROOT/'REASSEMBLY.json').open('x') as f:json.dump(report,f,indent=2,sort_keys=True);f.write('\n')
    print(json.dumps(report),flush=True)
if __name__=='__main__':main()
