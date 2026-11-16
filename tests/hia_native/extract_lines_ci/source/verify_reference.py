"""Read every whole target source and exact included production item."""
from pathlib import Path
import hashlib
import json
import tomllib

ROOT = Path(__file__).resolve().parent
TARGET = 'd3d75c30719db966b004756f610007a7c723729e'
TREE = '612e145513961556ac8844b5cc978f9b5175e4d4'


def identity(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                git_blob=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest())


def verify(root=ROOT):
    root = Path(root)
    reference = root / 'reference'
    manifest = json.loads((root / 'reference-source.json').read_bytes())
    metadata_raw = (reference / 'TARGET.json').read_bytes()
    assert hashlib.sha256(metadata_raw).hexdigest() == '38a2a860af8add7a1abc5fb14ac461b0060eb478e89e9e25d5f9ad309a8a2d4d'
    metadata = json.loads(metadata_raw)
    assert manifest['schema']=='hepta.runtime.extract-lines-original-extraction.v1'
    assert (manifest['target_commit'],manifest['target_tree'])==(TARGET,TREE)
    assert manifest['target_metadata']==identity(metadata_raw)
    assert manifest['source_files']==metadata['files'] and len(metadata['files'])==12
    targets={}
    for name,pin in metadata['files'].items():
        raw=(reference/'target'/name).read_bytes(); assert identity(raw)==pin, name
        targets[name]=raw
    assert len(metadata['excerpts'])==8
    for name,row in metadata['excerpts'].items():
        raw=(reference/'excerpts'/name).read_bytes()
        assert raw==targets[row['source']][row['start']:row['end']]
        assert identity(raw)=={k:row[k] for k in ('bytes','sha256','git_blob')}
    count=0
    for unit in manifest['units']:
        raw=(reference/unit['path']).read_bytes()
        assert identity(raw)=={k:unit[k] for k in ('bytes','sha256','git_blob')}
        previous=0
        for item in unit['items']:
            original=targets[item['target']][item['start']:item['end']]
            included=raw[item['included_start']:item['included_end']]
            assert item['included_start']>=previous and original==included
            assert original.startswith(item['declaration'].encode())
            assert identity(original)=={k:item[k] for k in ('bytes','sha256','git_blob')}
            previous=item['included_end'];count+=1
    assert count==manifest['exact_original_items']==88
    for name,pin in manifest['fixture_files'].items():
        assert identity((reference/name).read_bytes())==pin,name
    for name,pin in manifest['cargo'].items():
        assert identity((reference/name).read_bytes())==pin,name
    assert (reference/'src/main.rs').read_bytes()==(root/'reference_main.rs').read_bytes()
    main=(root/'reference_main.rs').read_bytes()
    assert main.count(b'mcp::fs::core::execute_extract_lines(call).await')==1
    assert main.count(b'with_request_context(cache.clone(), body)')==1
    cargo=tomllib.loads((reference/'Cargo.toml').read_text())
    assert cargo['package']==dict(name='hepta-extract-lines-original-oracle',version='0.1.0',edition='2021',**{'rust-version':'1.95'})
    assert cargo['dependencies']=={'anyhow':'=1.0.104','serde':{'version':'=1.0.229','features':['derive']},
        'serde_json':{'version':'=1.0.151','features':['float_roundtrip','raw_value']},
        'tokio':{'version':'=1.53.3','features':['rt','fs','io-util','sync']}}
    target={(p['name'],p['version'],p.get('source')):p.get('checksum')
            for p in tomllib.loads(targets['Cargo.lock'].decode())['package']}
    packages=tomllib.loads((reference/'Cargo.lock').read_text())['package']
    assert len(packages)==16
    registry=[]
    for p in packages:
        if p.get('source'):
            assert target.get((p['name'],p['version'],p['source']))==p['checksum']
            registry.append({k:p[k] for k in ('name','version','source','checksum')})
        else: assert p['name']==cargo['package']['name']
    return dict(status='EXACT_EXTRACT_REFERENCE_SOURCE_PASS',target_commit=TARGET,target_tree=TREE,
                exact_original_items=count,target_files=len(targets),registry=registry,
                public_handler_qualified=False)


if __name__=='__main__': print(json.dumps(verify(),sort_keys=True))
