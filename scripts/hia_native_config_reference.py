"""Prepare the four exact original configuration references; never execute Rust.

The test-only archive contains the already observed wrappers and original
function bodies. Every extracted byte, 54 original blocks and the complete
100-package registry closure are checked before a reference is admitted.
"""
from pathlib import Path
import hashlib,io,json,tarfile,tomllib

sha=lambda raw:hashlib.sha256(raw).hexdigest()

def check_project(project,metadata):
    for name,want in metadata['files'].items():
        path=project/name
        if path.is_symlink() or not path.is_file():raise ValueError('missing regular reference input: '+name)
        raw=path.read_bytes()
        if (len(raw),sha(raw))!=(want['bytes'],want['sha256']):raise ValueError('reference input changed: '+name)

def prepare_original_reference(repo,output):
    repo=Path(repo).resolve(strict=True);output=Path(output)
    folder=repo/'tests/hia_native';metadata_path=folder/'config_reference_sources.json'
    metadata=json.loads(metadata_path.read_bytes());archive=folder/metadata['archive'];raw=archive.read_bytes()
    if metadata['schema']!='hepta.runtime.config-original-template.v1' or (len(raw),sha(raw))!=(metadata['archive_bytes'],metadata['archive_sha256']):raise ValueError('reference archive changed')
    sources={}
    for name,want in metadata['original_sources'].items():
        path=repo/name
        if path.is_symlink() or not path.is_file():raise ValueError('original source is not regular: '+name)
        data=path.read_bytes();blob=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
        if (len(data),sha(data),blob)!=(want['bytes'],want['sha256'],want['git_blob']):raise ValueError('original source changed: '+name)
        sources[name]=data
    entries={}
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as stream:
        for item in stream:
            if not item.isfile() or item.name not in metadata['files'] or item.name in entries:raise ValueError('unknown or duplicate reference archive entry')
            data=stream.extractfile(item).read();want=metadata['files'][item.name]
            if (len(data),sha(data))!=(want['bytes'],want['sha256']):raise ValueError('reference template changed: '+item.name)
            entries[item.name]=data
    if set(entries)!=set(metadata['files']):raise ValueError('incomplete reference archive')
    if len(metadata['source_blocks'])!=54:raise ValueError('original function domain changed')
    for block in metadata['source_blocks']:
        raw=sources[block['source']][block['offset']:block['offset']+block['bytes']]
        if sha(raw)!=block['sha256'] or not block['targets']:raise ValueError('original function slice changed')
        for target in block['targets']:
            if entries[target['path']][target['offset']:target['offset']+len(raw)]!=raw:raise ValueError('reference function body differs: '+block['label'])
    if entries['original-runtime.lock']!=sources['Cargo.lock']:raise ValueError('original registry lock differs')
    original={(p['name'],p['version']):p for p in tomllib.loads(entries['original-runtime.lock'].decode())['package'] if 'checksum' in p}
    packages=[]
    for package in tomllib.loads(entries['Cargo.lock'].decode())['package']:
        if 'checksum' not in package:continue
        expected=original[(package['name'],package['version'])]
        if any(package[k]!=expected[k] for k in ['source','checksum']):raise ValueError('original dependency differs')
        packages.append({k:package[k] for k in ['name','version','source','checksum']})
    if len(packages)!=metadata['registry_packages'] or len(packages)!=100:raise ValueError('original dependency closure changed')
    output.mkdir(parents=True,exist_ok=False,mode=0o700)
    for name,data in entries.items():
        path=output/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
    receipt={'schema':'hepta.runtime.config-reference-preparation.v1','archive_sha256':metadata['archive_sha256'],
             'metadata_sha256':sha(metadata_path.read_bytes()),'files':metadata['files'],
             'original_sources':metadata['original_sources'],'packages':packages,'source_block_count':54,
             'executables':metadata['executables'],'shared_build':True}
    (output/'reference-inputs.json').write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n')
    check_project(output,receipt)
    return receipt

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--repo',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);a=parser.parse_args()
    result=prepare_original_reference(a.repo,a.output)
    print(json.dumps({'project':str(a.output.resolve()),'files':len(result['files']),'source_blocks':result['source_block_count'],'registry_packages':len(result['packages'])},sort_keys=True))
