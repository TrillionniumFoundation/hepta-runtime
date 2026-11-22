#!/usr/bin/env python3
"""Relocate exact private input bytes with separately identified request records."""
import argparse
import hashlib
import json
from pathlib import Path
import tarfile


def digest(data):
    return hashlib.sha256(data).hexdigest()


def save(path,value):
    with open(path,'x') as stream:
        json.dump(value,stream,ensure_ascii=False,indent=2)
        stream.write('\n')


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--manifest',required=True)
    parser.add_argument('--manifest-sha',required=True)
    parser.add_argument('--remote-prefix',required=True)
    parser.add_argument('--output',required=True)
    args=parser.parse_args()
    source=Path(args.manifest).resolve();raw=source.read_bytes()
    assert digest(raw)==args.manifest_sha
    manifest=json.loads(raw)
    output=Path(args.output).resolve();output.mkdir(mode=0o700)
    remote=Path(args.remote_prefix)
    assert remote.is_absolute() and '..' not in remote.parts
    files=output/'files';files.mkdir(mode=0o700)
    requests=output/'requests';requests.mkdir(mode=0o700)
    mapping=[];retained={};rows=[]
    def copy_pin(pin):
        data=Path(pin['path']).read_bytes()
        assert len(data)==pin['bytes'] and digest(data)==pin['sha256']
        name=pin['sha256']+'--'+Path(pin['path']).name
        if name not in retained:
            (files/name).write_bytes(data)
            retained[name]=True
        target=str(remote/'files'/name)
        mapping.append({'original_path':pin['path'],'sha256':pin['sha256'],'bytes':len(data),'remote_path':target,'relative_path':'files/'+name})
        return {'path':target,'bytes':len(data),'sha256':pin['sha256']}
    for case in manifest['cases']:
        request_raw=Path(case['request']['path']).read_bytes()
        assert digest(request_raw)==case['request']['sha256']
        request=json.loads(request_raw)
        for field in ['source_bridge','source_gzip','semantic_contract','program']:
            request[field]=copy_pin(request[field])
        name=f'fit_{case["fit"]}_{case["label"]}.json'
        path=requests/name;save(path,request)
        data=path.read_bytes()
        row={'fit':case['fit'],'label':case['label'],'request':{'path':str(remote/'requests'/name),'bytes':len(data),'sha256':digest(data)},
             'origin_request':case['request']}
        for key in ['old_graph','expected_primary','expected_keep']:row[key]=copy_pin(case[key])
        rows.append(row)
    relocated=dict(manifest,cases=rows,relocation={'original_manifest':{'path':str(source),'sha256':digest(raw),'bytes':len(raw)},
                  'remote_prefix':str(remote),'scientific_input_bytes_changed':False,'request_paths_changed':True,
                  'qualification_transfer_claimed':False})
    save(output/'INPUTS.json',relocated)
    save(output/'PATH_MAP.json',{'schema':'hepta.lifecycle-input-relocation.v1','files':mapping})
    with tarfile.open(output.with_suffix('.tar.gz'),'w:gz') as archive:
        for path in sorted(output.rglob('*')):
            if path.is_file():archive.add(path,arcname=str(path.relative_to(output)),recursive=False)
    print(json.dumps({'output':str(output),'archive':str(output.with_suffix('.tar.gz')),'files':len(retained),
                     'input_manifest_sha256':digest((output/'INPUTS.json').read_bytes()),
                     'archive_sha256':digest(output.with_suffix('.tar.gz').read_bytes())}))


if __name__=='__main__':main()
