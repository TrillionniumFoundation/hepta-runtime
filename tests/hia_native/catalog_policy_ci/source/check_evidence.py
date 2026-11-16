"""Relocation and rehashed-record refusals using independent exact file copies."""
from __future__ import annotations
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
import read_catalog as q

def save(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')

def run(source,build,native,controls,original,output):
    output.mkdir(parents=True,exist_ok=False)
    baseline=q.verify(source,build,native,original)
    control=q.controls_check(source,controls)
    rows=[]
    with tempfile.TemporaryDirectory(prefix='owned-snapshot-',dir=output) as temp:
        root=Path(temp)
        for name,origin,files in (('source',source,baseline['source_files']),('build',build,baseline['build_files']),('native',native,baseline['native_files']),('controls',controls,control['files'])):
            reader=q.Reader(origin)
            for relative,pin in files.items():
                target=root/name/relative;target.parent.mkdir(parents=True,exist_ok=True)
                target.write_bytes(reader.raw(relative,pin))
        def admit():
            q.verify(root/'source',root/'build',root/'native',original,verify_original=False)
            q.controls_check(root/'source',root/'controls')
        admit()
        def mutation(label,paths,edit):
            before={name:(root/name).read_bytes() for name in paths}
            folder=output/label;folder.mkdir()
            for index,(name,raw) in enumerate(before.items()):(folder/f'before-{index}.gz').write_bytes(gzip.compress(raw,mtime=0))
            aliases=[]
            try:
                edit(root,aliases)
                after=[]
                for index,name in enumerate(paths):
                    p=root/name;info=p.lstat()
                    if stat.S_ISREG(info.st_mode):
                        raw=p.read_bytes();(folder/f'after-{index}.gz').write_bytes(gzip.compress(raw,mtime=0));after.append({'path':name,'type':'regular','bytes':len(raw),'sha256':q.sha(raw),'nlink':info.st_nlink})
                    elif stat.S_ISLNK(info.st_mode):after.append({'path':name,'type':'symlink','target':os.readlink(p)})
                    else:after.append({'path':name,'type':'special','mode':info.st_mode})
                try:admit()
                except (ValueError,AssertionError,KeyError,RuntimeError,OSError) as error:
                    row={'label':label,'status':'REFUSED','error_type':type(error).__name__,'message':str(error),'paths':paths,'after':after}
                    save(folder/'refusal.json',row);rows.append(row)
                else:raise AssertionError('reader accepted mutation: '+label)
            finally:
                for path in aliases:path.unlink(missing_ok=True)
                for name,raw in before.items():
                    p=root/name;p.unlink(missing_ok=True);p.write_bytes(raw)
                    assert p.stat().st_nlink==1 and p.read_bytes()==raw
        def edit_json(path,fn):
            def edit(root,aliases):
                p=root/path;value=json.loads(p.read_bytes());fn(value);save(p,value)
            return edit
        mutation('missing-schema-row',['native/result.json'],edit_json('native/result.json',lambda v:v['rows'].pop(0)))
        mutation('wrong-native-call-count',['native/result.json'],edit_json('native/result.json',lambda v:v.__setitem__('native_calls',499)))
        mutation('missing-distinct-shape',['native/result.json'],edit_json('native/result.json',lambda v:v['shapes'].pop()))
        mutation('wrong-cursor-attribution',['native/result.json'],edit_json('native/result.json',lambda v:v['rows'][136].__setitem__('cursor_case',2)))
        mutation('source-byte-change',['source/catalog_policy.pseudo'],lambda root,aliases:(root/'source/catalog_policy.pseudo').write_bytes(b'#changed\n'+(root/'source/catalog_policy.pseudo').read_bytes()))
        mutation('forged-profile',['source/source-profile.json'],edit_json('source/source-profile.json',lambda v:v['files'].pop('qualify_catalog_policy.py')))
        def change_work(root,aliases):
            p=root/'native/schema-000-call-0.workspace.gz';raw=bytearray(gzip.decompress(p.read_bytes()));raw[0]^=1;p.write_bytes(gzip.compress(raw,mtime=0))
            r=root/'native/result.json';v=json.loads(r.read_bytes());v['rows'][0]['calls'][0]['workspace_sha256']=q.sha(raw);save(r,v)
        mutation('rehashed-node-count',['native/schema-000-call-0.workspace.gz','native/result.json'],change_work)
        def change_input(root,aliases):
            p=root/'native/schema-000-call-0.input.gz';raw=bytearray(gzip.decompress(p.read_bytes()));raw[16]=1;p.write_bytes(gzip.compress(raw,mtime=0))
            r=root/'native/result.json';v=json.loads(r.read_bytes());v['rows'][0]['calls'][0]['input_sha256']=q.sha(raw);save(r,v)
        mutation('rehashed-request',['native/schema-000-call-0.input.gz','native/result.json'],change_input)
        def change_sdk(root,aliases):
            p=root/'native/shape-00-sdk.output.gz';raw=bytearray(gzip.decompress(p.read_bytes()));raw[8]=5;p.write_bytes(gzip.compress(raw,mtime=0))
            r=root/'native/result.json';v=json.loads(r.read_bytes());v['shapes'][0]['sdk']['output_sha256']=q.sha(raw);save(r,v)
        mutation('rehashed-sdk-kind',['native/shape-00-sdk.output.gz','native/result.json'],change_sdk)
        def change_expected(root,aliases):
            p=root/'native/catalog-disabled-00.expected.gz';raw=gzip.decompress(p.read_bytes())+b' ';p.write_bytes(gzip.compress(raw,mtime=0))
        mutation('whole-wire-extra-byte',['native/catalog-disabled-00.expected.gz'],change_expected)
        def change_compiler(root,aliases):
            base=root/'build/modules/catalog-policy';p=base/'module.output.bin';raw=bytearray(p.read_bytes());raw[-1]^=1;p.write_bytes(raw)
            r=json.loads((base/'module.receipt.json').read_bytes());r['output_sha256']=q.sha(raw);save(base/'module.receipt.json',r)
            b=json.loads((base/'build.json').read_bytes());b['compile_receipt']=r;save(base/'build.json',b)
        mutation('rehashed-compiler-tail',['build/modules/catalog-policy/module.output.bin','build/modules/catalog-policy/module.receipt.json','build/modules/catalog-policy/build.json'],change_compiler)
        def symlink(root,aliases):
            p=root/'source/catalog_policy.pseudo';p.unlink();p.symlink_to('declarations.json')
        mutation('admitted-symlink',['source/catalog_policy.pseudo'],symlink)
        def hardlink(root,aliases):
            p=root/'source/catalog_policy.pseudo';other=root/'owned-hardlink';os.link(p,other);aliases.append(other)
        mutation('admitted-hardlink',['source/catalog_policy.pseudo'],hardlink)
        def fifo(root,aliases):
            p=root/'source/catalog_policy.pseudo';p.unlink();os.mkfifo(p)
        mutation('admitted-fifo',['source/catalog_policy.pseudo'],fifo)
        admit()
    assert len(rows)==14
    result={'schema':'hepta.runtime.catalog-policy-evidence-controls.v1','status':'PASS','actual_native_launches':0,
        'actual_rust_launches':0,'admissions':3,'refusals':14,'records':rows,'independent_file_copies':True,
        'all_owned_snapshot_fixtures_retired':True,'complete_source_and_mutation_bytes_retained':True}
    save(output/'result.json',result);return result

def main():
    p=argparse.ArgumentParser()
    for name in ('source','build','native','controls','original','output'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args()
    try:r=run(a.source,a.build,a.native,a.controls,a.original,a.output)
    except BaseException as e:
        if a.output.is_dir():save(a.output/'failure.json',{'type':type(e).__name__,'message':str(e)})
        raise
    print(json.dumps({k:v for k,v in r.items() if k!='records'},sort_keys=True))

if __name__=='__main__':main()
