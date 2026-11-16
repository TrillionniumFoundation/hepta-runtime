"""Reproduce the author, then actually compile the three exact HIA owners."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
sys.dont_write_bytecode = True
sys.path.insert(0,str(Path(__file__).resolve().parent))
import author_catalog_policy
import read_catalog

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--source',type=Path,default=Path(__file__).resolve().parent)
    p.add_argument('--hepta',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--bootstrap',type=Path)
    a=p.parse_args();source=a.source.resolve(strict=True);output=a.output.absolute()
    read_catalog.source_check(source)
    if a.bootstrap is None and os.environ.get('GITHUB_ACTIONS')!='true':
        raise ValueError('local builds require an existing qualified bootstrap copy')
    output.mkdir(parents=True,exist_ok=False)
    proof=author_catalog_policy.generate(a.hepta,source,output/'generated')
    assert (output/'generated/catalog_policy.hepta').read_bytes()==(source/'native/catalog_policy.hepta').read_bytes()
    assert (output/'generated/author-proof.json').read_bytes()==(source/'native/author-proof.json').read_bytes()
    if a.bootstrap is not None:
        shared=a.bootstrap.resolve(strict=True)
        # Only fixed bootstrap-owned files are copied; no directory traversal.
        admitted=('bootstrap.json','B1.image.bin','B2.image.bin','B3.image.bin')
        (output/'bootstrap').mkdir()
        shared_reader=read_catalog.Reader(shared)
        for name in admitted:(output/'bootstrap'/name).write_bytes(shared_reader.raw(name))
    sys.path.insert(0,str(source/'runtime_support/scripts'))
    from hia_native_build import NativeBuild
    builder=NativeBuild(a.hepta,output)
    modules={}
    for name,(relative,pin,profile) in read_catalog.SOURCE_PINS.items():
        assert hashlib.sha256((source/relative).read_bytes()).hexdigest()==pin
        path=builder.compile(name,source/relative,standalone=None,buffer_profile=profile)
        modules[name]={'path':path.relative_to(output).as_posix(),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
    read_catalog.build_check(output,source)
    result={'schema':'hepta.runtime.catalog-policy-build.v2','status':'PASS','producer_root':str(output),
        'modules':modules,'author_source_sha256':proof['source_sha256'],'fresh_native_compilations':3,
        'copied_qualified_bootstrap':a.bootstrap is not None,'fresh_original_build':False,'whole_runtime_replaced':False}
    (output/'catalog-build.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    print(json.dumps(result,sort_keys=True))

if __name__=='__main__':main()
