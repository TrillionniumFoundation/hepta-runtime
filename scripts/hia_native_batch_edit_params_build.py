"""Compile the HIA-only, image-only BatchEditParams projection owner."""
from pathlib import Path
import argparse
import hashlib
import json
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from hia_native_build import NativeBuild,json_bytes,write_new


def build_batch_edit_params(hepta, build_root, *, source_root=ROOT):
    build=NativeBuild(hepta,build_root)
    members={}
    for name,source in [('projection','batch_edit_params'),('value','serde_json_span')]:
        path=build.compile('batch-edit-'+name,Path(source_root)/'native'/f'{source}.hepta',
                           standalone=None,buffer_profile='history.v1')
        metadata=json.loads(path.read_bytes())
        members[name]={'manifest':str(path.relative_to(build.root)),
                       'manifest_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
                       'source':f'native/{source}.hepta','source_sha256':metadata['source_sha256'],
                       'image_sha256':metadata['image_sha256']}
    path=build.root/'batch-edit-params.json'
    write_new(path,json_bytes({'schema':'hepta.runtime.batch-edit-params-build.v1','members':members,
                              'compiler_commit':metadata['compiler_commit'],
                              'compiler_sha256':metadata['compiler_sha256'],
                              'public_route_replaced':False,'whole_runtime_replaced':False}))
    return path


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--hepta',type=Path,required=True)
    parser.add_argument('--build',type=Path,required=True)
    args=parser.parse_args();print(build_batch_edit_params(args.hepta,args.build))
