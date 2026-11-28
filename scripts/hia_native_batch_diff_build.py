"""Build the HIA post-write batch diff owner; Python is only a build driver."""
from pathlib import Path
import argparse
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts'))
from hia_native_build import NativeBuild, json_bytes, write_new


def build_batch_diff(hepta, build_root, *, source_root=ROOT):
    build = NativeBuild(hepta, build_root)
    members={}
    for key,name in [('diff','batch_diff'),('apply','batch_apply'),('editable','editable_content')]:
        path=build.compile('batch-diff-'+key,Path(source_root)/'native'/f'{name}.hepta',
                           standalone=None,buffer_profile='batch-plan.v1')
        raw=path.read_bytes();metadata=json.loads(raw)
        members[key]={'manifest':str(path.relative_to(build.root)),
                      'manifest_sha256':hashlib.sha256(raw).hexdigest(),
                      'source':'native/'+name+'.hepta','source_sha256':metadata['source_sha256'],
                      'image_sha256':metadata['image_sha256']}
    result=build.root/'batch-diff.json'
    write_new(result,json_bytes({'schema':'hepta.runtime.batch-diff-build.v1','members':members,
                                'public_batch_route_replaced':False,'filesystem_effects_replaced':False}))
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--hepta', type=Path, required=True)
    parser.add_argument('--build', type=Path, required=True)
    args = parser.parse_args()
    print(build_batch_diff(args.hepta, args.build))

