"""Freshly compile the seven native owners of the batch Planner input path."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import signal
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from hia_native_build import NativeBuild,json_bytes,write_new

MEMBERS=(('input','batch_plan_input','batch-plan.v1'),('value','serde_json_span','history.v1'),
         ('params','batch_edit_params','history.v1'),('editable','editable_content','batch-plan.v1'),
         ('plan','batch_plan','batch-plan.v1'),('endpoint','line_endpoint','batch-plan.v1'),('verify','line_verify','batch-plan.v1'))

def _compile(hepta,build_root,*,source_root=ROOT):
    build=NativeBuild(hepta,build_root);members={}
    for name,owner,profile in MEMBERS:
        path=build.compile('batch-plan-input-'+name,Path(source_root)/'native'/(owner+'.hepta'),standalone=None,buffer_profile=profile)
        metadata=json.loads(path.read_bytes())
        members[name]={'manifest':str(path.resolve()),'manifest_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
                       'source':owner,'source_sha256':metadata['source_sha256'],'image_sha256':metadata['image_sha256']}
    path=build.root/'members.json'
    write_new(path,json_bytes({'schema':'hepta.runtime.batch-plan-input-build.v1','members':members,
        'compiler_commit':metadata['compiler_commit'],'compiler_sha256':metadata['compiler_sha256'],
        'fresh_images':7,'fresh_cold':False,'public_route_replaced':False}))
    return path

def build_batch_plan_input(hepta,build_root,*,source_root=ROOT):
    source_root=Path(source_root).resolve();build_root=Path(build_root).resolve();hepta=Path(hepta).resolve()
    parent=build_root.parent;parent.mkdir(parents=True,exist_ok=True)
    command=[sys.executable,'-I','-B',str(source_root/'scripts/hia_native_batch_plan_input_build.py'),
             '--worker','--hepta',str(hepta),'--build',str(build_root),'--source',str(source_root)]
    began=time.monotonic();timed=False
    with (parent/'compile.stdout').open('xb')as stdout,(parent/'compile.stderr').open('xb')as stderr:
        child=subprocess.Popen(command,cwd=source_root,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,start_new_session=True)
        try:code=child.wait(timeout=180)
        except subprocess.TimeoutExpired:timed=True;os.killpg(child.pid,signal.SIGKILL);code=child.wait(timeout=3)
    record={'name':'compile','command':command,'cwd':str(source_root),'pid':child.pid,'exit_code':code,'timed_out':timed,
            'timeout_seconds':180,'elapsed_seconds':time.monotonic()-began}
    for kind in ('stdout','stderr'):
        raw=(parent/('compile.'+kind)).read_bytes();record[kind]={'path':'compile.'+kind,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
    write_new(parent/'compile.process.json',json_bytes(record))
    if code or timed:raise RuntimeError('native batch input build failed: '+str(record))
    path=build_root/'members.json'
    if json.loads((parent/'compile.stdout').read_bytes())!=json.loads(path.read_bytes()):raise RuntimeError('actual build stdout/bundle mismatch')
    return path

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--hepta',required=True,type=Path);parser.add_argument('--build',required=True,type=Path)
    parser.add_argument('--source',type=Path,default=ROOT);parser.add_argument('--worker',action='store_true')
    args=parser.parse_args()
    if args.worker:
        path=_compile(args.hepta,args.build,source_root=args.source);print(json.dumps(json.loads(path.read_bytes()),sort_keys=True))
    else:print(build_batch_plan_input(args.hepta,args.build,source_root=args.source))
