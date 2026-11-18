"""Build source-bound HIA shadow owners; no runtime decisions execute in Python."""
from pathlib import Path
import argparse,hashlib,json,sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from hia_native_build import NativeBuild,json_bytes,write_new

MEMBERS=(('core','execution_shadow','standard','filter'),
         ('json','execution_json','standard','filter'),
         ('controller','execution_controller','history.v1',None),
         ('json_composed','execution_json','history.v1',None),
         ('core_composed','execution_shadow','history.v1',None))
sha=lambda raw:hashlib.sha256(raw).hexdigest()

def build_execution(hepta:Path,build_root:Path,*,source_root:Path=ROOT)->Path:
    root=source_root.resolve(strict=True);build_root=build_root.resolve()
    from hia_native_execution_qualification import source_pins,build_evidence
    before=source_pins(root)
    builder=NativeBuild(hepta,build_root);compiler=builder.bootstrap()
    key=sha(json_bytes({'sources':before,'compiler_sha256':sha(compiler.read_bytes())}))
    folder=build_root/'execution-shadow'/key;destination=folder/'bundle.json'
    if destination.exists():
        build_evidence(destination,source_root=root,hepta=hepta)
        return destination
    members={}
    for key,source,profile,transport in MEMBERS:
        raw=(root/'native'/(source+'.hepta')).read_bytes()
        path=builder.compile('shadow-'+key.replace('_','-')+'-'+sha(raw)[:16],
                            root/'native'/(source+'.hepta'),standalone=transport,buffer_profile=profile)
        meta=json.loads(path.read_bytes())
        members[key]={'manifest':str(path.relative_to(build_root)),'manifest_sha256':sha(path.read_bytes()),
                      'source':'native/'+source+'.hepta','source_sha256':sha(raw),
                      'image_sha256':meta['image_sha256'],'buffer_profile':profile}
    for first,second in [('core','core_composed'),('json','json_composed')]:
        if members[first]['image_sha256']!=members[second]['image_sha256']:
            raise ValueError('execution profile changed native image bytes')
    if source_pins(root)!=before:raise ValueError('execution source inputs changed during build')
    value={'schema':'hepta.runtime.execution-shadow-bundle.v1','compiler_commit':builder.identity['commit'],
           'compiler_sha256':sha(compiler.read_bytes()),'members':members,'source_pins':before,
           'production_activated':False,'whole_runtime_replaced':False,'old_stack_removal_qualified':False}
    folder.mkdir(parents=True,exist_ok=False,mode=0o700);write_new(destination,json_bytes(value))
    builder._recheck();build_evidence(destination,source_root=root,hepta=hepta)
    return destination

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--hepta',type=Path,required=True);p.add_argument('--build-root',type=Path,required=True)
    p.add_argument('--source-root',type=Path,default=ROOT);a=p.parse_args()
    print(json.dumps({'manifest':str(build_execution(a.hepta,a.build_root,source_root=a.source_root))},sort_keys=True))
