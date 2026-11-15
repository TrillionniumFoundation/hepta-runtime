"""Build immutable RuntimeConfig and its source-owned native regex dependency.

Every service operation is performed by fixed HIA images and native boundaries.
Python is used only for compilation, exact artifact checks and test orchestration.
"""
from pathlib import Path
import argparse,hashlib,json,subprocess,sys,time
from hia_native_build import NativeBuild
from build_regex_probe import build_probe
ROOT=Path(__file__).resolve().parents[1]
sha=lambda raw:hashlib.sha256(raw).hexdigest()


def main():
    p=argparse.ArgumentParser();p.add_argument('--hepta',required=True,type=Path);p.add_argument('--build-root',required=True,type=Path);p.add_argument('--output',required=True,type=Path);p.add_argument('--prefix',default='cfg-regex');a=p.parse_args()
    hepta=a.hepta.resolve(strict=True);root=a.build_root.resolve();builder=NativeBuild(hepta,root);builder.bootstrap();modules={}
    declarations=[('json','config_json','serde-json.v1','filter'),('validation','config_validation','history.v1',None),('identity','config_identity','serde-json.v1','filter'),
        ('identity_composed','config_identity','history.v1',None),('owner','config_owner','history.v1',None),('mcp','config_mcp','history.v1',None),
        ('execution','execution_controller','history.v1',None),('execution_json','execution_json','history.v1',None),('execution_core','execution_shadow','history.v1',None),('value','serde_json','serde-json.v1',None),('publication','result_publication','standard',None)]
    declarations += [(name,name,'standard'if name in ['regex_unicode','regex_unicode_data']else'history.v1','filter'if name=='regex_unicode_data'else None)for name in ['regex_unicode','regex_unicode_data','regex_syntax','regex_hir','regex_nfa','regex_match','regex_controller']]
    for name,source,profile,standalone in declarations:
        modules[name]=builder.compile(a.prefix+'-'+name.replace('_','-'),ROOT/'native'/(source+'.hepta'),standalone=standalone,buffer_profile=profile)
    modules['validation_composed']=modules['validation']
    records=[]
    def run(name,script,args):
        command=[sys.executable,'-B',str(ROOT/'scripts'/script),*map(str,args)];start=time.monotonic();r=subprocess.run(command,cwd=ROOT,capture_output=True,timeout=180)
        (root/(a.prefix+'-'+name+'.stdout')).write_bytes(r.stdout);(root/(a.prefix+'-'+name+'.stderr')).write_bytes(r.stderr)
        records.append({'name':name,'command':command,'cwd':str(ROOT),'exit':r.returncode,'elapsed':time.monotonic()-start,'timeout_seconds':180,'stdout_sha256':sha(r.stdout),'stderr_sha256':sha(r.stderr)})
        if r.returncode:raise RuntimeError((name,r.returncode,r.stderr[-4096:]))
        return json.loads(r.stdout.decode().splitlines()[-1])
    common=['--hepta',hepta,'--runtime',ROOT,'--build-root',root]
    fs=run('fs','build_config_fs_probe.py',common+['--name',a.prefix+'-fs']);modules['fs']=Path(fs['module_manifest'])
    owner_args=[]
    for name in ['owner','fs','json','validation','identity','regex_syntax','regex_unicode_data','regex_hir','regex_nfa','regex_match','regex_controller']:
        key='identity_composed'if name=='identity'else name;owner_args+=['--'+name.replace('_','-')+'-manifest',modules[key]]
    owner=run('owner','build_config_owner_probe.py',common+['--name',a.prefix+'-owner']+owner_args)
    fixture=run('fixture','build_config_owner_probe.py',common+['--name',a.prefix+'-fixture','--fixture-admin']+owner_args)
    mcp_args=owner_args[:]
    for name in ['mcp','execution','execution_json','execution_core','value','publication']:mcp_args+=['--'+name.replace('_','-')+'-manifest',modules[name]]
    mcp=run('mcp','build_config_mcp_service.py',common+['--name',a.prefix+'-mcp']+mcp_args)
    by_source={source:modules[name]for name,source,_,_ in declarations};by_source['config_identity']=modules['identity_composed']
    executables={name:Path(item['manifest'])for name,item in [('fs',fs),('owner',owner),('fixture',fixture),('mcp',mcp)]}
    for profile in ['unicode','syntax','hir','regex','validation']:
        executables['regex_'+profile]=build_probe(hepta,root,profile,a.prefix+'-'+profile,by_source)
    result={'schema':'hepta.runtime.config-native-build.v2','modules':{name:{'path':str(path.resolve()),'sha256':sha(path.read_bytes())}for name,path in modules.items()},
        'executables':{name:{'path':str(path.resolve()),'sha256':sha(path.read_bytes())}for name,path in executables.items()},'records':records,'compiler_commit':builder.identity['commit'],'compiler_sha256':builder.compiler_sha256,'fresh_cold_qualified':False,'runtime_python_required':False,'unconstrained_regex_resources_closed':False}
    a.output.parent.mkdir(parents=True,exist_ok=True)
    with a.output.open('x')as target:target.write(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'output':str(a.output.resolve()),'modules':len(modules),'executables':list(executables),'sha256':sha(a.output.read_bytes())},sort_keys=True))


if __name__=='__main__':main()
