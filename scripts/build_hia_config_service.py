"""Build the fixed configuration components and real eleven-image MCP executable.

Python orchestrates compilation only. The resulting ELF contains fixed native
code and HIA images; no Python, Rust, dynamic linker or libc runs in the service.
The compiler's existing bootstrap receipt is reusable, not a fresh cold claim.
"""
from pathlib import Path
import argparse,hashlib,json,subprocess,sys
ROOT=Path(__file__).resolve().parents[1]
sha=lambda raw:hashlib.sha256(raw).hexdigest()

def main():
    p=argparse.ArgumentParser();p.add_argument('--hepta',type=Path,required=True);p.add_argument('--build-root',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    from hia_native_build import NativeBuild
    build=NativeBuild(a.hepta,a.build_root);build.bootstrap();modules={}
    declarations=[('json','config_json','serde-json.v1','filter'),('validation','config_validation','serde-json.v1','filter'),('identity','config_identity','serde-json.v1','filter'),
        ('validation_composed','config_validation','history.v1',None),('identity_composed','config_identity','history.v1',None),
        ('owner','config_owner','history.v1',None),('mcp','config_mcp','history.v1',None),('execution','execution_controller','history.v1',None),
        ('execution_json','execution_json','history.v1',None),('execution_core','execution_shadow','history.v1',None),('value','serde_json','serde-json.v1',None),('publication','result_publication','standard',None)]
    for name,source,profile,standalone in declarations:
        modules[name]=build.compile('cfg-'+name.replace('_','-'),ROOT/'native'/(source+'.hepta'),standalone=standalone,buffer_profile=profile)
    root=a.build_root.resolve();records=[]
    def run(name,script,args):
        done=subprocess.run([sys.executable,str(ROOT/'scripts'/script),*map(str,args)],capture_output=True,timeout=180)
        (root/(name+'.stdout')).write_bytes(done.stdout);(root/(name+'.stderr')).write_bytes(done.stderr)
        if done.returncode:raise RuntimeError((name,done.returncode,done.stderr[-4096:]))
        records.append({'name':name,'exit':0,'stdout_sha256':sha(done.stdout),'stderr_sha256':sha(done.stderr)})
        return json.loads(done.stdout.decode().splitlines()[-1])
    common=['--hepta',a.hepta,'--runtime',ROOT,'--build-root',root]
    fs=run('filesystem','build_config_fs_probe.py',common+['--name','cfg-fs']);modules['fs']=Path(fs['module_manifest'])
    args=[]
    for name in ['owner','fs','json','validation','identity']:
        key=name+'_composed' if name in ['validation','identity'] else name
        args+=['--'+name+'-manifest',modules[key]]
    owner=run('owner','build_config_owner_probe.py',common+['--name','cfg-owner-live']+args)
    fixture=run('fixture','build_config_owner_probe.py',common+['--name','cfg-owner-fixture','--fixture-admin']+args)
    for name in ['mcp','execution','execution_json','execution_core','value','publication']:args+=['--'+name.replace('_','-')+'-manifest',modules[name]]
    mcp=run('mcp','build_config_mcp_service.py',common+['--name','cfg-mcp']+args)
    result={'schema':'hepta.runtime.config-native-build.v1','modules':{n:{'path':str(m.resolve()),'sha256':sha(m.read_bytes())} for n,m in modules.items()},
            'executables':{n:{'path':str(Path(data['manifest']).resolve()),'sha256':sha(Path(data['manifest']).read_bytes())} for n,data in [('fs',fs),('owner',owner),('fixture',fixture),('mcp',mcp)]},
            'records':records,'compiler_commit':build.identity['commit'],'compiler_sha256':build.compiler_sha256,'fresh_cold_qualified':False}
    a.output.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n');print(json.dumps({'output':str(a.output.resolve()),'modules':len(modules),'executables':list(result['executables'])},sort_keys=True))

if __name__=='__main__':main()
